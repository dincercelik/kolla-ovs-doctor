"""The routers check: L3 HA state, and the qrouter and SNAT namespaces."""
from collections import defaultdict

from kolla_ovs_doctor.findings import make_finding


def parse_netns(text):
    """Return {namespace: {"addr": [], "nat": [], "neigh": [], "route": []}}."""
    namespaces, current, field = {}, None, None
    for line in text.splitlines():
        if line.startswith("@ns "):
            # A namespace appears twice: once for addresses and once for NAT rules.
            current = namespaces.setdefault(
                line[4:].strip(), {"addr": [], "nat": [], "neigh": [], "route": []})
            field = None
        elif line.strip() in ("@addr", "@nat", "@neigh", "@route"):
            field = line.strip()[1:]
        elif current is not None and field and line.strip():
            current[field].append(line)
    return namespaces


def ports_by_router(ports):
    """Return {router id: {"ips": [], "networks": set, "snat_ports": [(ip, mac)]}}."""
    interfaces = ("network:ha_router_replicated_interface", "network:router_interface",
                  "network:router_interface_distributed")
    routers = defaultdict(lambda: {"ips": [], "networks": set(), "snat_ports": []})
    for port in ports:
        owner, device = port.get("owner"), port.get("device")
        if owner in interfaces:
            routers[device]["networks"].add(port["network_id"])
            routers[device]["ips"] += [ip for ip in port.get("ips", []) if ":" not in ip]
        elif owner == "network:router_centralized_snat":
            routers[device]["snat_ports"] += [(ip, port["mac"].lower())
                                              for ip in port.get("ips", []) if ":" not in ip]
    return routers


def audit_snat(host, router, namespace, snat_ports):
    """Check the gateway addresses, SNAT rules and default route of an SNAT namespace."""
    label = router["name"] or router["id"]
    if namespace is None:
        return [make_finding(host, "snat_ns_missing", label)]
    addresses = " ".join(namespace["addr"])
    findings = []
    for ip in router["gateway_ips"]:
        if f" {ip}/" not in addresses:
            findings.append(make_finding(host, "snat_ip_missing", f"{label}: {ip}"))
        if not any(f"--to-source {ip}" in line for line in namespace["nat"]):
            findings.append(make_finding(host, "snat_rule_missing", f"{label}: {ip}"))
    if not any(" table " not in line for line in namespace["route"]):
        findings.append(make_finding(host, "snat_default_route_missing", label))
    for ip, _ in snat_ports:
        if f" {ip}/" not in addresses:
            findings.append(make_finding(host, "snat_port_missing", f"{label}: {ip}"))
    return findings


def audit_centralized(router, data, active, netns):
    """Check scheduling and namespaces of a router without DVR."""
    label = router["name"] or router["id"]
    agents = router["agents"]
    if not agents and router["agents_known"]:
        return [make_finding("neutron", "router_unscheduled", label)]
    if not agents:
        return []
    findings = []
    down = [agent["host"] for agent in agents if agent.get("alive") is False]
    if len(down) == len(agents):
        findings.append(make_finding("neutron", "router_agents_down",
                                     f"{label}: {', '.join(sorted(down))}"))
    else:
        findings += [make_finding(host, "router_agent_down", label) for host in sorted(down)]
    name = "qrouter-" + router["id"]
    for agent in agents:
        host = agent["host"]
        if host not in netns or host in down:
            continue
        if name not in netns[host]:
            findings.append(make_finding(host, "router_ns_missing", label))
        elif not router["ha"] or host in active:
            addresses = " ".join(netns[host][name]["addr"])
            findings += [make_finding(host, "router_interface_missing", f"{label}: {ip}")
                         for ip in data["ips"] if f" {ip}/" not in addresses]
    return findings


def audit_standby_vips(router, active, netns):
    """Report gateway addresses that are still on a standby node."""
    label = router["name"] or router["id"]
    name = ("snat-" if router["distributed"] else "qrouter-") + router["id"]
    findings = []
    for agent in router["agents"]:
        host = agent["host"]
        namespace = netns.get(host, {}).get(name)
        if host in active or namespace is None or agent.get("ha_state") != "standby":
            continue
        addresses = " ".join(namespace["addr"])
        findings += [make_finding(host, "router_vip_on_standby", f"{label}: {ip}")
                     for ip in router["gateway_ips"] if f" {ip}/" in addresses]
    return findings


def dvr_snat_hosts(router, netns):
    """Return (hosts that should have the SNAT namespace, findings) for DVR without HA."""
    label = router["name"] or router["id"]
    name = "snat-" + router["id"]

    def mode(agent):
        return (agent.get("configurations") or {}).get("agent_mode")

    agents = router["agents"]
    if not router["agents_known"] or (agents and not any(map(mode, agents))):
        # No scheduling data. Check the hosts that have the namespace.
        return [host for host, spaces in netns.items() if name in spaces], []
    snat = [agent for agent in agents if mode(agent) == "dvr_snat"]
    if not snat:
        return [], [make_finding("neutron", "router_unscheduled", f"{label}: no dvr_snat agent")]
    down = sorted(agent["host"] for agent in snat if agent.get("alive") is False)
    if len(down) == len(snat):
        return [], [make_finding("neutron", "router_agents_down", f"{label}: {', '.join(down)}")]
    return ([agent["host"] for agent in snat if agent["host"] not in down],
            [make_finding(host, "router_agent_down", label) for host in down])


def audit_ha_state(router, active):
    """Report an HA router with no active agent, or with more than one."""
    label = router["name"] or router["id"]
    known_state = any(agent.get("ha_state") for agent in router["agents"])
    if router["ha"] and known_state and not active:
        return [make_finding("neutron", "ha_active_missing", label)]
    if router["ha"] and len(active) > 1:
        return [make_finding("neutron", "ha_active_multiple",
                             f"{label}: {', '.join(sorted(active))}")]
    return []


def audit_router_snat(router, data, active, netns):
    """Check the SNAT namespace on each host that should have it."""
    if router["ha"]:
        candidates, findings = active, []
    elif router["distributed"]:
        candidates, findings = dvr_snat_hosts(router, netns)
    else:
        candidates, findings = [agent["host"] for agent in router["agents"]], []
    name = ("snat-" if router["distributed"] else "qrouter-") + router["id"]
    snat_ports = data["snat_ports"] if router["distributed"] else []
    for host in candidates:
        if host in netns:
            findings += audit_snat(host, router, netns[host].get(name), snat_ports)
    return findings


def audit_dvr_qrouters(router, data, hosts, netns):
    """Check the qrouter namespace of a DVR router on each compute host."""
    label = router["name"] or router["id"]
    qrouter = "qrouter-" + router["id"]
    findings = []
    for host in sorted(hosts & set(netns)):
        namespace = netns[host].get(qrouter)
        if namespace is None:
            findings.append(make_finding(host, "qrouter_ns_missing", label))
            continue
        if not (router["snat_enabled"] and router["gateway_ips"]):
            continue
        for ip, mac in data["snat_ports"]:
            if not any(f"default via {ip} " in line for line in namespace["route"]):
                findings.append(make_finding(host, "qrouter_snat_route_missing",
                                             f"{label}: {ip}"))
            neighbour = [line for line in namespace["neigh"] if line.startswith(f"{ip} ")]
            if not any(mac in line.lower() for line in neighbour):
                findings.append(make_finding(host, "qrouter_snat_arp_wrong",
                                             f"{label}: {ip} should be {mac}"))
    return findings


def audit_router(router, data, compute_hosts, netns):
    """Check one router: HA state, scheduling, and its SNAT and qrouter namespaces."""
    active = [agent["host"] for agent in router["agents"] if agent.get("ha_state") == "active"]
    findings = audit_ha_state(router, active)
    if router["ha"]:
        findings += audit_standby_vips(router, active, netns)
    if not router["distributed"]:
        findings += audit_centralized(router, data, active, netns)
    if router["snat_enabled"] and router["gateway_ips"]:
        findings += audit_router_snat(router, data, active, netns)
    if router["distributed"]:
        hosts = set().union(*(compute_hosts[network] for network in data["networks"]))
        findings += audit_dvr_qrouters(router, data, hosts, netns)
    return findings


def audit_routers(routers, ports, netns):
    """Check HA state and the namespaces of every router on collected hosts."""
    by_router = ports_by_router(ports)
    compute_hosts = defaultdict(set)
    for port in ports:
        if (port.get("owner") or "").startswith("compute:") and port.get("host"):
            compute_hosts[port["network_id"]].add(port["host"])
    empty = {"ips": [], "networks": set(), "snat_ports": []}
    findings = []
    for router in routers:
        findings += audit_router(router, by_router.get(router["id"], empty),
                                 compute_hosts, netns)
    return findings
