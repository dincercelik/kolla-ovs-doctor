"""Read Neutron, and build what each VXLAN network should look like."""
import functools
import ipaddress
from collections import defaultdict

from kolla_ovs_doctor import util

SKIPPED_PORT_OWNERS = {"network:floatingip", "network:router_interface_distributed"}


def network_vnis(networks):
    """Return {network id: set(vnis)}. A network can have more than one VXLAN segment."""
    vnis = defaultdict(set)
    for net in networks:
        if net["vni"] is not None:
            vnis[net["id"]].add(net["vni"])
    return vnis


def build_expected(networks, ports, tunnel_ips):
    """Return {vni: {"arps": [(ip, mac, host)], "hosts": set(hosts), "macs": {mac: host}}}.

    Ports on networks with more than one VXLAN segment are left out. Neutron does
    not say which segment such a port uses.
    """
    vnis = network_vnis(networks)
    expected = defaultdict(lambda: {"arps": [], "hosts": set(), "macs": {}})
    for port in ports:
        segments = vnis.get(port["network_id"], set())
        vni = next(iter(segments)) if len(segments) == 1 else None
        host = port.get("host")
        if (vni is None or host not in tunnel_ips
                or port.get("owner") in SKIPPED_PORT_OWNERS
                or port.get("status") != "ACTIVE"):
            continue
        expected[vni]["hosts"].add(host)
        expected[vni]["macs"][port["mac"].lower()] = host
        owner = port.get("owner") or ""
        if owner.startswith("compute:") or owner == "network:dhcp":
            for ip in port.get("ips", []):
                if ":" not in ip:
                    expected[vni]["arps"].append((ip, port["mac"].lower(), host))
    return dict(expected)


def build_known(networks, ports):
    """Return all that Neutron knows per VNI, for ports in any state on any host."""
    vnis = network_vnis(networks)
    known = {vni: {"macs": set(), "macs_by_ip": defaultdict(set), "pair_cidrs": []}
             for segments in vnis.values() for vni in segments}
    for port in ports:
        # The port counts in every segment of its network. We do not know which
        # segment it uses, and none of its flows may look stale.
        for vni in vnis.get(port["network_id"], ()):
            state, mac = known[vni], port["mac"].lower()
            state["macs"].add(mac)
            for ip in port.get("ips", []):
                state["macs_by_ip"][ip].add(mac)
            for pair in port.get("address_pairs", []):
                pair_mac = (pair.get("mac") or mac).lower()
                state["macs"].add(pair_mac)
                state["pair_cidrs"].append(
                    (ipaddress.ip_network(pair["ip"], strict=False), pair_mac))
    return known


def build_bound(networks, ports):
    """Return {vni: hosts with a bound port}, for ports in any state."""
    vnis = network_vnis(networks)
    bound = defaultdict(set)
    for port in ports:
        if port.get("host"):
            for vni in vnis.get(port["network_id"], ()):
                bound[vni].add(port["host"])
    return bound


@functools.cache
def openstack_connection():
    """Return the OpenStack connection shared by the whole run."""
    import openstack

    return openstack.connect(cloud="envvars")


def collect_routers(workers=10):
    """Return every router with its gateway and the l3 agents that host it."""
    conn = openstack_connection()
    routers = list(conn.network.routers())

    def agents_of(router_id):
        response = conn.network.get(f"/routers/{router_id}/l3-agents")
        return response.ok, response.json().get("agents", []) if response.ok else []

    # One API call per router, in parallel. Requests keeps 10 connections per pool.
    # More threads would open extra ones and log "connection pool is full".
    results = util.run_parallel([router.id for router in routers], agents_of, min(workers, 10))
    records = []
    for router in routers:
        found, error = results[router.id]
        ok, agents = found if not error else (False, [])
        gateway = router.external_gateway_info or {}
        records.append({
            "agents": agents,
            "agents_known": ok,
            "distributed": bool(router.is_distributed),
            "gateway_ips": [item["ip_address"] for item in gateway.get("external_fixed_ips", [])
                            if ":" not in item["ip_address"]],
            "ha": bool(router.is_ha),
            "id": router.id,
            "name": router.name,
            "snat_enabled": bool(gateway.get("enable_snat", True)) and bool(gateway),
        })
    return records


def port_record(port):
    """Return the port fields that this tool uses."""
    return {
        "address_pairs": [{"ip": item["ip_address"], "mac": item.get("mac_address")}
                          for item in port.allowed_address_pairs or []],
        "created": port.created_at,
        "device": port.device_id,
        "host": port.binding_host_id,
        "ips": [item["ip_address"] for item in port.fixed_ips or []],
        "mac": port.mac_address,
        "network_id": port.network_id,
        "owner": port.device_owner,
        "status": port.status,
    }


def collect_port(mac):
    """Read one port without listing the whole cloud."""
    conn = openstack_connection()
    matches = [port_record(port) for port in conn.network.ports(mac_address=mac)]
    return matches[0] if matches else None


def collect_neutron():
    """Return (networks, ports, {host: tunnel IP} of live agents, {tunnel IP: host})."""
    conn = openstack_connection()
    tunnel_ips, ip_hosts = {}, {}
    for agent in conn.network.agents(binary="neutron-openvswitch-agent"):
        ip = (agent.configuration or {}).get("tunneling_ip")
        if ip:
            ip_hosts[ip] = agent.host
        if ip and agent.is_alive:
            tunnel_ips[agent.host] = ip
    all_networks = list(conn.network.networks())
    networks = [
        {"id": net.id, "vni": net.provider_segmentation_id}
        for net in all_networks
        if net.provider_network_type == "vxlan"
    ]
    networks += [
        {"id": net.id, "vni": segment.get("provider:segmentation_id")}
        for net in all_networks
        for segment in getattr(net, "segments", None) or []
        if segment.get("provider:network_type") == "vxlan"
    ]
    ports = [port_record(port) for port in conn.network.ports()]
    return networks, ports, tunnel_ips, ip_hosts
