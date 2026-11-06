"""The flows check: br-tun tables 4, 20, 21 and 22 against Neutron."""
import ipaddress
from collections import Counter, defaultdict

from kolla_ovs_doctor import parse
from kolla_ovs_doctor.findings import make_finding


def stale_flood_reason(ip, vni, expected, context):
    """Return why a flood tunnel is stale, or None if it may be needed."""
    peer = context["ip_hosts"].get(ip)
    if peer is None:
        return f"{ip} has no OVS agent"
    if (peer in context["collected"]
            and peer not in expected.get(vni, {}).get("hosts", set())
            and peer not in context["bound_hosts"].get(vni, set())
            and vni not in context["present_vnis"].get(peer, set())):
        return f"{peer} ({ip}) has no such network"
    return None


def arp_is_known(state, ip, mac):
    """Return True if Neutron knows this IP and MAC, also through address pairs."""
    if mac in state["macs_by_ip"].get(ip, set()):
        return True
    address = ipaddress.ip_address(ip)
    return any(address in net and mac == pair_mac and address.version == net.version
               for net, pair_mac in state["pair_cidrs"])


def audit_orphan_vnis(sections, context, add):
    """Report VNIs that have flows on the host but no VXLAN network in Neutron."""
    known, only_vni = context["known"], context["only_vni"]
    for vni in sorted(parse.present_vnis(sections)):
        if vni not in known and only_vni in (None, vni):
            add("vni_orphan", vni, "no VXLAN network in Neutron")


def audit_vlan_conflicts(sections, context, add):
    """Report local VLANs that more than one VNI uses."""
    only_vni = context["only_vni"]
    all_vlans = parse.parse_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    for vlan, vnis in sorted(all_vlans.items()):
        if len(vnis) > 1 and (only_vni is None or only_vni in vnis):
            names = ", ".join(f"{vni:#x}" for vni in sorted(vnis))
            add("vlan_conflict", min(vnis), f"local vlan {vlan} used by VNIs {names}")


def audit_stale_unicast(sections, context, add):
    """Report static table 20 flows for MACs that Neutron does not know."""
    known, only_vni = context["known"], context["only_vni"]
    for flow_vni, mac, learned, _ in parse.parse_unicast_flows(sections.get("table20", "")):
        if (not learned and flow_vni in known and only_vni in (None, flow_vni)
                and mac not in known[flow_vni]["macs"]):
            add("unicast_stale", flow_vni, f"{mac} is not a Neutron port")


def audit_stale_arp(sections, context, add):
    """Report ARP responder flows that Neutron does not know.

    Return {vni: {ip: mac}} of the ARP flows on the host, for audit_missing_arp.
    """
    known, only_vni = context["known"], context["only_vni"]
    all_vlans = parse.parse_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    vlans = parse.parse_unique_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    arp_by_vni = defaultdict(dict)
    for vlan, ip, mac in parse.parse_arp_flows(sections.get("table21", "")):
        vni = vlans.get(vlan)
        if vni is None and vlan in all_vlans:
            continue  # Shared local VLAN, reported as vlan_conflict.
        if vni is None:
            add("arp_stale", 0, f"{ip} -> {mac} on unknown vlan {vlan}")
        elif vni in known and only_vni in (None, vni):
            arp_by_vni[vni][ip] = mac
            if not arp_is_known(known[vni], ip, mac):
                owners = ",".join(sorted(known[vni]["macs_by_ip"].get(ip, []))) or "none"
                add("arp_stale", vni, f"{ip} -> {mac} (neutron: {owners})")
    return arp_by_vni


def audit_stale_floods(sections, expected, context, add):
    """Report flood tunnels to hosts that do not need this VNI."""
    known, only_vni = context["known"], context["only_vni"]
    tunnels = parse.parse_tunnels(sections.get("tunnels", ""))
    for vni, flood_ports in parse.parse_flood_ports(sections.get("table22", "")).items():
        if vni not in known or only_vni not in (None, vni):
            continue
        for port in sorted(flood_ports):
            ip = tunnels.get(port)
            reason = stale_flood_reason(ip, vni, expected, context) if ip else None
            if reason:
                add("flood_stale", vni, reason)


def audit_missing_arp(host, arp_by_vni, expected, add):
    """Report ARP entries that Neutron expects but the host does not have.

    Only VNIs with ARP flows on the host count, so a host without arp_responder
    reports nothing.
    """
    for vni, entries in sorted(arp_by_vni.items()):
        for ip, mac, owner in expected.get(vni, {}).get("arps", []):
            if owner != host and ip not in entries:
                add("arp_missing", vni, f"{ip} -> {mac} on {owner}")


def audit_stale_entries(host, sections, expected, context, add):
    """Find entries that should not exist, shared local VLANs and missing ARP entries."""
    audit_orphan_vnis(sections, context, add)
    audit_vlan_conflicts(sections, context, add)
    audit_stale_unicast(sections, context, add)
    arp_by_vni = audit_stale_arp(sections, context, add)
    audit_stale_floods(sections, expected, context, add)
    audit_missing_arp(host, arp_by_vni, expected, add)


def audit_host(host, sections, expected, tunnel_ips, context=None):
    """Return a list of findings for one host."""
    tunnels = parse.parse_tunnels(sections.get("tunnels", ""))
    unicast = parse.unicast_by_vni(sections.get("table20", ""))
    floods = parse.parse_flood_ports(sections.get("table22", ""))
    tunnel_remotes = set(tunnels.values())
    findings = []

    def add(kind, vni, detail, peer_ip=None):
        item = make_finding(host, kind, detail, vni)
        if peer_ip:
            item["peer_ip"] = peer_ip
        findings.append(item)

    no_tunnel = Counter()
    for vni, state in sorted(expected.items()):
        if host not in state["hosts"]:
            continue
        flood_remotes = {tunnels[port] for port in floods.get(vni, set()) if port in tunnels}
        for peer in sorted(state["hosts"] - {host}):
            ip = tunnel_ips[peer]
            if ip not in tunnel_remotes:
                no_tunnel[peer] += 1
            if ip not in flood_remotes:
                add("flood_missing", vni, f"{peer} ({ip})", ip)

        entries = unicast.get(vni, {})
        for mac, owner in sorted(state["macs"].items()):
            if owner == host:
                continue
            flows = entries.get(mac, ())
            ip = tunnel_ips[owner]
            static = [flow for flow in flows if not flow[0]]
            if static:
                targets = {tunnels.get(port) for _, outputs in static for port in outputs}
                if ip not in targets:
                    add("unicast_wrong", vni, f"{mac} -> {owner} ({ip})")
            elif flows:
                add("unicast_learned_only", vni, f"{mac} on {owner}")
            else:
                add("unicast_missing", vni, f"{mac} on {owner}")
    # One finding per peer. One tunnel port serves all VNIs.
    for peer, count in sorted(no_tunnel.items()):
        noun = "VNI" if count == 1 else "VNIs"
        add("tunnel_missing", 0, f"{peer} ({tunnel_ips[peer]}), needed by {count} {noun}")
    if context:
        audit_stale_entries(host, sections, expected, context, add)
    return findings
