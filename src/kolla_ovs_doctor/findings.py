"""Finding kinds, their severity and how findings are sorted.

Import names from this module, not the module itself: "findings" is a common
local variable name."""


FLOW_KINDS = {
    "arp_missing", "arp_stale", "flood_missing", "flood_stale", "tunnel_missing",
    "unicast_learned_only", "unicast_missing", "unicast_stale", "unicast_wrong",
    "vlan_conflict", "vni_orphan",
}
# Grouped by severity. Sorted inside each group.
SEVERITY = {
    "agent_down": "critical", "arp_stale": "critical", "dvr_mac_conflict": "critical",
    "dvr_mac_missing": "critical", "flood_missing": "critical",
    "ha_active_missing": "critical", "ha_active_multiple": "critical",
    "qrouter_ns_missing": "critical", "qrouter_snat_arp_wrong": "critical",
    "qrouter_snat_route_missing": "critical", "router_agents_down": "critical",
    "router_interface_missing": "critical", "router_ns_missing": "critical",
    "router_unscheduled": "critical", "router_vip_on_standby": "critical",
    "snat_default_route_missing": "critical", "snat_ip_missing": "critical",
    "snat_ns_missing": "critical", "snat_port_missing": "critical",
    "snat_rule_missing": "critical", "tunnel_missing": "critical",
    "unicast_wrong": "critical", "vlan_conflict": "critical",
    "arp_missing": "warning", "config_drift": "warning", "router_agent_down": "warning",
    "unicast_missing": "warning", "unicast_stale": "warning",
    "flood_stale": "info", "unicast_learned_only": "info", "version_drift": "info",
    "vni_orphan": "info",
}
SEVERITY_ORDER = ("critical", "warning", "info")  # Most severe first.


def make_finding(host, kind, detail, vni=0):
    """Return one finding."""
    return {"detail": detail, "host": host, "kind": kind, "vni": vni}


def severity_of(item):
    """Return the severity of a finding."""
    return SEVERITY.get(item["kind"], "warning")


def finding_order(item):
    """Sort key: host, then most severe first, then kind, VNI and detail."""
    return (item["host"], SEVERITY_ORDER.index(severity_of(item)), item["kind"],
            item["vni"], item["detail"])
