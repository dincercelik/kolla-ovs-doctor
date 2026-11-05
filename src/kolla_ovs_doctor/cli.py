"""ovs-doctor: check that the br-tun flows on every OVS host match Neutron's VXLAN state.

By default all VXLAN networks are checked. Use --vni to check one.
Tables 4, 20, 21 and 22 are checked for missing flows, and for flows that
Neutron does not know. A full run also does these checks (see --checks):
  drift    config and version differences between agents
  dvr      DVR MACs in tables 1 and 9
  routers  L3 HA state, and qrouter and SNAT namespaces
A host whose OVS agent is down is reported as agent_down. It is not checked.

Run it on a host with SSH key access to the hypervisors. Load admin
credentials first (source admin-openrc.sh).

It works only on Kolla-Ansible clouds that use Docker. Before it runs anything
on a host, it checks two things. The host must be a Kolla-Ansible OVS host. The
SSH user must be able to use sudo without a password. If a host fails, --cleanup,
--fix and --restore stop before they change anything. A normal run reports the
host as an error and skips it. Each script runs on a host under one
`sudo -n bash -s`. The scripts do not call sudo themselves.

A network can have more than one VXLAN segment. Its ports count as known in
every segment, so their flows are never deleted. They are not checked for
missing flows, because Neutron does not say which segment a port uses.

Exit codes:
  0  no problems found
  1  problems found
  2  collection, fix or preflight errors

--cleanup removes flood_stale tunnels from flood flows. It also deletes the
flows of vni_orphan entries. Run it with --dry-run first. A tunnel is kept if
its host has a port on the network, in any state (DOWN too). An orphan VNI is
kept if an OVS port still uses its local VLAN. It is also kept if another VNI
uses the same VLAN (vlan_conflict).

--fdb-watch MAC --vni N follows one port. It shows how long each host takes to
add the l2pop flows for it. This shows if agents are slow or stuck.

--fix adds missing tunnels to flood flows. It deletes ARP responder and unicast
flows that Neutron does not know. Run it with --dry-run first. The fix may not
last, because the OVS agent can overwrite it. Other findings are not changed.
--restore does not bring back deleted flows. They stay in the backup file.

--restore puts back the flood flow of one VNI on each host, from a backup file.
Only that flow changes, not the whole bridge. By default it uses the newest
backup. A restore makes its own backup first, so running it again undoes it.
Backups go to --backup-dir on each host (default /var/backups/kolla-ovs-doctor).
"""
import argparse
import atexit
import datetime
import functools
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import types
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

from kolla_ovs_doctor import __version__

ALL_CHECKS = ("drift", "dvr", "flows", "routers")
# oslo.config reads booleans in any case and in these words. 1 and 0 are left out,
# because they are often plain numbers.
CONFIG_BOOLEANS = {"false": "false", "no": "false", "off": "false", "on": "true", "true": "true",
                   "yes": "true"}
DEFAULT_BACKUP_DIR = "/var/backups/kolla-ovs-doctor"
FDB_ENTRIES = ("arp", "flood", "unicast")
FLOW_KINDS = {
    "arp_missing", "arp_stale", "flood_missing", "flood_stale", "tunnel_missing",
    "unicast_learned_only", "unicast_missing", "unicast_stale", "unicast_wrong",
    "vlan_conflict", "vni_orphan",
}
# Parsers keep a small cache, keyed by the dump text. So each host's tables are
# parsed once, even when several checks read them. Do not change a cached result:
# all callers share it. Hosts are checked one at a time, so 16 entries are enough.
PARSE_CACHE_SIZE = 16
SECTION_MARKER = "=====AUDIT:{}====="
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
SKIPPED_PORT_OWNERS = {"network:floatingip", "network:router_interface_distributed"}
VERSION_KEYS = (
    "agent_container_os", "host_kernel", "host_os", "image", "neutron", "oslo.messaging",
    "ovs_container_os", "ovs_image", "ovs_version", "ovsdb_image",
)

# A script for a container runs as `docker exec -i <container> bash -s [-- args]`.
# The script is in a quoted heredoc, so it needs no extra quoting.

# One docker exec and one br-tun dump. collect_host splits the dump into tables.
COLLECT_SCRIPT = """
set -e
docker exec -i openvswitch_vswitchd bash -s <<'OVS'
set -e
echo "{brtun}"; ovs-ofctl --no-names dump-flows br-tun
echo "{tags}"; ovs-vsctl --bare --columns=tag list port
echo "{tunnels}"; ovs-vsctl --columns=ofport,options find interface type=vxlan
OVS
""".format(
    brtun=SECTION_MARKER.format("brtun"),
    tags=SECTION_MARKER.format("tags"),
    tunnels=SECTION_MARKER.format("tunnels"),
)
DRIFT_SCRIPT = r"""
echo '=====AUDIT:drift====='
# Blocks are in the order of the keys they print.
docker exec -i neutron_openvswitch_agent bash -s <<'AGENT' || true
. /etc/os-release; echo "agent_container_os=$PRETTY_NAME"
/var/lib/kolla/venv/bin/python3 -c "
import importlib.metadata as m
for name in ('neutron', 'oslo.messaging'):
    print(name + '=' + m.version(name))
"
AGENT
KEYS='amqp_[a-z_]+|arp_responder|enable_distributed_routing|heartbeat_[a-z_]+'
KEYS="$KEYS|l2_population|rabbit_[a-z_]+|tunnel_types"
cat /etc/kolla/neutron-openvswitch-agent/*.conf \
    /etc/kolla/neutron-openvswitch-agent/*.ini 2>/dev/null \
  | grep -E "^ *($KEYS) *=" \
  | grep -viE 'password|user *=|userid' | sed 's/ *= */=/' | sort -u || true
echo "host_kernel=$(uname -r)"
(. /etc/os-release; echo "host_os=$PRETTY_NAME") || true
docker inspect --format '{{.Name}} {{.Config.Image}}' \
    neutron_openvswitch_agent openvswitch_db openvswitch_vswitchd 2>/dev/null \
  | awk '$1 == "/neutron_openvswitch_agent" {print "image=" $2}
         $1 == "/openvswitch_db" {print "ovsdb_image=" $2}
         $1 == "/openvswitch_vswitchd" {print "ovs_image=" $2}' || true
docker exec -i openvswitch_vswitchd bash -s <<'OVS' || true
. /etc/os-release; echo "ovs_container_os=$PRETTY_NAME"
ovs-vswitchd --version | awk 'NR==1{print "ovs_version=" $NF}'
OVS
"""
# Runs under sudo, like every other script. If sudo asks for a password, the script
# does not start. preflight_host sees this in the exit code.
PREFLIGHT_SCRIPT = r"""
if [ "$(id -u)" != 0 ]; then
  echo '@problem sudo did not run the script as root'
  echo '@preflight done'
  exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
  if command -v podman >/dev/null 2>&1; then
    echo '@problem podman deployments are not supported'
  else
    echo '@problem docker not found'
  fi
  echo '@preflight done'
  exit 0
fi
test -f /etc/kolla/neutron-openvswitch-agent/config.json \
  || echo '@problem /etc/kolla/neutron-openvswitch-agent/config.json not found'
for c in neutron_openvswitch_agent openvswitch_db openvswitch_vswitchd; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] \
    || echo "@problem container $c is not running"
done
if label=$(docker inspect -f '{{index .Config.Labels "kolla_version"}}' \
    neutron_openvswitch_agent 2>/dev/null); then
  case "$label" in
    ''|'<no value>') echo '@problem neutron_openvswitch_agent has no kolla_version label' ;;
  esac
fi
echo '@preflight done'
exit 0
"""
ROUTER_SCRIPT = r"""
echo '=====AUDIT:netns====='
# A subshell with set +e, because grep may find nothing here.
(
set +e
NS=$(ip netns list | awk '{print $1}' | grep -E '^(qrouter|snat)-')
for ns in $NS; do
  echo "@ns $ns"
  echo "@addr"; ip -n "$ns" -o -4 addr show
  echo "@neigh"; ip -n "$ns" -4 neigh show nud permanent
  echo "@route"; ip -n "$ns" -4 route show table all | grep '^default'
done
# Read SNAT rules with the iptables of the l3 agent. The host may use the other
# iptables backend (legacy or nft), and then it shows no rules.
if [ -n "$NS" ] && docker ps --format '{{.Names}}' | grep -qx neutron_l3_agent; then
  docker exec -i -u root neutron_l3_agent bash -s -- $NS <<'L3' | grep -E '^@|-j SNAT'
for ns in "$@"; do
  echo "@ns $ns"; echo "@nat"
  ip netns exec "$ns" iptables -t nat -S
done
L3
else
  for ns in $NS; do
    echo "@ns $ns"; echo "@nat"
    for ipt in iptables iptables-legacy iptables-nft; do
      command -v "$ipt" >/dev/null && ip netns exec "$ns" "$ipt" -t nat -S 2>/dev/null
    done | grep -- '-j SNAT' | sort -u
  done
fi
exit 0
)
"""
# --fdb-watch reads only the flows of one port. $1 is its MAC and $2 its IPv4
# address. $2 is empty if the port has no IPv4 address. Then table 21 is skipped.
WATCH_SCRIPT = """
set -e
docker exec -i openvswitch_vswitchd bash -s -- {{mac}} {{ip}} <<'OVS'
set -e
echo "{arp_count}"; ovs-ofctl dump-aggregate br-tun table=21,arp
echo "{table4}"; ovs-ofctl --no-names dump-flows br-tun table=4
echo "{table20}"; ovs-ofctl --no-names dump-flows br-tun "table=20,dl_dst=$1"
echo "{table21}"; [ -z "$2" ] || ovs-ofctl --no-names dump-flows br-tun "table=21,arp,arp_tpa=$2"
echo "{table22}"; ovs-ofctl --no-names dump-flows br-tun table=22
echo "{tunnels}"; ovs-vsctl --columns=ofport,options find interface type=vxlan
OVS
""".format(
    arp_count=SECTION_MARKER.format("arp_count"),
    table4=SECTION_MARKER.format("table4"),
    table20=SECTION_MARKER.format("table20"),
    table21=SECTION_MARKER.format("table21"),
    table22=SECTION_MARKER.format("table22"),
    tunnels=SECTION_MARKER.format("tunnels"),
)

RE_ACTIONS = re.compile(r"actions=(\S+)")
RE_ARP_MAC = re.compile(r"mod_dl_src:([0-9a-fA-F:]{17})"
                        r"|set_field:([0-9a-fA-F:]{17})->(?:arp_sha|eth_src)")
RE_ARP_SHA_LOAD = re.compile(r"load:0x([0-9a-fA-F]{1,12})->NXM_NX_ARP_SHA")
RE_ARP_TPA = re.compile(r"arp_tpa=([0-9.]+)")
RE_DL_DST = re.compile(r"dl_dst=([0-9a-fA-F:]{17})")
RE_DL_VLAN = re.compile(r"dl_vlan=(\d+)")
RE_FLOW_COUNT = re.compile(r"flow_count=(\d+)")
RE_OFPORT = re.compile(r"\s*ofport\s*:\s*(-?\d+)")
RE_OUTPUT = re.compile(r"output:(\d+)")
RE_REMOTE_IP = re.compile(r'remote_ip="?([0-9a-fA-F:.]+)"?')
RE_TABLE = re.compile(r"\btable=(\d+)")
RE_TUN_ID = re.compile(r"tun_id=(0x[0-9a-fA-F]+)")
RE_VLAN_VID = re.compile(r"mod_vlan_vid:(\d+)|set_field:(\d+)->vlan_vid")
RE_VNI = re.compile(r"load:(0x[0-9a-fA-F]+)->NXM_NX_TUN_ID"
                    r"|set_field:(0x[0-9a-fA-F]+)->tun_id"
                    r"|set_tunnel(?:64)?:(0x[0-9a-fA-F]+)")


def split_sections(text):
    """Return {name: text} for the =====AUDIT:<name>===== sections of a script's output."""
    sections, current = {}, None
    for line in text.splitlines():
        match = re.fullmatch(r"=====AUDIT:(\w+)=====", line.strip())
        if match:
            current = match.group(1)
            sections[current] = []
        elif current:
            sections[current].append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}


def split_flow_tables(text):
    """Split one br-tun dump into {"table<N>": text}."""
    tables = defaultdict(list)
    for line in text.splitlines():
        match = RE_TABLE.search(line)
        if match:
            tables["table" + match.group(1)].append(line)
    return {name: "\n".join(lines) for name, lines in tables.items()}


@functools.lru_cache(maxsize=PARSE_CACHE_SIZE)
def parse_tunnels(text):
    """Return {ofport: remote_ip}."""
    tunnels, ofport = {}, None
    for line in text.splitlines():
        port = RE_OFPORT.match(line)
        if port:
            ofport = int(port.group(1))
        remote = RE_REMOTE_IP.search(line)
        if remote and ofport is not None and ofport > 0:
            tunnels[ofport] = remote.group(1)
    return tunnels


def line_vni(line):
    """Return the VNI that one flow line sets, or None."""
    match = RE_VNI.search(line)
    if not match:
        return None
    return int(next(group for group in match.groups() if group), 16)


def line_outputs(line):
    """Return the output ports of one flow line."""
    return [int(port) for port in RE_OUTPUT.findall(line)]


@functools.lru_cache(maxsize=PARSE_CACHE_SIZE)
def parse_unicast_flows(text):
    """Return ((vni, mac, learned, outputs), ...)."""
    entries = []
    for line in text.splitlines():
        mac = RE_DL_DST.search(line)
        vni = line_vni(line)
        if mac and vni is not None:
            entries.append((vni, mac.group(1).lower(),
                            "hard_timeout" in line, tuple(line_outputs(line))))
    return tuple(entries)


@functools.lru_cache(maxsize=PARSE_CACHE_SIZE)
def unicast_by_vni(text):
    """Return {vni: {mac: ((learned, outputs), ...)}} for table 20."""
    grouped = defaultdict(lambda: defaultdict(list))
    for vni, mac, learned, outputs in parse_unicast_flows(text):
        grouped[vni][mac].append((learned, outputs))
    return {vni: {mac: tuple(flows) for mac, flows in macs.items()}
            for vni, macs in grouped.items()}


@functools.lru_cache(maxsize=PARSE_CACHE_SIZE)
def parse_flood_ports(text):
    """Return {vni: frozenset(ofports)}."""
    floods = defaultdict(set)
    for line in text.splitlines():
        vni = line_vni(line)
        if vni is not None:
            floods[vni].update(line_outputs(line))
    return {vni: frozenset(ports) for vni, ports in floods.items()}


@functools.lru_cache(maxsize=PARSE_CACHE_SIZE)
def parse_flood_flows(text):
    """Return {vni: ((vlan, actions), ...)} for table 22 flows."""
    flows = defaultdict(list)
    for line in text.splitlines():
        vni = line_vni(line)
        vlan = RE_DL_VLAN.search(line)
        actions = RE_ACTIONS.search(line)
        if vni is not None and vlan and actions:
            flows[vni].append((int(vlan.group(1)), actions.group(1)))
    return {vni: tuple(items) for vni, items in flows.items()}


@functools.lru_cache(maxsize=PARSE_CACHE_SIZE)
def parse_vlan_vnis(table4, table22):
    """Return {local VLAN: frozenset(vnis)} from tables 4 and 22."""
    vlans = defaultdict(set)
    for line in table4.splitlines():
        tun_id = RE_TUN_ID.search(line)
        vlan_id = RE_VLAN_VID.search(line)
        if tun_id and vlan_id:
            value = int(vlan_id.group(1) or vlan_id.group(2))
            vlans[value & 0xfff].add(int(tun_id.group(1), 16))
    for vni, flows in parse_flood_flows(table22).items():
        for vlan, _ in flows:
            vlans[vlan].add(vni)
    return {vlan: frozenset(vnis) for vlan, vnis in vlans.items()}


@functools.lru_cache(maxsize=PARSE_CACHE_SIZE)
def parse_unique_vlan_vnis(table4, table22):
    """Return {local VLAN: vni} for local VLANs used by exactly one VNI."""
    return {vlan: next(iter(vnis))
            for vlan, vnis in parse_vlan_vnis(table4, table22).items() if len(vnis) == 1}


def present_vnis(sections):
    """Return every VNI a host has flows for, including VNIs on a shared VLAN."""
    return {vni for vnis in parse_vlan_vnis(sections.get("table4", ""),
                                            sections.get("table22", "")).values()
            for vni in vnis}


def line_arp_mac(line):
    """Return the MAC that an ARP responder flow answers with, or None."""
    match = RE_ARP_MAC.search(line)
    if match:
        return (match.group(1) or match.group(2)).lower()
    load = RE_ARP_SHA_LOAD.search(line)
    if load:
        raw = load.group(1).lower().zfill(12)
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    return None


@functools.lru_cache(maxsize=PARSE_CACHE_SIZE)
def parse_arp_flows(text):
    """Return ((vlan, ip, mac), ...) for ARP responder flows."""
    entries = []
    for line in text.splitlines():
        ip = RE_ARP_TPA.search(line)
        vlan = RE_DL_VLAN.search(line)
        mac = line_arp_mac(line)
        if ip and vlan and mac:
            entries.append((int(vlan.group(1)), ip.group(1), mac))
    return tuple(entries)


def has_arp_flows(sections):
    """Return True if the host has ARP responder flows (arp_responder is on)."""
    if "arp_count" in sections:  # --fdb-watch reads only a count, not the table.
        match = RE_FLOW_COUNT.search(sections["arp_count"])
        return bool(match and int(match.group(1)))
    return bool(parse_arp_flows(sections.get("table21", "")))


def parse_static_unicast_flows(text):
    """Return [(vlan, vni, mac)] for table 20 flows without a timeout."""
    entries = []
    for line in text.splitlines():
        mac = RE_DL_DST.search(line)
        vlan = RE_DL_VLAN.search(line)
        vni = line_vni(line)
        if mac and vlan and vni is not None and "hard_timeout" not in line:
            entries.append((int(vlan.group(1)), vni, mac.group(1).lower()))
    return entries


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


def parse_drift(text):
    """Return {key: value} from the drift section."""
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.strip().split("=", 1)
            values[key] = value
    return values


def parse_dvr_macs(table1, table9):
    """Return (this host's DVR MACs, peer DVR MACs it accepts)."""
    own = {mac.lower() for pair in re.findall(
        r"mod_dl_src:([0-9a-fA-F:]{17})|set_field:([0-9a-fA-F:]{17})->eth_src", table1)
        for mac in pair if mac}
    accepted = set()
    for line in table9.splitlines():
        match = re.search(r"dl_src=([0-9a-fA-F:]{17})", line)
        if match and "priority=0" not in line:
            accepted.add(match.group(1).lower())
    return own, accepted


def plan_stale_deletions(sections, known, only_vni):
    """Return [(vni, flow spec, label)] for stale flows to delete, sorted by VNI."""
    vlans = parse_unique_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    deletions = []
    for vlan, ip, mac in parse_arp_flows(sections.get("table21", "")):
        vni = vlans.get(vlan)
        if vni in known and only_vni in (None, vni) and not arp_is_known(known[vni], ip, mac):
            deletions.append(((vni, "arp", int(ipaddress.ip_address(ip)), mac),
                              (vni, f"table=21,arp,dl_vlan={vlan},arp_tpa={ip}",
                               f"arp {ip} -> {mac}")))
    for vlan, vni, mac in parse_static_unicast_flows(sections.get("table20", "")):
        if vni in known and only_vni in (None, vni) and mac not in known[vni]["macs"]:
            deletions.append(((vni, "unicast", 0, mac),
                              (vni, f"table=20,dl_vlan={vlan},dl_dst={mac}",
                               f"unicast {mac}")))
    return [item for _, item in sorted(deletions)]


def plan_flood_fix(sections, vni, peer_ips):
    """Return (vlan, new_actions, added_ports). vlan is None if there is nothing to do."""
    ports = {ip: port for port, ip in parse_tunnels(sections.get("tunnels", "")).items()}
    missing = sorted(set(peer_ips) - set(ports))
    if missing:
        raise ValueError(f"no tunnel port for {', '.join(missing)}")
    flows = parse_flood_flows(sections.get("table22", "")).get(vni, [])
    if len(flows) != 1:
        raise ValueError(f"expected one table 22 flow for VNI {vni}, found {len(flows)}")
    vlan, actions = flows[0]
    present = set(line_outputs(actions))
    added = sorted({ports[ip] for ip in peer_ips} - present)
    if not added:
        return None, actions, []
    return vlan, actions + "".join(f",output:{port}" for port in added), added


def plan_restore(sections, backup_text, vni):
    """Return (vlan, actions, removed, added). vlan is None if there is nothing to do."""
    current = parse_flood_flows(sections.get("table22", "")).get(vni, [])
    saved = parse_flood_flows(backup_text).get(vni, [])
    if len(current) != 1 or len(saved) != 1:
        raise ValueError(f"expected one flood flow for VNI {vni}, found "
                         f"{len(current)} live and {len(saved)} in backup")
    (vlan, live_actions), (saved_vlan, actions) = current[0], saved[0]
    if vlan != saved_vlan:
        raise ValueError(f"local vlan changed from {saved_vlan} to {vlan}")
    tunnels = parse_tunnels(sections.get("tunnels", ""))
    gone = sorted(set(line_outputs(actions)) - set(tunnels))
    if gone:
        raise ValueError(f"backup uses ports that no longer exist: {gone}")
    live, wanted = set(line_outputs(live_actions)), set(line_outputs(actions))
    if live == wanted:
        return None, actions, [], []
    return vlan, actions, sorted(live - wanted), sorted(wanted - live)


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


def plan_orphan_cleanup(sections, context):
    """Return ([(vni, vlan, flow specs)], [(vni, vlan, reason)] that are kept)."""
    if "tags" not in sections:
        return [], []
    used = {int(value) for value in sections["tags"].split() if value.isdigit()}
    vlans = parse_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    plans, kept = [], []
    for vlan, vnis in sorted(vlans.items()):
        for vni in sorted(vnis):
            if vni in context["known"] or context["only_vni"] not in (None, vni):
                continue
            others = vnis - {vni}
            if others:
                # Deleting by dl_vlan would also delete the other VNI's flows.
                shared = ", ".join(f"{other:#x}" for other in sorted(others))
                kept.append((vni, vlan, f"local vlan {vlan} is shared with VNI {shared}"))
            elif vlan in used:
                kept.append((vni, vlan, f"local vlan {vlan} still has OVS ports"))
            else:
                plans.append((vni, vlan, orphan_flow_specs(vni, vlan)))
    return plans, kept


def orphan_flow_specs(vni, vlan):
    """Return the flow specs that delete an orphan VNI on its local VLAN."""
    return [f"table=4,tun_id={vni:#x}", f"table=1,dl_vlan={vlan}",
            f"table=20,dl_vlan={vlan}", f"table=21,dl_vlan={vlan}",
            f"table=22,dl_vlan={vlan}"]


def plan_flood_cleanup(sections, expected, context):
    """Return [(vni, vlan, new actions, removed ports, reasons)]."""
    tunnels = parse_tunnels(sections.get("tunnels", ""))
    plans = []
    for vni, flows in sorted(parse_flood_flows(sections.get("table22", "")).items()):
        if (len(flows) != 1 or vni not in context["known"]
                or context["only_vni"] not in (None, vni)):
            continue
        vlan, actions = flows[0]
        reasons = {}
        for port in line_outputs(actions):
            if port in tunnels:
                reason = stale_flood_reason(tunnels[port], vni, expected, context)
                if reason:
                    reasons[port] = reason
        remaining = [port for port in line_outputs(actions) if port not in reasons]
        if reasons and remaining:
            new_actions = actions
            for port in reasons:
                new_actions = re.sub(rf",output:{port}(?=,|$)", "", new_actions)
            plans.append((vni, vlan, new_actions, sorted(reasons), reasons))
    return plans


def arp_is_known(state, ip, mac):
    """Return True if Neutron knows this IP and MAC, also through address pairs."""
    if mac in state["macs_by_ip"].get(ip, set()):
        return True
    address = ipaddress.ip_address(ip)
    return any(address in net and mac == pair_mac and address.version == net.version
               for net, pair_mac in state["pair_cidrs"])


def audit_stale_entries(host, sections, expected, context, add):
    """Find entries that should not exist, shared local VLANs and missing ARP entries."""
    known, only_vni = context["known"], context["only_vni"]
    tunnels = parse_tunnels(sections.get("tunnels", ""))
    all_vlans = parse_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    vlans = parse_unique_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    arp_flows = parse_arp_flows(sections.get("table21", ""))

    for vni in sorted(present_vnis(sections)):
        if vni not in known and only_vni in (None, vni):
            add("vni_orphan", vni, "no VXLAN network in Neutron")

    for vlan, vnis in sorted(all_vlans.items()):
        if len(vnis) > 1 and (only_vni is None or only_vni in vnis):
            names = ", ".join(f"{vni:#x}" for vni in sorted(vnis))
            add("vlan_conflict", min(vnis), f"local vlan {vlan} used by VNIs {names}")

    for flow_vni, mac, learned, _ in parse_unicast_flows(sections.get("table20", "")):
        if (not learned and flow_vni in known and only_vni in (None, flow_vni)
                and mac not in known[flow_vni]["macs"]):
            add("unicast_stale", flow_vni, f"{mac} is not a Neutron port")

    arp_by_vni = defaultdict(dict)
    for vlan, ip, mac in arp_flows:
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

    for vni, flood_ports in parse_flood_ports(sections.get("table22", "")).items():
        if vni not in known or only_vni not in (None, vni):
            continue
        for port in sorted(flood_ports):
            ip = tunnels.get(port)
            reason = stale_flood_reason(ip, vni, expected, context) if ip else None
            if reason:
                add("flood_stale", vni, reason)

    for vni, entries in sorted(arp_by_vni.items()):
        for ip, mac, owner in expected.get(vni, {}).get("arps", []):
            if owner != host and ip not in entries:
                add("arp_missing", vni, f"{ip} -> {mac} on {owner}")


def audit_host(host, sections, expected, tunnel_ips, context=None):
    """Return a list of findings for one host."""
    tunnels = parse_tunnels(sections.get("tunnels", ""))
    unicast = unicast_by_vni(sections.get("table20", ""))
    floods = parse_flood_ports(sections.get("table22", ""))
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


def make_finding(host, kind, detail, vni=0):
    """Return one finding."""
    return {"detail": detail, "host": host, "kind": kind, "vni": vni}


def config_value(key, value):
    """Return a config value in one spelling, so True and true do not count as drift."""
    if key in VERSION_KEYS:
        return value
    return CONFIG_BOOLEANS.get(value.strip().lower(), value.strip())


def audit_drift(collected):
    """Compare each host's versions and config with the most common value."""
    values = {host: {key: config_value(key, value)
                     for key, value in parse_drift(sections.get("drift", "")).items()}
              for host, sections in collected.items()}
    values = {host: data for host, data in values.items() if data}
    findings = []
    for key in sorted({key for data in values.values() for key in data}):
        counts = Counter(data.get(key, "<unset>") for data in values.values())
        common = counts.most_common(1)[0][0]
        kind = "version_drift" if key in VERSION_KEYS else "config_drift"
        for host, data in sorted(values.items()):
            value = data.get(key, "<unset>")
            if value != common:
                findings.append(make_finding(host, kind, f"{key}={value} (most hosts: {common})"))
    return findings


def audit_dvr(collected):
    """Check that DVR MACs are unique and known to every other host."""
    tables = {host: parse_dvr_macs(sections.get("table1", ""), sections.get("table9", ""))
              for host, sections in collected.items()}
    owners = defaultdict(set)
    for host, (own, _) in tables.items():
        for mac in own:
            owners[mac].add(host)
    findings = []
    for mac, hosts in sorted(owners.items()):
        if len(hosts) > 1:
            findings += [make_finding(host, "dvr_mac_conflict",
                                      f"{mac} is also used by {', '.join(sorted(hosts - {host}))}")
                         for host in sorted(hosts)]
    for host, (_, accepted) in sorted(tables.items()):
        for mac, hosts in sorted(owners.items()):
            if host not in hosts and mac not in accepted:
                owner_list = ", ".join(sorted(hosts))
                findings.append(make_finding(host, "dvr_mac_missing",
                                             f"{mac} of {owner_list} not in table 9"))
    return findings


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


@functools.cache
def openstack_connection():
    """Return the OpenStack connection shared by the whole run."""
    import openstack

    return openstack.connect(cloud="envvars")


def run_parallel(hosts, func, workers):
    """Run func(host) on each host in parallel.

    Return {host: (result, exception or None)} in the order of hosts.
    """
    def call(host):
        try:
            return host, func(host), None
        except Exception as exc:  # One host must not stop the others.
            return host, None, exc

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return {host: (result, error) for host, result, error in pool.map(call, list(hosts))}


def collect_routers(workers=10):
    """Return every router with its gateway and the l3 agents that host it."""
    conn = openstack_connection()
    routers = list(conn.network.routers())

    def agents_of(router_id):
        response = conn.network.get(f"/routers/{router_id}/l3-agents")
        return response.ok, response.json().get("agents", []) if response.ok else []

    # One API call per router, in parallel. Requests keeps 10 connections per pool.
    # More threads would open extra ones and log "connection pool is full".
    results = run_parallel([router.id for router in routers], agents_of, min(workers, 10))
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


@functools.cache
def ssh_control_dir():
    """Return a private directory for SSH control sockets, removed at exit."""
    # /tmp keeps the path short. A Unix socket path can be about 104 bytes at most.
    base = "/tmp" if os.path.isdir("/tmp") else None
    path = tempfile.mkdtemp(dir=base, prefix="ovs-doctor-ssh-")
    atexit.register(shutil.rmtree, path, ignore_errors=True)
    return path


class RemoteError(RuntimeError):
    """A remote script failed. Exit code 255 means SSH itself failed."""

    def __init__(self, message, returncode):
        super().__init__(message)
        self.returncode = returncode


def run_ssh(host, user, timeout, script):
    """Run a script on a host as root, with one sudo for the whole script."""
    target = f"{user}@{host}" if user else host
    # All calls to a host share one SSH connection. It closes 60s after the last call.
    command = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}",
               "-o", "ControlMaster=auto", "-o", f"ControlPath={ssh_control_dir()}/%C",
               "-o", "ControlPersist=60",
               target, "sudo", "-n", "bash", "-s"]
    result = subprocess.run(command, capture_output=True, check=False, input=script,
                            text=True, timeout=timeout + 120)
    if result.returncode != 0:
        raise RemoteError(result.stderr.strip() or f"ssh exit {result.returncode}",
                          result.returncode)
    return result.stdout


def parse_preflight(text):
    """Return the problems the preflight script reported."""
    lines = [line.strip() for line in text.splitlines()]
    if "@preflight done" not in lines:
        return ["preflight output incomplete"]
    return [line[len("@problem "):] for line in lines if line.startswith("@problem ")]


def preflight_host(host, args):
    """Return why a host cannot be used, or None if it passes."""
    try:
        problems = parse_preflight(run_ssh(host, args.ssh_user, args.timeout,
                                           PREFLIGHT_SCRIPT))
    except RemoteError as exc:
        # SSH exits with 255 if it cannot connect. The preflight script always exits
        # with 0. So any other exit code means sudo did not start the script.
        if exc.returncode == 255:
            problems = [f"ssh: {exc}"]
        else:
            problems = [f"passwordless sudo is not available ({exc})"]
    except Exception as exc:
        problems = [f"ssh: {exc}"]
    return "; ".join(problems) or None


def preflight(hosts, args):
    """Check sudo and the Kolla-Ansible setup on each host. Return {host: problem}."""
    results = run_parallel(sorted(hosts), lambda host: preflight_host(host, args),
                           args.workers)
    problems = {host: problem for host, (problem, _) in results.items() if problem}
    for host, problem in problems.items():
        print(f"{host:<8} PREFLIGHT {problem}", file=sys.stderr)
    return problems


def collect_host(host, user, timeout, extra=""):
    """Return a host's sections: tunnels, tags, table<N> and any extra checks."""
    sections = split_sections(run_ssh(host, user, timeout, COLLECT_SCRIPT + extra))
    sections.update(split_flow_tables(sections.pop("brtun", "")))
    return sections


def collect_fdb_flows(host, args, mac, ip):
    """Read only the flows --fdb-watch needs for one port."""
    script = WATCH_SCRIPT.format(ip=shlex.quote(ip or ""), mac=shlex.quote(mac))
    return split_sections(run_ssh(host, args.ssh_user, args.timeout, script))


def apply_changes(host, args, changes=(), deletions=()):
    """Back up br-tun flows to --backup-dir, then change and delete flows.

    Return the path of the backup file on the host.
    """
    lines = [f"$D ovs-ofctl mod-flows br-tun {shlex.quote(flow)}" for flow in changes]
    lines += [f"$D ovs-ofctl del-flows br-tun {shlex.quote(flow)}" for flow in deletions]
    script = """
set -e
D='docker exec openvswitch_vswitchd'
DIR={}
mkdir -p "$DIR"
BACKUP="$DIR/br-tun-$(date +%F-%H%M%S)-$$.flows"
$D ovs-ofctl --no-names dump-flows br-tun > "$BACKUP.tmp"
mv "$BACKUP.tmp" "$BACKUP"
{}
echo "$BACKUP"
""".format(shlex.quote(args.backup_dir), "\n".join(lines))
    return run_ssh(host, args.ssh_user, args.timeout, script).strip()


def apply_flood_flow(host, args, vlan, actions):
    """Set the actions of one table 22 flood flow. Return the backup path."""
    flow = f"table=22,dl_vlan={vlan},actions={actions}"
    return apply_changes(host, args, [flow])


def read_backup(host, args, name):
    """Return (path, table 22 lines) from a backup in --backup-dir, or (None, "")."""
    if name == "latest":
        select = "F=$(ls -1t \"$DIR\"/br-tun-*.flows 2>/dev/null | head -1)"
    else:
        select = f"F=\"$DIR/{name}\"; [ -f \"$F\" ] || F="
    script = f"""
DIR={shlex.quote(args.backup_dir)}
{select}
[ -n "$F" ] || exit 0
echo "$F"
grep 'table=22' "$F" || true
"""
    lines = run_ssh(host, args.ssh_user, args.timeout, script).splitlines()
    return (lines[0], "\n".join(lines[1:])) if lines else (None, "")


def restore_host(host, args, out=print):
    """Put back the flood flow of --vni from a backup on one host."""
    path, backup_text = read_backup(host, args, args.restore)
    if path is None:
        out(f"{host:<8} restore: no backup")
        return
    sections = collect_host(host, args.ssh_user, args.timeout)
    vlan, actions, removed, added = plan_restore(sections, backup_text, args.vni)
    if vlan is None:
        out(f"{host:<8} restore: already matches {path}")
    elif args.dry_run:
        out(f"{host:<8} restore: would remove ports {removed}, add {added} "
            f"from {path}: {actions}")
    else:
        backup = apply_flood_flow(host, args, vlan, actions)
        out(f"{host:<8} restore: removed ports {removed}, added {added} "
            f"from {path}, backup {backup}")


def fix_host(host, sections, findings, args, known, out=print):
    """Repair one host. Return (applied, problems)."""
    peers, problems, blocked, changes = defaultdict(list), [], set(), []
    lines = []
    for item in findings:
        if item["kind"] == "flood_missing":
            peers[item["vni"]].append(item["peer_ip"])
    for vni, ips in sorted(peers.items()):
        try:
            vlan, actions, added = plan_flood_fix(sections, vni, ips)
        except ValueError as exc:
            problems.append(f"vni {vni}: {exc}")
            blocked.add(vni)
            continue
        if vlan is not None:
            changes.append(f"table=22,dl_vlan={vlan},actions={actions}")
            lines.append((vni, 0, f"add flood ports {added}"))
    deletions = [item for item in plan_stale_deletions(sections, known, args.vni)
                 if item[0] not in blocked]
    lines += [(vni, 1 + index, f"delete {label}")
              for index, (vni, _, label) in enumerate(deletions)]
    for vni, _, text in sorted(lines):
        out(f"{host:<8} vni={vni:<8} {text}")
    if args.dry_run or not (changes or deletions):
        return False, problems
    backup = apply_changes(host, args, changes, [spec for _, spec, _ in deletions])
    out(f"{host:<8} fix: applied, backup {backup}")
    return True, problems


def repair_parallel(hosts, action, args, errors, label):
    """Run action(host, out) on hosts in parallel and print each host's lines in order.

    Return {host: result} for the hosts that finished. Failures are added to errors.
    """
    outputs = {host: [] for host in hosts}
    results = run_parallel(hosts, lambda host: action(host, outputs[host].append),
                           args.workers)
    done = {}
    for host, (result, error) in results.items():
        for line in outputs[host]:
            print(line)
        if error:
            errors[host] = f"{label} failed: {error}"
        else:
            done[host] = result
    return done


def reread_after_change(host, args, changed):
    """Read a host again after its flows changed. Return (sections, error)."""
    if not changed:
        return None, None
    try:
        return collect_host(host, args.ssh_user, args.timeout), None
    except Exception as exc:  # The change worked. Only the new state is unknown.
        return None, exc


def changed_but_unread(action, error):
    """Return the error text for a change that worked but could not be re-read."""
    return (f"{action} applied, but reading the host again failed ({error}). "
            f"Its findings are from before the {action}")


def refresh_context(hosts, args, context):
    """Read the hosts, then Neutron. Then a port made in the meantime counts as in use."""
    results = run_parallel(hosts, lambda host: collect_host(host, args.ssh_user, args.timeout),
                           args.workers)
    fresh = {host: sections for host, (sections, error) in results.items() if not error}
    networks, ports, tunnel_ips, ip_hosts = collect_neutron()
    expected = build_expected(networks, ports, tunnel_ips)
    if args.vni is not None:
        expected = {key: value for key, value in expected.items() if key == args.vni}
    context.update(
        bound_hosts=build_bound(networks, ports), collected=set(fresh), ip_hosts=ip_hosts,
        known=build_known(networks, ports),
        present_vnis={host: present_vnis(sections) for host, sections in fresh.items()})
    return fresh, expected, tunnel_ips, networks, ports


def cleanup_host(host, sections, expected, context, args, out=print):
    """Remove stale flood ports and orphan VNIs. Return True if flows changed."""
    plans = plan_flood_cleanup(sections, expected, context)
    orphans, kept = plan_orphan_cleanup(sections, context)
    lines = [(vni, vlan, 0, f"delete orphan flows on local vlan {vlan}")
             for vni, vlan, _ in orphans]
    lines += [(vni, vlan, 0, f"keep orphan: {reason}") for vni, vlan, reason in kept]
    lines += [(vni, vlan, port, f"remove flood port {port}: {reasons[port]}")
              for vni, vlan, _, removed, reasons in plans for port in removed]
    for vni, _, _, text in sorted(lines):
        out(f"{host:<8} vni={vni:<8} {text}")
    if args.dry_run or not (plans or orphans):
        return False
    changes = [f"table=22,dl_vlan={vlan},actions={actions}"
               for _, vlan, actions, _, _ in plans]
    deletions = [spec for _, _, specs in orphans for spec in specs]
    backup = apply_changes(host, args, changes, deletions)
    out(f"{host:<8} cleanup: applied, backup {backup}")
    return True


def parse_hosts(value):
    """Return the --hosts list sorted, without duplicates and empty entries."""
    return sorted({host.strip() for host in value.split(",") if host.strip()})


def fail(message):
    """Print an error and stop with exit code 2 (collection, fix or preflight error)."""
    print(f"ERROR {message}", file=sys.stderr)
    sys.exit(2)


def severity_of(item):
    """Return the severity of a finding."""
    return SEVERITY.get(item["kind"], "warning")


def finding_order(item):
    """Sort key: host, then most severe first, then kind, VNI and detail."""
    return (item["host"], SEVERITY_ORDER.index(severity_of(item)), item["kind"],
            item["vni"], item["detail"])


def present_fdb_entries(sections, vni, mac, ip, owner_ip):
    """Return which l2pop entries for one port exist in a host's tables."""
    vlans = parse_unique_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    tunnels = parse_tunnels(sections.get("tunnels", ""))
    arp = any(vlans.get(vlan) == vni and entry_ip == ip and entry_mac == mac
              for vlan, entry_ip, entry_mac in parse_arp_flows(sections.get("table21", "")))
    unicast = any(entry_vni == vni and entry_mac == mac and not learned
                  and any(tunnels.get(port) == owner_ip for port in outputs)
                  for entry_vni, entry_mac, learned, outputs
                  in parse_unicast_flows(sections.get("table20", "")))
    flood_ports = parse_flood_ports(sections.get("table22", "")).get(vni, set())
    return {"arp": arp,
            "flood": any(tunnels.get(port) == owner_ip for port in flood_ports),
            "unicast": unicast}


def expected_fdb_entries(sections, port_owner, has_ipv4=True):
    """Return the l2pop entries a host should get for a port.

    ARP responder entries exist only for IPv4 addresses of compute and DHCP ports.
    They exist only on hosts with arp_responder on. Such hosts have ARP flows in table 21.
    """
    owner = port_owner or ""
    arp = (has_ipv4 and (owner.startswith("compute:") or owner == "network:dhcp")
           and has_arp_flows(sections))
    return {entry for entry in FDB_ENTRIES if arp or entry != "arp"}


def port_age(port):
    """Return the seconds since the port was created, or None if unknown."""
    created = port.get("created")
    if not created:
        return None
    moment = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
    return datetime.datetime.now(datetime.timezone.utc).timestamp() - moment.timestamp()


def find_fdb_port(args, ports):
    """Return the port that --fdb-watch follows, or stop if it cannot be followed."""
    mac = args.fdb_watch.lower()
    port = next((item for item in ports if item["mac"].lower() == mac), None)
    if port is None or not port.get("ips"):
        fail(f"no port with an IP found for {mac}")
    if port.get("owner") in SKIPPED_PORT_OWNERS:
        fail(f"{mac} is a {port['owner']} port. l2pop adds no flows for it")
    return port


def wait_until_bound(args, port, bound):
    """Wait until the port is ACTIVE on a host. Return (port, start time)."""
    mac = args.fdb_watch.lower()
    if bound(port):
        started = time.time() - (port_age(port) or 0)
        print(f"port {mac} {port['ips'][0]} on {port['host']}, vni {args.vni}, "
              f"port age {time.time() - started:.0f}s")
        return port, started
    print(f"waiting up to {args.fdb_watch_time}s for {mac} to become ACTIVE on a host")
    limit = time.time() + args.fdb_watch_time
    while not bound(port):
        if time.time() >= limit:
            fail(f"{mac} did not become ACTIVE on a host")
        time.sleep(args.fdb_watch_interval)
        port = collect_port(mac) or port
    started = time.time()
    print(f"port {mac} {port['ips'][0]} on {port['host']}, vni {args.vni}, from ACTIVE")
    return port, started


def record_fdb_poll(watch, results, moment):
    """Store what one poll found. Print each entry the first time it shows up."""
    for host, (sections, error) in results.items():
        if error:
            watch.failed[host] = str(error)
            continue
        watch.failed.pop(host, None)
        if watch.vni not in present_vnis(sections):
            continue
        wanted = watch.targets.setdefault(host, set())
        wanted |= expected_fdb_entries(sections, watch.port_owner, bool(watch.arp_ip))
        state = present_fdb_entries(sections, watch.vni, watch.mac, watch.ip, watch.owner_ip)
        for entry, present in state.items():
            if present and (host, entry) not in watch.seen:
                wanted.add(entry)
                watch.seen[(host, entry)] = moment
                print(f"{host:<8} {entry:<8} seen at {moment:.0f}s")


def fdb_watch_complete(watch):
    """Return True when every host has every entry it should get."""
    return bool(watch.targets) and all((host, entry) in watch.seen
                                       for host, wanted in watch.targets.items()
                                       for entry in wanted)


def print_fdb_table(watch, owner):
    """Print when each host got each entry. Return True if an entry never came."""
    print(f"owner {owner}")
    print(f"{'host':<8} " + " ".join(f"{entry:<8}" for entry in FDB_ENTRIES).rstrip())
    missing = False
    for host in sorted(watch.targets):
        row = []
        for entry in FDB_ENTRIES:
            value = watch.seen.get((host, entry))
            if value is not None:
                row.append(f"{value:.0f}s")
            elif entry in watch.targets[host]:
                missing = True
                row.append("never")
            else:
                row.append("n/a")
        print(f"{host:<8} " + " ".join(f"{value:<8}" for value in row).rstrip())
    return missing


def run_fdb_watch(args, ports, tunnel_ips):
    """Report how long each host needs to add the l2pop flows of one port."""
    def bound(item):
        return item.get("status") == "ACTIVE" and item.get("host") in tunnel_ips

    port, started = wait_until_bound(args, find_fdb_port(args, ports), bound)
    # ARP responder entries exist only for IPv4 addresses.
    ip = next((address for address in port["ips"] if ":" not in address), port["ips"][0])
    owner = port["host"]
    all_hosts = set(parse_hosts(args.hosts) if args.hosts else tunnel_ips)
    problems = preflight(all_hosts | {owner}, args)
    if owner in problems:
        fail(f"port owner {owner} failed the preflight check: {problems[owner]}")
    all_hosts -= set(problems)
    watch = types.SimpleNamespace(
        arp_ip="" if ":" in ip else ip,
        failed={host: f"preflight: {problem}" for host, problem in problems.items()},
        ip=ip, mac=args.fdb_watch.lower(), owner_ip=None, port_owner=None, seen={},
        targets={}, vni=args.vni)
    deadline = time.time() + args.fdb_watch_time
    try:
        while True:
            latest = collect_port(watch.mac) or port
            if bound(latest) and latest["host"] != owner:
                moved = time.time() - started
                print(f"port moved from {owner} to {latest['host']} at {moved:.0f}s. "
                      f"Timing starts again.")
                owner = latest["host"]
                started = time.time()
                deadline = started + args.fdb_watch_time
                watch.seen, watch.targets = {}, {}
            port = latest
            watch.owner_ip, watch.port_owner = tunnel_ips[owner], port.get("owner")
            results = run_parallel(
                sorted(all_hosts - {owner}),
                lambda host: collect_fdb_flows(host, args, watch.mac, watch.arp_ip), args.workers)
            record_fdb_poll(watch, results, time.time() - started)
            if fdb_watch_complete(watch) or time.time() >= deadline:
                break
            time.sleep(args.fdb_watch_interval)
    except KeyboardInterrupt:
        print("interrupted")
    missing = print_fdb_table(watch, owner)
    for host, error in sorted(watch.failed.items()):
        print(f"{host:<8} ERROR {error}", file=sys.stderr)
    return 2 if watch.failed else (1 if missing else 0)


def print_summary(findings, previous):
    """Print one row per kind: most severe first, then by count, with the change."""
    counts = Counter(item["kind"] for item in findings)
    print(f"{'severity':<9} {'kind':<22} {'count':>6} {'change':>7}  top hosts")
    kinds = set(counts) | set(previous)
    order = sorted(kinds, key=lambda kind: (
        SEVERITY_ORDER.index(SEVERITY.get(kind, "warning")), -counts[kind], kind))
    by_kind = defaultdict(Counter)
    for item in findings:
        by_kind[item["kind"]][item["host"]] += 1
    for kind in order:
        busiest = sorted(by_kind[kind].items(), key=lambda pair: (-pair[1], pair[0]))[:4]
        top = " ".join(f"{host}:{count}" for host, count in busiest)
        change = counts[kind] - previous[kind] if kind in previous else None
        delta = "" if change is None else f"{change:+d}"
        print(f"{SEVERITY.get(kind, 'warning'):<9} {kind:<22} {counts[kind]:>6} "
              f"{delta:>7}  {top}")


def read_summary_state(path):
    """Return the counts of the previous run, or {} if there are none."""
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def write_summary_state(path, findings):
    """Save the counts of this run for the next --summary."""
    counts = dict(Counter(item["kind"] for item in findings))
    directory = os.path.dirname(os.path.abspath(path))
    with tempfile.NamedTemporaryFile("w", delete=False, dir=directory) as handle:
        json.dump(counts, handle, indent=2, sort_keys=True)
    os.replace(handle.name, path)


def prometheus_label(value):
    """Escape a Prometheus label value."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def write_prometheus_file(path, findings, hosts, collected):
    """Write finding counts and per-host collection status for Prometheus."""
    counts = defaultdict(int)
    for item in findings:
        counts[(item["host"], item["vni"], item["kind"], severity_of(item))] += 1
    lines = [
        "# HELP ovs_doctor_findings Neutron/OVS inconsistencies by type.",
        "# TYPE ovs_doctor_findings gauge",
    ]
    for (host, vni, kind, severity), value in sorted(counts.items()):
        labels = ",".join(f'{name}="{prometheus_label(label)}"' for name, label in
                          (("host", host), ("kind", kind), ("severity", severity), ("vni", vni)))
        lines.append(f"ovs_doctor_findings{{{labels}}} {value}")
    lines += [
        "# HELP ovs_doctor_host_up 1 if the host's flows were collected.",
        "# TYPE ovs_doctor_host_up gauge",
    ]
    for host in sorted(hosts):
        up = 1 if host in collected else 0
        lines.append(f'ovs_doctor_host_up{{host="{prometheus_label(host)}"}} {up}')
    directory = os.path.dirname(os.path.abspath(path))
    with tempfile.NamedTemporaryFile("w", delete=False, dir=directory) as handle:
        handle.write("\n".join(lines) + "\n")
    os.chmod(handle.name, 0o644)
    os.replace(handle.name, path)


def parse_args():
    """Read and check the command line. Return (args, checks)."""
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     prog="ovs-doctor")
    parser.add_argument("--backup-dir", default=DEFAULT_BACKUP_DIR,
                        help=f"where --cleanup, --fix and --restore keep br-tun backups "
                             f"on each host (default: {DEFAULT_BACKUP_DIR})")
    parser.add_argument("--checks", help=f"comma-separated list from {','.join(ALL_CHECKS)} "
                                         "(default: all, or flows with --vni)")
    parser.add_argument("--cleanup", action="store_true",
                        help="remove flood_stale tunnels and vni_orphan flows")
    parser.add_argument("--dry-run", action="store_true",
                        help="with --cleanup, --fix or --restore, show the changes only")
    parser.add_argument("--fdb-watch", metavar="MAC",
                        help="time how long each host takes to add the l2pop flows of "
                             "one port (needs --vni)")
    parser.add_argument("--fdb-watch-interval", type=int, default=15,
                        help="seconds between --fdb-watch polls (default: 15)")
    parser.add_argument("--fdb-watch-time", type=int, default=600,
                        help="seconds --fdb-watch waits at most (default: 600)")
    parser.add_argument("--fix", action="store_true",
                        help="add missing flood ports and delete stale flows")
    parser.add_argument("--hosts", help="comma-separated hosts (default: all OVS agents)")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--prometheus-file", help="write a Prometheus textfile to this path")
    parser.add_argument("--restore", nargs="?", const="latest", metavar="FILE",
                        help="restore the flood flow from a backup in --backup-dir on "
                             "each host (needs --vni, default: newest)")
    parser.add_argument("--severity", choices=SEVERITY_ORDER,
                        help="show and count only findings at this level or above")
    parser.add_argument("--ssh-user", default="ubuntu")
    parser.add_argument("--summary", action="store_true",
                        help="print a table by finding type instead of every line")
    parser.add_argument("--summary-state",
                        help="JSON file with the previous counts, for the --summary change "
                             "column")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--version", action="version", version=f"ovs-doctor {__version__}")
    parser.add_argument("--vni", type=lambda value: int(value, 0),
                        help="audit one VNI, for example 0x285")
    parser.add_argument("--workers", type=int, default=10)
    args = parser.parse_args()
    # Checked in the order of the option names.
    if not os.path.isabs(args.backup_dir):
        parser.error("--backup-dir must be an absolute path")
    checks = set(args.checks.split(",")) if args.checks else (
        {"flows"} if args.vni is not None else set(ALL_CHECKS))
    if checks - set(ALL_CHECKS):
        parser.error(f"--checks takes only {','.join(ALL_CHECKS)}")
    if (args.cleanup or args.fix) and "flows" not in checks:
        parser.error("--cleanup and --fix need the flows check")
    if sum(bool(item) for item in (args.cleanup, args.fix, args.restore)) > 1:
        parser.error("--cleanup, --fix and --restore cannot be used together")
    if args.dry_run and not (args.cleanup or args.fix or args.restore):
        parser.error("--dry-run needs --cleanup, --fix or --restore")
    if args.fdb_watch and args.vni is None:
        parser.error("--fdb-watch needs --vni")
    if args.hosts is not None and not parse_hosts(args.hosts):
        parser.error("--hosts needs at least one host name")
    if args.restore and args.vni is None:
        parser.error("--restore needs --vni")
    if args.restore and args.restore != "latest":
        args.restore = os.path.basename(args.restore)
        if not re.fullmatch(r"br-tun-\d{4}-\d{2}-\d{2}-\d{6}-\d+\.flows", args.restore):
            parser.error("--restore needs a br-tun-<date>-<time>-<pid>.flows file name")
    return args, checks


def select_hosts(args, tunnel_ips, ip_hosts):
    """Return (hosts to check, hosts with a dead OVS agent)."""
    hosts = parse_hosts(args.hosts) if args.hosts else sorted(tunnel_ips)
    # Hosts with a dead OVS agent are not in tunnel_ips. Report them as agent_down.
    dead = sorted(set(ip_hosts.values()) - set(tunnel_ips))
    if args.hosts:
        dead = [host for host in dead if host in hosts]
        hosts = [host for host in hosts if host not in dead]
    if not hosts and not dead:
        fail("no OVS agent hosts to check. Check the credentials and the agent list")
    return hosts, dead


def collect_all(state):
    """Read every usable host. Return {host: sections}. Failures are added to errors."""
    extra = (ROUTER_SCRIPT if "routers" in state.checks else "") + (
        DRIFT_SCRIPT if "drift" in state.checks else "")
    results = run_parallel(state.usable, lambda host: collect_host(
        host, state.args.ssh_user, state.args.timeout, extra), state.args.workers)
    collected = {}
    for host, (sections, error) in results.items():
        if error:
            state.errors.setdefault(host, str(error))
        else:
            collected[host] = sections
    return collected


def audit_all(state):
    """Run the selected checks on the collected hosts. Return the findings."""
    findings = []
    if "flows" in state.checks:
        for host, sections in state.collected.items():
            findings += audit_host(host, sections, state.expected, state.tunnel_ips,
                                   state.context)
    if "dvr" in state.checks:
        findings += audit_dvr(state.collected)
    if "drift" in state.checks:
        findings += audit_drift(state.collected)
    if "routers" in state.checks:
        netns = {host: parse_netns(sections.get("netns", ""))
                 for host, sections in state.collected.items()}
        findings += audit_routers(collect_routers(state.args.workers), state.ports, netns)
    return findings


def replace_flow_findings(findings, host, new):
    """Return the findings with one host's flow findings replaced by new ones."""
    return [item for item in findings
            if item["host"] != host or item["kind"] not in FLOW_KINDS] + new


def stop_if_neutron_shrank(state, networks, ports):
    """Stop if Neutron now returns far fewer ports or networks than at the start."""
    if len(ports) < len(state.ports) / 2 or len(networks) < len(state.networks) / 2:
        fail("Neutron returned far fewer ports or networks. Nothing was changed")


def run_fix(state):
    """Add missing flood ports and delete stale flows (--fix)."""
    args = state.args
    fix_kinds = {"arp_stale", "flood_missing", "unicast_stale"}
    targets = sorted({item["host"] for item in state.findings if item["kind"] in fix_kinds})
    fresh = {}
    results = run_parallel(targets, lambda host: collect_host(
        host, args.ssh_user, args.timeout), args.workers)
    for host, (sections, error) in results.items():
        if error:
            state.errors[host] = f"fix failed: {error}"
        else:
            fresh[host] = sections
    # Read Neutron after the hosts. Then a port made in the meantime is not stale.
    latest_networks, latest_ports, _, _ = collect_neutron()
    stop_if_neutron_shrank(state, latest_networks, latest_ports)
    state.known = build_known(latest_networks, latest_ports)
    state.context["known"] = state.known
    own = defaultdict(list)
    for item in state.findings:
        own[item["host"]].append(item)

    def fix_one(host, out):
        applied, problems = fix_host(host, fresh[host], own[host], args, state.known, out)
        return (problems, *reread_after_change(host, args, applied))

    done = repair_parallel(list(fresh), fix_one, args, state.errors, "fix")
    for host, (problems, after, reread_error) in done.items():
        messages = ["fix incomplete: " + "; ".join(problems)] if problems else []
        if reread_error:
            messages.append(changed_but_unread("fix", reread_error))
        if messages:
            state.errors[host] = "; ".join(messages)
        if after is not None:
            state.findings = replace_flow_findings(state.findings, host, audit_host(
                host, after, state.expected, state.tunnel_ips, state.context))


def run_cleanup(state):
    """Remove stale flood ports and orphan VNIs (--cleanup)."""
    args = state.args
    cleanup_kinds = {"flood_stale", "vni_orphan"}
    if not any(item["kind"] in cleanup_kinds for item in state.findings):
        return
    fresh, latest_expected, latest_ips, latest_networks, latest_ports = refresh_context(
        state.usable, args, state.context)
    stop_if_neutron_shrank(state, latest_networks, latest_ports)
    targets = sorted({item["host"] for item in state.findings
                      if item["kind"] in cleanup_kinds})
    for host in targets:
        if host not in fresh:
            state.errors[host] = "cleanup failed: host could not be read again"

    def cleanup_one(host, out):
        changed = cleanup_host(host, fresh[host], latest_expected, state.context, args, out)
        return reread_after_change(host, args, changed)

    done = repair_parallel([host for host in targets if host in fresh], cleanup_one,
                           args, state.errors, "cleanup")
    for host, (after, reread_error) in done.items():
        if reread_error:
            state.errors[host] = changed_but_unread("cleanup", reread_error)
        if after is not None:
            state.findings = replace_flow_findings(state.findings, host, audit_host(
                host, after, latest_expected, latest_ips, state.context))


def print_report(state):
    """Print and save the results. Return the exit code."""
    args = state.args
    findings = sorted(state.findings, key=finding_order)
    errors = dict(sorted(state.errors.items()))
    if args.severity:
        allowed = SEVERITY_ORDER[:SEVERITY_ORDER.index(args.severity) + 1]
        findings = [item for item in findings if severity_of(item) in allowed]
    if args.prometheus_file:
        write_prometheus_file(args.prometheus_file, findings, sorted(state.hosts + state.dead),
                              state.collected)
    previous = read_summary_state(args.summary_state) if args.summary_state else {}
    if args.json:
        for item in findings:
            item["severity"] = severity_of(item)
        print(json.dumps({"errors": errors, "findings": findings}, indent=2,
                         sort_keys=True))
    else:
        if args.summary:
            print_summary(findings, previous)
        else:
            for item in findings:
                vni = f"vni={item['vni']:<8} " if item["vni"] else ""
                print(f"{item['host']:<8} {vni}{item['kind']:<16} {item['detail']}")
        for host, message in errors.items():
            print(f"{host:<8} ERROR {message}", file=sys.stderr)
        kinds = Counter(item["kind"] for item in findings)
        summary = " ".join(f"{kind}={count}" for kind, count in sorted(kinds.items()))
        print(f"errors={len(errors)} findings={len(findings)} hosts={len(state.hosts)} "
              f"networks={len(state.expected)} {summary}".rstrip())
    if args.summary_state:
        write_summary_state(args.summary_state, findings)
    if errors:
        return 2
    return 1 if findings else 0


def main():
    """Run the tool and return its exit code."""
    args, checks = parse_args()
    ssh_control_dir()  # Make it once, before threads use it.
    try:
        networks, ports, tunnel_ips, ip_hosts = collect_neutron()
    except Exception as exc:  # Missing credentials, Keystone down, and so on.
        fail(f"cannot reach OpenStack ({exc}). Load admin credentials first "
             f"(source admin-openrc.sh)")
    if args.fdb_watch:
        return run_fdb_watch(args, ports, tunnel_ips)
    expected = build_expected(networks, ports, tunnel_ips)
    if args.vni is not None:
        expected = {vni: state for vni, state in expected.items() if vni == args.vni}
    hosts, dead = select_hosts(args, tunnel_ips, ip_hosts)

    problems = preflight(hosts, args)
    if problems and (args.cleanup or args.fix or args.restore):
        fail(f"preflight failed on {', '.join(sorted(problems))}. Nothing was changed")
    usable = [host for host in hosts if host not in problems]
    if hosts and not usable:
        fail("no host passed the preflight check")
    state = types.SimpleNamespace(
        args=args, checks=checks, collected={}, context=None, dead=dead,
        errors={host: f"preflight: {problem}" for host, problem in problems.items()},
        expected=expected,
        findings=[make_finding(host, "agent_down", "neutron-openvswitch-agent is not alive")
                  for host in dead],
        hosts=hosts, ip_hosts=ip_hosts, known=build_known(networks, ports),
        networks=networks, ports=ports, tunnel_ips=tunnel_ips, usable=usable)

    if args.restore:
        repair_parallel(usable, lambda host, out: restore_host(host, args, out),
                        args, state.errors, "restore")
    state.collected = collect_all(state)
    state.context = {
        "bound_hosts": build_bound(networks, ports),
        "collected": set(state.collected),
        "ip_hosts": ip_hosts,
        "known": state.known,
        "only_vni": args.vni,
        "present_vnis": {host: present_vnis(sections)
                         for host, sections in state.collected.items()},
    }
    state.findings += audit_all(state)
    if args.fix:
        run_fix(state)
    if args.cleanup:
        run_cleanup(state)
    return print_report(state)
