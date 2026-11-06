"""Parse br-tun flow dumps from ovs-ofctl and ovs-vsctl."""
import functools
import re
from collections import defaultdict

# Parsers keep a small cache, keyed by the dump text. So each host's tables are
# parsed once, even when several checks read them. Do not change a cached result:
# all callers share it. Hosts are checked one at a time, so 16 entries are enough.
PARSE_CACHE_SIZE = 16
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
