"""The dvr check: DVR MACs in br-tun tables 1 and 9."""
import re
from collections import defaultdict

from kolla_ovs_doctor.findings import make_finding


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
