"""ovs-doctor: check that the br-tun flows on every OVS host match Neutron's VXLAN state.

By default all VXLAN networks are checked. Use --vni to check one.
Tables 4, 20, 21 and 22 are checked for missing flows, and for flows that
Neutron does not know. A full run also does these checks (see --checks):
  drift    config and version differences between agents
  dvr      DVR MACs in tables 1 and 9
  routers  L3 HA state, and qrouter and SNAT namespaces
A host whose OVS agent is down is reported as agent_down. It is not checked.

Run it on a host with SSH key access to the hypervisors. Load admin
credentials first (source admin-openrc.sh). SSH reads HostName, User, Port and
IdentityFile from ~/.ssh/config. A new host key is accepted, but a changed one is
refused. Jump hosts (ProxyJump, ProxyCommand) are not supported.

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
import os
import re
import types

from kolla_ovs_doctor import (
    __version__,
    checks,
    fdb_watch,
    neutron,
    parse,
    remote,
    repair,
    report,
    scripts,
    util,
)
from kolla_ovs_doctor.findings import SEVERITY_ORDER, make_finding

ALL_CHECKS = ("drift", "dvr", "flows", "routers")


def parse_hosts(value):
    """Return the --hosts list sorted, without duplicates and empty entries."""
    return sorted({host.strip() for host in value.split(",") if host.strip()})


def parse_args():
    """Read and check the command line. Return (args, checks)."""
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     prog="ovs-doctor")
    parser.add_argument("--backup-dir", default=remote.DEFAULT_BACKUP_DIR,
                        help=f"where --cleanup, --fix and --restore keep br-tun backups "
                             f"on each host (default: {remote.DEFAULT_BACKUP_DIR})")
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
        util.fail("no OVS agent hosts to check. Check the credentials and the agent list")
    return hosts, dead


def collect_all(state):
    """Read every usable host. Return {host: sections}. Failures are added to errors."""
    extra = (scripts.render("router") if "routers" in state.checks else "") + (
        scripts.render("drift") if "drift" in state.checks else "")
    results = util.run_parallel(state.usable, lambda host: remote.collect_host(
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
            findings += checks.flows.audit_host(host, sections, state.expected,
                                                state.tunnel_ips, state.context)
    if "dvr" in state.checks:
        findings += checks.dvr.audit_dvr(state.collected)
    if "drift" in state.checks:
        findings += checks.drift.audit_drift(state.collected)
    if "routers" in state.checks:
        netns = {host: checks.routers.parse_netns(sections.get("netns", ""))
                 for host, sections in state.collected.items()}
        routers = neutron.collect_routers(state.args.workers)
        findings += checks.routers.audit_routers(routers, state.ports, netns)
    return findings


def main():
    """Run the tool and return its exit code."""
    args, checks = parse_args()
    try:
        networks, ports, tunnel_ips, ip_hosts = neutron.collect_neutron()
    except Exception as exc:  # Missing credentials, Keystone down, and so on.
        util.fail(f"cannot reach OpenStack ({exc}). Load admin credentials first "
                  f"(source admin-openrc.sh)")
    if args.fdb_watch:
        return fdb_watch.run_fdb_watch(args, ports, tunnel_ips)
    expected = neutron.build_expected(networks, ports, tunnel_ips)
    if args.vni is not None:
        expected = {vni: state for vni, state in expected.items() if vni == args.vni}
    hosts, dead = select_hosts(args, tunnel_ips, ip_hosts)

    problems = remote.preflight(hosts, args)
    if problems and (args.cleanup or args.fix or args.restore):
        util.fail(f"preflight failed on {', '.join(sorted(problems))}. Nothing was changed")
    usable = [host for host in hosts if host not in problems]
    if hosts and not usable:
        util.fail("no host passed the preflight check")
    state = types.SimpleNamespace(
        args=args, checks=checks, collected={}, context=None, dead=dead,
        errors={host: f"preflight: {problem}" for host, problem in problems.items()},
        expected=expected,
        findings=[make_finding(host, "agent_down", "neutron-openvswitch-agent is not alive")
                  for host in dead],
        hosts=hosts, ip_hosts=ip_hosts, known=neutron.build_known(networks, ports),
        networks=networks, ports=ports, tunnel_ips=tunnel_ips, usable=usable)

    if args.restore:
        repair.repair_parallel(usable, lambda host, out: repair.restore_host(host, args, out),
                               args, state.errors, "restore")
    state.collected = collect_all(state)
    state.context = {
        "bound_hosts": neutron.build_bound(networks, ports),
        "collected": set(state.collected),
        "ip_hosts": ip_hosts,
        "known": state.known,
        "only_vni": args.vni,
        "present_vnis": {host: parse.present_vnis(sections)
                         for host, sections in state.collected.items()},
    }
    state.findings += audit_all(state)
    if args.fix:
        repair.run_fix(state)
    if args.cleanup:
        repair.run_cleanup(state)
    return report.print_report(state)
