"""Run scripts on the hosts over SSH, under one sudo per script."""
import atexit
import functools
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from kolla_ovs_doctor import parse, scripts, util

DEFAULT_BACKUP_DIR = "/var/backups/kolla-ovs-doctor"


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
                                           scripts.PREFLIGHT_SCRIPT))
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
    results = util.run_parallel(sorted(hosts), lambda host: preflight_host(host, args),
                                args.workers)
    problems = {host: problem for host, (problem, _) in results.items() if problem}
    for host, problem in problems.items():
        print(f"{host:<8} PREFLIGHT {problem}", file=sys.stderr)
    return problems


def collect_host(host, user, timeout, extra=""):
    """Return a host's sections: tunnels, tags, table<N> and any extra checks."""
    sections = split_sections(run_ssh(host, user, timeout, scripts.COLLECT_SCRIPT + extra))
    sections.update(parse.split_flow_tables(sections.pop("brtun", "")))
    return sections


def collect_fdb_flows(host, args, mac, ip):
    """Read only the flows --fdb-watch needs for one port."""
    script = scripts.WATCH_SCRIPT.format(ip=shlex.quote(ip or ""), mac=shlex.quote(mac))
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
