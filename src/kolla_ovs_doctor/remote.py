"""Run scripts on the hosts over SSH with Paramiko, under one sudo per script."""
import atexit
import functools
import getpass
import os
import re
import select
import sys
import time

import paramiko

from kolla_ovs_doctor import parse, scripts, util

DEFAULT_BACKUP_DIR = "/var/backups/kolla-ovs-doctor"
# One open SSH client per (host, user) for the whole run. Calls to one host never
# overlap, so this needs no lock.
_CLIENTS = {}


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


class RemoteError(RuntimeError):
    """A remote script failed. Exit code 255 means SSH itself failed."""

    def __init__(self, message, returncode):
        super().__init__(message)
        self.returncode = returncode


@functools.cache
def ssh_config(path, stamp):
    """Return the parsed ssh_config at path. stamp is (mtime, size), or None if it is missing."""
    return paramiko.SSHConfig.from_path(path) if stamp else paramiko.SSHConfig()


@functools.cache
def ssh_config_entry(path, stamp, host):
    """Return the ssh_config settings for host.

    This is cached per host, because Paramiko looks up this machine's own name in DNS
    for every IdentityFile line. With slow DNS that takes 5 seconds each time.
    """
    return ssh_config(path, stamp).lookup(host)


def ssh_options(host, user):
    """Return the Paramiko connect options for host, from ~/.ssh/config and --ssh-user."""
    path = os.path.expanduser("~/.ssh/config")
    if os.path.exists(path):
        info = os.stat(path)
        stamp = (info.st_mtime_ns, info.st_size)
    else:
        stamp = None
    found = ssh_config_entry(path, stamp, host)
    if "proxycommand" in found or "proxyjump" in found:
        raise RemoteError(f"ssh: {host} needs ProxyJump or ProxyCommand, and jump hosts are "
                          f"not supported", 255)
    options = {"hostname": found.get("hostname", host), "port": int(found.get("port", 22)),
               "username": user or found.get("user") or getpass.getuser()}
    if "identityfile" in found:
        options["key_filename"] = found["identityfile"]
    return options


def connect(host, user, timeout):
    """Open an SSH connection to host.

    A host that is not in known_hosts is accepted for this run, and not saved. A host
    whose key changed is refused.
    """
    client = paramiko.SSHClient()
    for path in (os.path.expanduser("~/.ssh/known_hosts"), "/etc/ssh/ssh_known_hosts"):
        if os.path.exists(path):
            client.load_system_host_keys(path)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(allow_agent=True, auth_timeout=timeout, banner_timeout=timeout,
                   look_for_keys=True, timeout=timeout, **ssh_options(host, user))
    client.get_transport().set_keepalive(30)
    return client


def client_for(host, user, timeout):
    """Return the open SSH client for host. Connect first if there is none, or it closed."""
    client = _CLIENTS.get((host, user))
    transport = client.get_transport() if client else None
    if transport is None or not transport.is_active():
        client = _CLIENTS[(host, user)] = connect(host, user, timeout)
    return client


def open_channel(host, user, timeout):
    """Open a session channel to host. If the open connection was dropped, connect once more."""
    was_open = (host, user) in _CLIENTS
    try:
        return client_for(host, user, timeout).get_transport().open_session(timeout=timeout)
    except (EOFError, OSError, paramiko.SSHException):
        if not was_open:
            raise
        _CLIENTS.pop((host, user)).close()
        return client_for(host, user, timeout).get_transport().open_session(timeout=timeout)


def close_clients():
    """Close every open SSH client."""
    for client in _CLIENTS.values():
        client.close()
    _CLIENTS.clear()


atexit.register(close_clients)


def read_channel(channel, deadline):
    """Read stdout and stderr together until the command ends. Return both as text."""
    out, err = [], []
    while True:
        if channel.recv_ready():
            out.append(channel.recv(65536))
        elif channel.recv_stderr_ready():
            err.append(channel.recv_stderr(65536))
        elif channel.eof_received or channel.closed:
            break
        elif time.monotonic() >= deadline:
            raise RemoteError("ssh: the host did not finish in time", 255)
        else:
            # The channel only signals stdout, so wake up often enough for stderr too.
            select.select([channel], [], [], 0.05)
    return (b"".join(out).decode(errors="replace"), b"".join(err).decode(errors="replace"))


def run_ssh(host, user, timeout, script):
    """Run a script on a host as root, with one sudo for the whole script."""
    deadline = time.monotonic() + timeout + 120
    try:
        channel = open_channel(host, user, timeout)
        with channel:
            channel.exec_command("sudo -n bash -s")
            channel.sendall(script.encode())
            channel.shutdown_write()
            out, err = read_channel(channel, deadline)
            code = channel.recv_exit_status()
    except (EOFError, OSError, paramiko.SSHException) as exc:
        raise RemoteError(f"ssh: {exc or type(exc).__name__}", 255) from exc
    if code != 0:
        raise RemoteError(err.strip() or f"ssh exit {code}", code)
    return out


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
                                           scripts.render("preflight")))
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
    sections = split_sections(run_ssh(host, user, timeout, scripts.render("collect") + extra))
    sections.update(parse.split_flow_tables(sections.pop("brtun", "")))
    return sections


def collect_fdb_flows(host, args, mac, ip):
    """Read only the flows --fdb-watch needs for one port."""
    script = scripts.render("fdb_watch", ip=ip or "", mac=mac)
    return split_sections(run_ssh(host, args.ssh_user, args.timeout, script))


def apply_changes(host, args, changes=(), deletions=()):
    """Back up br-tun flows to --backup-dir, then change and delete flows.

    Return the path of the backup file on the host.
    """
    script = scripts.render("apply_changes", backup_dir=args.backup_dir, changes=list(changes),
                            deletions=list(deletions))
    return run_ssh(host, args.ssh_user, args.timeout, script).strip()


def apply_flood_flow(host, args, vlan, actions):
    """Set the actions of one table 22 flood flow. Return the backup path."""
    flow = f"table=22,dl_vlan={vlan},actions={actions}"
    return apply_changes(host, args, [flow])


def read_backup(host, args, name):
    """Return (path, table 22 lines) from a backup in --backup-dir, or (None, "")."""
    script = scripts.render("read_backup", backup_dir=args.backup_dir, name=name)
    lines = run_ssh(host, args.ssh_user, args.timeout, script).splitlines()
    return (lines[0], "\n".join(lines[1:])) if lines else (None, "")
