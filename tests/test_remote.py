"""Tests for kolla_ovs_doctor.remote."""
import socket
import time
import types

import paramiko
import pytest
from sshd import SSHServer

from kolla_ovs_doctor import remote


@pytest.fixture(scope="module")
def sshd():
    """Start the test SSH server once for this module."""
    server = SSHServer()
    yield server
    server.close()


@pytest.fixture
def ssh_home(sshd, tmp_path, monkeypatch):
    """Make a home folder with an SSH config for host "box", its key and known_hosts.

    Return a function that rewrites the config, so a test can change it.
    """
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    sshd.client_key.write_private_key_file(str(ssh / "test_key"))
    (ssh / "known_hosts").write_text(
        f"[127.0.0.1]:{sshd.port} {sshd.host_key.get_name()} {sshd.host_key.get_base64()}\n")

    def write_config(extra=""):
        (ssh / "config").write_text(
            f"Host box\n  HostName 127.0.0.1\n  IdentityFile ~/.ssh/test_key\n"
            f"  Port {sshd.port}\n  User tester\n{extra}")

    write_config()
    # Paramiko asks DNS for this machine's name. Answer at once, and count the calls.
    write_config.fqdn_calls = []
    monkeypatch.setattr(socket, "getfqdn",
                        lambda name="": write_config.fqdn_calls.append(name) or "localhost")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    remote.close_clients()
    sshd.commands.clear()
    sshd.users.clear()
    yield write_config
    remote.close_clients()


def test_run_ssh_uses_ssh_config_and_one_sudo(sshd, ssh_home):
    assert remote.run_ssh("box", None, 5, "echo hello") == "hello\n"
    assert sshd.users == ["tester"]
    assert sshd.commands == ["sudo -n bash -s"]


def test_a_host_that_never_answers_stops_at_the_deadline(sshd, ssh_home, monkeypatch):
    monkeypatch.setattr(remote, "SCRIPT_GRACE", 0)
    sshd.exec_delay = 3
    started = time.monotonic()
    try:
        with pytest.raises(remote.RemoteError) as exc:
            remote.run_ssh("box", None, 1, "true")
    finally:
        sshd.exec_delay = 0
    assert exc.value.returncode == 255 and "did not finish in time" in str(exc.value)
    assert time.monotonic() - started < 2.5


def test_exit_code_and_stderr(ssh_home):
    with pytest.raises(remote.RemoteError) as exc:
        remote.run_ssh("box", None, 5, "echo oops >&2; exit 3")
    assert exc.value.returncode == 3 and "oops" in str(exc.value)


def test_big_output_with_stderr_arrives_whole(ssh_home):
    script = ("head -c 300000 /dev/zero | tr '\\0' e >&2\n"
              "head -c 5000000 /dev/zero | tr '\\0' x\n")
    out = remote.run_ssh("box", None, 5, script)
    assert len(out) == 5000000 and set(out) == {"x"}


def test_changed_host_key_is_refused(sshd, ssh_home, tmp_path):
    other = paramiko.RSAKey.generate(2048)
    (tmp_path / ".ssh" / "known_hosts").write_text(
        f"[127.0.0.1]:{sshd.port} {other.get_name()} {other.get_base64()}\n")
    with pytest.raises(remote.RemoteError) as exc:
        remote.run_ssh("box", None, 5, "true")
    assert exc.value.returncode == 255


def test_wrong_client_key_is_refused(ssh_home, tmp_path):
    paramiko.RSAKey.generate(2048).write_private_key_file(str(tmp_path / ".ssh" / "test_key"))
    with pytest.raises(remote.RemoteError) as exc:
        remote.run_ssh("box", None, 5, "true")
    assert exc.value.returncode == 255


def test_jump_hosts_are_not_supported(ssh_home):
    ssh_home("  ProxyJump bastion\n")
    with pytest.raises(remote.RemoteError) as exc:
        remote.run_ssh("box", None, 5, "true")
    assert exc.value.returncode == 255 and "jump hosts are not supported" in str(exc.value)


@pytest.mark.parametrize(("code", "start"), [(1, "passwordless sudo is not available"),
                                             (255, "ssh:")])
def test_preflight_host_errors(monkeypatch, code, start):
    def fail_ssh(*args, **kwargs):
        raise remote.RemoteError("sudo: a password is required", code)

    monkeypatch.setattr(remote, "run_ssh", fail_ssh)
    args = types.SimpleNamespace(ssh_user=None, timeout=1)
    assert remote.preflight_host("h", args).startswith(start)
