"""Tests for kolla_ovs_doctor.remote."""
import time
import types

import paramiko
import pytest
from helpers import BR_TUN_DUMP
from sshd import SSHServer

from kolla_ovs_doctor import parse, remote


def test_collect_host_splits_the_br_tun_dump(monkeypatch):
    monkeypatch.setattr(remote, "run_ssh", lambda host, user, timeout, script: (
        '=====AUDIT:tunnels=====\nofport : 2\noptions : {remote_ip="192.0.2.9"}\n'
        "=====AUDIT:tags=====\n3\n=====AUDIT:brtun=====\n" + BR_TUN_DUMP))
    sections = remote.collect_host("h", None, 1)
    assert "brtun" not in sections
    assert parse.present_vnis(sections) == {0x64}
    assert parse.parse_tunnels(sections["tunnels"]) == {2: "192.0.2.9"}


def test_backup_script(ssh_scripts):
    args = types.SimpleNamespace(backup_dir="/var/backups/kolla ovs doctor", ssh_user=None,
                                 timeout=1)
    remote.apply_changes("apply", args, [], [])
    remote.read_backup("latest", args, "latest")
    remote.read_backup("named", args, "br-tun-2026-11-05-101010-1.flows")
    assert "DIR='/var/backups/kolla ovs doctor'" in ssh_scripts["apply"]
    assert '-$$.flows"' in ssh_scripts["apply"]
    assert 'mv "$BACKUP.tmp" "$BACKUP"' in ssh_scripts["apply"]
    assert "/tmp" not in ssh_scripts["latest"] and "/tmp" not in ssh_scripts["named"]


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


def test_ssh_user_option_wins_over_config(sshd, ssh_home):
    remote.run_ssh("box", "other", 5, "true")
    assert sshd.users == ["other"]


def test_exit_code_and_stderr(ssh_home):
    with pytest.raises(remote.RemoteError) as exc:
        remote.run_ssh("box", None, 5, "echo oops >&2; exit 3")
    assert exc.value.returncode == 3 and "oops" in str(exc.value)


def test_big_output_with_stderr_arrives_whole(ssh_home):
    script = ("head -c 300000 /dev/zero | tr '\\0' e >&2\n"
              "head -c 5000000 /dev/zero | tr '\\0' x\n")
    out = remote.run_ssh("box", None, 5, script)
    assert len(out) == 5000000 and set(out) == {"x"}


def test_one_connection_per_host_and_reconnect(sshd, ssh_home):
    before = sshd.accepted
    remote.run_ssh("box", None, 5, "true")
    remote.run_ssh("box", None, 5, "true")
    assert sshd.accepted == before + 1
    sshd.drop_connections()
    assert remote.run_ssh("box", None, 5, "echo back") == "back\n"
    assert sshd.accepted == before + 2


def test_unknown_host_key_is_refused(ssh_home, tmp_path):
    (tmp_path / ".ssh" / "known_hosts").write_text("")
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


def test_read_channel_stops_at_the_deadline(ssh_home):
    channel = remote.client_for("box", None, 5).get_transport().open_session()
    channel.exec_command("sleep 3")
    with pytest.raises(remote.RemoteError) as exc:
        remote.read_channel(channel, time.monotonic() + 0.3)
    channel.close()
    assert exc.value.returncode == 255 and "did not finish in time" in str(exc.value)


def test_parse_preflight():
    assert remote.parse_preflight("@preflight done\n") == []
    assert remote.parse_preflight("@problem a\n@problem b\n@preflight done") == ["a", "b"]
    assert remote.parse_preflight("@problem a\n") == ["preflight output incomplete"]


@pytest.mark.parametrize(("code", "start"), [(1, "passwordless sudo is not available"),
                                             (255, "ssh:")])
def test_preflight_host_errors(monkeypatch, code, start):
    def fail_ssh(*args, **kwargs):
        raise remote.RemoteError("sudo: a password is required", code)

    monkeypatch.setattr(remote, "run_ssh", fail_ssh)
    args = types.SimpleNamespace(ssh_user=None, timeout=1)
    assert remote.preflight_host("h", args).startswith(start)
