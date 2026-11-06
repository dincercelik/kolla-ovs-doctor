"""Tests for kolla_ovs_doctor.remote."""
import types

import pytest
from helpers import BR_TUN_DUMP

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


def test_ssh_command(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = " ".join(command)
        return types.SimpleNamespace(returncode=0, stderr="", stdout="ok")

    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    remote.run_ssh("h", "u", 5, "true")
    assert "ControlMaster=auto" in seen["command"] and "ControlPersist=60" in seen["command"]
    assert "ControlPath=/tmp/ovs-doctor-ssh-" in seen["command"]
    assert seen["command"].endswith("sudo -n bash -s")


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
