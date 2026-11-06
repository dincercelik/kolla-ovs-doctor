"""Tests for kolla_ovs_doctor.scripts: syntax and content of the shell scripts."""
import re
import subprocess
import types

from kolla_ovs_doctor import remote, scripts


def test_watch_script_passes_mac_and_ip():
    script = scripts.WATCH_SCRIPT.format(ip="10.0.0.5", mac="fa:16:3e:00:00:09")
    assert "bash -s -- fa:16:3e:00:00:09 10.0.0.5 <<'OVS'" in script


def test_remote_scripts_parse(ssh_scripts):
    args = types.SimpleNamespace(backup_dir="/var/backups/kolla ovs doctor", ssh_user=None,
                                 timeout=1)
    remote.apply_changes("apply", args, ["table=22,dl_vlan=1,actions=output:2"],
                         ["table=21,dl_vlan=1"])
    remote.read_backup("latest", args, "latest")
    remote.read_backup("named", args, "br-tun-2026-11-05-101010-1.flows")
    collect = scripts.COLLECT_SCRIPT + scripts.ROUTER_SCRIPT + scripts.DRIFT_SCRIPT
    texts = dict(ssh_scripts, collect=collect, preflight=scripts.PREFLIGHT_SCRIPT,
                 watch=scripts.WATCH_SCRIPT.format(ip="10.0.0.5", mac="fa:16:3e:00:00:09"))
    for name, script in sorted(texts.items()):
        result = subprocess.run(["bash", "-n"], capture_output=True, check=False, input=script,
                                text=True)
        assert result.returncode == 0, (name, result.stderr)


def test_one_docker_exec_and_no_sudo_inside_scripts(ssh_scripts):
    args = types.SimpleNamespace(backup_dir="/b", ssh_user=None, timeout=1)
    remote.apply_changes("apply", args, [], [])
    texts = [scripts.COLLECT_SCRIPT, scripts.DRIFT_SCRIPT, scripts.PREFLIGHT_SCRIPT,
             scripts.ROUTER_SCRIPT, scripts.WATCH_SCRIPT, ssh_scripts["apply"]]
    assert scripts.COLLECT_SCRIPT.count("docker exec") == 1
    assert not any(re.search(r"(^|[\s;|&(`$])sudo\s", text.replace("'@problem sudo", ""))
                   for text in texts)


def test_local_preflight_reports_a_problem():
    result = subprocess.run(["bash", "-s"], capture_output=True, check=False,
                            input=scripts.PREFLIGHT_SCRIPT, text=True, timeout=60)
    assert result.returncode == 0
    assert "@preflight done" in result.stdout and "@problem" in result.stdout
