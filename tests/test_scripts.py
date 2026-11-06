"""Tests for kolla_ovs_doctor.scripts: rendering, syntax and content of the shell scripts."""
import os
import pathlib
import re
import shutil
import subprocess

import jinja2
import pytest

from kolla_ovs_doctor import scripts

TEMPLATES = pathlib.Path(scripts.__file__).parent / "templates"
# Sample values for every template. A template without a sample fails the tests.
SAMPLES = {
    "apply_changes": {"backup_dir": "/var/backups/kolla ovs doctor",
                      "changes": ["table=22,dl_vlan=1,actions=output:2"],
                      "deletions": ["table=21,dl_vlan=1"]},
    "collect": {},
    "drift": {},
    "fdb_watch": {"ip": "10.0.0.5", "mac": "fa:16:3e:00:00:09"},
    "preflight": {},
    "read_backup": {"backup_dir": "/var/backups/kolla ovs doctor",
                    "name": "br-tun-2026-11-05-101010-1.flows"},
    "router": {},
}


def rendered():
    """Return {label: script} for every template, plus the collect run with all checks."""
    texts = {name: scripts.render(name, **values) for name, values in SAMPLES.items()}
    texts["collect+router+drift"] = texts["collect"] + texts["router"] + texts["drift"]
    texts["read_backup latest"] = scripts.render("read_backup", backup_dir="/b", name="latest")
    return texts


def test_every_template_has_a_sample():
    assert sorted(path.name[:-len(".sh.j2")] for path in TEMPLATES.glob("*.sh.j2")) == sorted(
        SAMPLES)


def test_missing_values_are_an_error():
    with pytest.raises(jinja2.UndefinedError):
        scripts.render("fdb_watch", mac="fa:16:3e:00:00:09")


def test_values_are_quoted():
    script = scripts.render("apply_changes", backup_dir="/var/backups/a b",
                            changes=["table=22,actions=output:2"], deletions=["x; rm -rf /"])
    assert "DIR='/var/backups/a b'" in script
    assert "del-flows br-tun 'x; rm -rf /'" in script


def test_watch_script_passes_mac_and_ip():
    script = scripts.render("fdb_watch", ip="10.0.0.5", mac="fa:16:3e:00:00:09")
    assert "bash -s -- fa:16:3e:00:00:09 10.0.0.5 <<'OVS'" in script


@pytest.mark.parametrize(("label", "script"), sorted(rendered().items()))
def test_scripts_parse(label, script):
    result = subprocess.run(["bash", "-n"], capture_output=True, check=False, input=script,
                            text=True)
    assert result.returncode == 0, result.stderr


def test_backup_script():
    script = scripts.render("apply_changes", **SAMPLES["apply_changes"])
    assert '-$$.flows"' in script and 'mv "$BACKUP.tmp" "$BACKUP"' in script
    assert "/tmp" not in rendered()["read_backup"] + rendered()["read_backup latest"]


def test_one_docker_exec_and_no_sudo_inside_scripts():
    assert scripts.render("collect").count("docker exec") == 1
    assert not any(re.search(r"(^|[\s;|&(`$])sudo\s", text.replace("'@problem sudo", ""))
                   for text in rendered().values())


def test_local_preflight_reports_a_problem():
    result = subprocess.run(["bash", "-s"], capture_output=True, check=False,
                            input=scripts.render("preflight"), text=True, timeout=60)
    assert result.returncode == 0
    assert "@preflight done" in result.stdout and "@problem" in result.stdout


@pytest.mark.parametrize(("label", "script"), sorted(rendered().items()))
def test_shellcheck(label, script):
    if not shutil.which("shellcheck"):
        if os.environ.get("OVS_DOCTOR_REQUIRE_SHELLCHECK") == "1":
            pytest.fail("shellcheck is required but not installed")
        pytest.skip("shellcheck is not installed")
    result = subprocess.run(["shellcheck", "--shell=bash", "-"], capture_output=True,
                            check=False, input=script, text=True)
    assert result.returncode == 0, result.stdout
