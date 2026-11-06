"""Run the remote scripts with bash against fake docker, ip, iptables and OVS commands."""
import os
import subprocess

import pytest

from kolla_ovs_doctor import parse, remote, scripts

FAKEBIN = os.path.join(os.path.dirname(__file__), "fakebin")


def run_script(script):
    """Run a script with the fake commands first in PATH. Return the CompletedProcess."""
    env = dict(os.environ, PATH=FAKEBIN + os.pathsep + os.environ["PATH"])
    return subprocess.run(["bash", "-s"], capture_output=True, check=False, env=env,
                          input=script, text=True, timeout=30)


@pytest.fixture(scope="module")
def collected():
    """Run the collect, router and drift scripts once. Return (result, sections)."""
    result = run_script(scripts.render("collect") + scripts.render("router")
                        + scripts.render("drift"))
    sections = remote.split_sections(result.stdout)
    sections.update(parse.split_flow_tables(sections.pop("brtun", "")))
    return result, sections


def test_collect_script_exits_0(collected):
    result, _ = collected
    assert result.returncode == 0, result.stderr


def test_collect_script_sections(collected):
    _, sections = collected
    assert parse.parse_tunnels(sections["tunnels"]) == {2: "192.0.2.9"}
    assert sections["tags"].strip() == "3"
    assert parse.present_vnis(sections) == {0x64}
