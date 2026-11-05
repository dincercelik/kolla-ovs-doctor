"""Run the remote scripts with bash against fake docker, ip, iptables and OVS commands."""
import os
import subprocess

import pytest

from kolla_ovs_doctor import cli

FAKEBIN = os.path.join(os.path.dirname(__file__), "fakebin")


def run_script(script):
    """Run a script with the fake commands first in PATH. Return the CompletedProcess."""
    env = dict(os.environ, PATH=FAKEBIN + os.pathsep + os.environ["PATH"])
    return subprocess.run(["bash", "-s"], capture_output=True, check=False, env=env,
                          input=script, text=True, timeout=30)


@pytest.fixture(scope="module")
def collected():
    """Run the collect, router and drift scripts once. Return (result, sections)."""
    result = run_script(cli.COLLECT_SCRIPT + cli.ROUTER_SCRIPT + cli.DRIFT_SCRIPT)
    sections = cli.split_sections(result.stdout)
    sections.update(cli.split_flow_tables(sections.pop("brtun", "")))
    return result, sections


def test_collect_script_exits_0(collected):
    result, _ = collected
    assert result.returncode == 0, result.stderr


def test_collect_script_sections(collected):
    _, sections = collected
    assert cli.parse_tunnels(sections["tunnels"]) == {2: "192.0.2.9"}
    assert sections["tags"].strip() == "3"
    assert cli.present_vnis(sections) == {0x64}


def test_router_script_namespaces(collected):
    _, sections = collected
    namespaces = cli.parse_netns(sections["netns"])
    assert set(namespaces) == {"qrouter-r1", "snat-r1"}
    snat = namespaces["snat-r1"]
    assert snat["addr"] and snat["neigh"] and snat["route"]
    assert snat["nat"] == ["-A neutron-l3-agent-snat -o qg-1 -j SNAT --to-source 203.0.113.5"]


def test_drift_script_keys(collected):
    _, sections = collected
    drift = cli.parse_drift(sections["drift"])
    assert {"agent_container_os", "host_kernel", "host_os", "image", "ovs_container_os",
            "ovs_image", "ovs_version", "ovsdb_image"} <= set(drift)
    assert drift["ovs_version"] == "3.3.0"


def test_watch_script_passes_mac_and_ip():
    result = run_script(cli.WATCH_SCRIPT.format(ip="10.0.0.5", mac="fa:16:3e:00:00:09"))
    sections = cli.split_sections(result.stdout)
    assert result.returncode == 0, result.stderr
    assert "dl_dst=fa:16:3e:00:00:09" in sections["table20"]
    assert "arp_tpa=10.0.0.5" in sections["table21"]
    assert cli.has_arp_flows(sections)


def test_watch_script_without_ipv4_skips_table_21():
    result = run_script(cli.WATCH_SCRIPT.format(ip="''", mac="fa:16:3e:00:00:09"))
    assert result.returncode == 0, result.stderr
    assert cli.split_sections(result.stdout)["table21"] == ""
    assert "arp_tpa" not in result.stderr
