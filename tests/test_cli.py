"""Tests for kolla_ovs_doctor.cli: options, host selection and the whole run."""
import json

import pytest
from helpers import BAD_PREFLIGHT, GOOD_PREFLIGHT, run_cli

from kolla_ovs_doctor import cli, neutron, remote, scripts


@pytest.fixture
def two_hosts(monkeypatch):
    """A cloud with a good and a bad host. Return the list of (host, kind) SSH calls."""
    calls = []

    def fake_ssh(host, user, timeout, script):
        is_preflight = script == scripts.render("preflight")
        calls.append((host, "preflight" if is_preflight else "other"))
        if is_preflight:
            return BAD_PREFLIGHT if host == "bad" else GOOD_PREFLIGHT
        return ""

    monkeypatch.setattr(remote, "run_ssh", fake_ssh)
    monkeypatch.setattr(neutron, "collect_neutron", lambda: (
        [], [], {"bad": "192.0.2.2", "good": "192.0.2.1"},
        {"192.0.2.1": "good", "192.0.2.2": "bad"}))
    return calls


def test_preflight_failure_stops_fix_before_anything_else(two_hosts, run_main):
    code, _, _ = run_main(["--checks", "flows", "--dry-run", "--fix"])
    assert code == 2
    assert all(kind == "preflight" for _, kind in two_hosts)


def test_preflight_failure_skips_the_host_in_an_audit(two_hosts, run_main):
    code, _, _ = run_main(["--checks", "flows", "--json"])
    assert code == 2
    assert ("bad", "other") not in two_hosts and ("good", "other") in two_hosts


def test_no_host_passing_preflight_exits_2(monkeypatch, two_hosts, run_main):
    monkeypatch.setattr(neutron, "collect_neutron", lambda: ([], [], {"bad": "192.0.2.2"}, {}))
    assert run_main(["--checks", "flows"])[0] == 2


def test_parse_hosts():
    assert cli.parse_hosts(" c2,a,,c2 , b") == ["a", "b", "c2"]


def test_hosts_are_sorted_and_deduplicated(monkeypatch, run_main):
    collected = []
    monkeypatch.setattr(remote, "run_ssh", lambda *args: GOOD_PREFLIGHT)
    monkeypatch.setattr(neutron, "collect_neutron",
                        lambda: ([], [], {"a": "192.0.2.1", "b": "192.0.2.2"}, {}))
    monkeypatch.setattr(remote, "collect_host", lambda host, *a, **k: collected.append(host) or {})
    run_main(["--checks", "flows", "--hosts", "b,a,b,", "--json"])
    assert collected == ["a", "b"]


def test_empty_hosts_option_is_rejected(run_main):
    assert run_main(["--hosts", ","])[0] == 2


def test_no_hosts_exits_2(monkeypatch, run_main):
    monkeypatch.setattr(neutron, "collect_neutron", lambda: ([], [], {}, {}))
    assert run_main(["--checks", "flows"])[0] == 2


@pytest.fixture
def dead_agent(monkeypatch):
    monkeypatch.setattr(remote, "run_ssh", lambda *args: GOOD_PREFLIGHT)
    monkeypatch.setattr(neutron, "collect_neutron", lambda: (
        [], [], {"a": "192.0.2.1"}, {"192.0.2.1": "a", "192.0.2.9": "dead1"}))
    monkeypatch.setattr(remote, "collect_host", lambda host, *a, **k: {})


def test_dead_agent_is_reported(dead_agent, run_main, tmp_path):
    prometheus = tmp_path / "x.prom"
    code, out, _ = run_main(["--checks", "flows", "--json", "--prometheus-file",
                             str(prometheus)])
    findings = json.loads(out)["findings"]
    assert code == 1
    assert [item["host"] for item in findings if item["kind"] == "agent_down"] == ["dead1"]
    body = prometheus.read_text()
    assert 'host_up{host="dead1"} 0' in body and 'host_up{host="a"} 1' in body


def test_hosts_option_with_only_a_dead_host(dead_agent, run_main):
    code, out, _ = run_main(["--checks", "flows", "--hosts", "dead1", "--json"])
    assert code == 1 and "agent_down" in out


def test_cannot_reach_openstack(monkeypatch, run_main):
    def broken():
        raise RuntimeError("Cloud envvars was not found.")

    monkeypatch.setattr(neutron, "collect_neutron", broken)
    code, _, err = run_main([])
    assert code == 2 and "cannot reach OpenStack" in err


def test_help_and_version():
    help_text = run_cli("--help").stdout
    assert help_text.startswith("usage: ovs-doctor")
    for option in ("--fdb-watch-time", "--prometheus-file", "--summary-state", "--version"):
        assert option in help_text
    assert run_cli("--version").stdout.strip() == f"ovs-doctor {cli.__version__}"


@pytest.mark.parametrize("option", ["--state", "--textfile", "--watch-interval", "--watch-time"])
def test_old_option_names_are_gone(option):
    result = run_cli(option, "1")
    assert result.returncode == 2 and "unrecognized arguments" in result.stderr


@pytest.mark.parametrize(("name", "accepted"), [("br-tun-2026-11-06-101010-4242.flows", True),
                                                ("br-tun-2026-11-06-101010.flows", False)])
def test_restore_file_names(name, accepted):
    rejected = "--restore needs a br-tun" in run_cli("--restore", name, "--vni", "1").stderr
    assert rejected != accepted
