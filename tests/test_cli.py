"""Tests for kolla_ovs_doctor.cli: preflight, dead agents and API errors in a whole run."""
import json

import pytest
from helpers import BAD_PREFLIGHT, GOOD_PREFLIGHT

from kolla_ovs_doctor import neutron, remote, scripts


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


def test_failing_routers_api_is_one_error(monkeypatch, run_main):
    def broken(workers):
        raise RuntimeError("404 Not Found")

    monkeypatch.setattr(remote, "run_ssh", lambda *args: GOOD_PREFLIGHT)
    monkeypatch.setattr(neutron, "collect_neutron", lambda: (
        [], [], {"a": "192.0.2.1"}, {"192.0.2.1": "a", "192.0.2.9": "dead1"}))
    monkeypatch.setattr(remote, "collect_host", lambda host, *a, **k: {})
    monkeypatch.setattr(neutron, "collect_routers", broken)
    code, out, err = run_main([])
    assert code == 2
    assert "neutron  ERROR cannot read the routers (404 Not Found)" in err
    assert "agent_down" in out  # The other findings are still reported.
