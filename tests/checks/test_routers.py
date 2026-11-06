"""Tests for kolla_ovs_doctor.checks.routers."""
from helpers import kinds

from kolla_ovs_doctor.checks import routers


def dvr_router(**changes):
    router = {"agents": [{"alive": True, "configurations": {"agent_mode": "dvr_snat"},
                          "host": "net1"},
                         {"alive": True, "configurations": {"agent_mode": "dvr"}, "host": "c1"}],
              "agents_known": True, "distributed": True, "gateway_ips": ["203.0.113.5"],
              "ha": False, "id": "r1", "name": "r1", "snat_enabled": True}
    router.update(changes)
    return router


def test_dvr_missing_snat_namespace():
    found = routers.audit_routers([dvr_router()], [], {"c1": {}, "net1": {}})
    assert any(item["kind"] == "snat_ns_missing" and item["host"] == "net1" for item in found)


def test_dvr_without_dvr_snat_agent_is_unscheduled():
    router = dvr_router(agents=[dvr_router()["agents"][1]])
    found = routers.audit_routers([router], [], {"c1": {}, "net1": {}})
    assert "router_unscheduled" in kinds(found)


def test_dvr_with_all_snat_agents_down():
    router = dvr_router(agents=[dict(dvr_router()["agents"][0], alive=False)])
    found = routers.audit_routers([router], [], {"c1": {}, "net1": {}})
    assert "router_agents_down" in kinds(found)


def test_dvr_unknown_agents_give_no_scheduling_finding():
    router = dvr_router(agents=[], agents_known=False)
    assert kinds(routers.audit_routers([router], [], {"c1": {}, "net1": {}})) == []


def test_centralized_failed_agent_call_is_not_unscheduled():
    router = dvr_router(agents=[], agents_known=False, distributed=False)
    assert "router_unscheduled" not in kinds(routers.audit_routers([router], [], {}))


def test_parse_netns_merges_the_two_passes():
    text = ("@ns snat-r1\n@addr\n1: qg inet 203.0.113.5/24\n"
            "@ns snat-r1\n@nat\n-A x -j SNAT --to-source 203.0.113.5")
    parsed = routers.parse_netns(text)
    assert parsed["snat-r1"]["addr"] and parsed["snat-r1"]["nat"]
