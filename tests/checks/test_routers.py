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


def test_dvr_unknown_agents_give_no_scheduling_finding():
    router = dvr_router(agents=[], agents_known=False)
    assert kinds(routers.audit_routers([router], [], {"c1": {}, "net1": {}})) == []


def test_centralized_failed_agent_call_is_not_unscheduled():
    router = dvr_router(agents=[], agents_known=False, distributed=False)
    assert "router_unscheduled" not in kinds(routers.audit_routers([router], [], {}))
