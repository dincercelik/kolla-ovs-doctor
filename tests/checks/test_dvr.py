"""Tests for kolla_ovs_doctor.checks.dvr."""
from helpers import kinds

from kolla_ovs_doctor.checks import dvr


def dvr_host(own, accepted):
    """Return sections for a host with DVR MAC own that accepts the MACs in accepted."""
    return {"table1": f"table=1, actions=mod_dl_src:{own}",
            "table9": "\n".join(f"table=9, priority=1,dl_src={mac} actions=output:1"
                                for mac in accepted)}


def test_dvr_macs_known_everywhere():
    collected = {"c1": dvr_host("fa:16:3f:00:00:01", ["fa:16:3f:00:00:02"]),
                 "c2": dvr_host("fa:16:3f:00:00:02", ["fa:16:3f:00:00:01"])}
    assert dvr.audit_dvr(collected) == []


def test_dvr_mac_conflict_and_missing_mac():
    collected = {"c1": dvr_host("fa:16:3f:00:00:01", []),
                 "c2": dvr_host("fa:16:3f:00:00:01", []),
                 "c3": dvr_host("fa:16:3f:00:00:03", ["fa:16:3f:00:00:01"])}
    found = dvr.audit_dvr(collected)
    assert kinds(found) == ["dvr_mac_conflict", "dvr_mac_conflict", "dvr_mac_missing",
                            "dvr_mac_missing"]
    assert sorted(item["host"] for item in found if item["kind"] == "dvr_mac_missing") == [
        "c1", "c2"]
