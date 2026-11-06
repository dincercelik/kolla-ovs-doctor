"""Tests for kolla_ovs_doctor.checks.flows."""
from helpers import empty_context, kinds, multi_segment, shared_vlan

from kolla_ovs_doctor import neutron
from kolla_ovs_doctor.checks import flows


def test_shared_vlan_is_reported_and_arp_is_not_stale():
    known = neutron.build_known(*multi_segment())
    found = flows.audit_host("c1", shared_vlan(), {}, {}, empty_context(known))
    assert "vlan_conflict" in kinds(found)
    assert any(item["kind"] == "vni_orphan" and item["vni"] == 0x3e7 for item in found)
    assert "arp_stale" not in kinds(found)
