"""Tests for kolla_ovs_doctor.fdb_watch."""
from helpers import ARP_FLOW

from kolla_ovs_doctor import fdb_watch


def test_fdb_expected_entries():
    arp = {"table21": ARP_FLOW}
    assert fdb_watch.expected_fdb_entries(arp, "compute:nova") == {"arp", "flood", "unicast"}
    assert fdb_watch.expected_fdb_entries({}, "compute:nova") == {"flood", "unicast"}
    assert fdb_watch.expected_fdb_entries(arp, "network:router_gateway") == {"flood", "unicast"}
    assert fdb_watch.expected_fdb_entries(arp, "compute:nova", False) == {"flood", "unicast"}
