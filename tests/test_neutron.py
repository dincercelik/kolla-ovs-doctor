"""Tests for kolla_ovs_doctor.neutron."""

from helpers import multi_segment

from kolla_ovs_doctor import neutron


def test_multi_segment_macs_are_known_in_every_segment():
    known = neutron.build_known(*multi_segment())
    assert "fa:16:3e:00:00:01" in known[100]["macs"]
    assert "fa:16:3e:00:00:01" in known[200]["macs"]


def test_multi_segment_ports_are_not_expected():
    networks, ports = multi_segment()
    expected = neutron.build_expected(networks, ports, {"c1": "192.0.2.1", "c2": "192.0.2.2"})
    assert 100 not in expected and 200 not in expected and 300 in expected


def test_multi_segment_ports_are_bound_in_every_segment():
    bound = neutron.build_bound(*multi_segment())
    assert "c1" in bound[100] and "c1" in bound[200]
