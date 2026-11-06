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


def test_tunnel_missing_once_per_peer():
    networks = [{"id": f"n{n}", "vni": 10 + n} for n in range(3)]
    ports = [{"address_pairs": [], "host": host, "ips": [], "mac": f"fa:16:3e:00:0{n}:{m}",
              "network_id": f"n{n}", "owner": "compute:x", "status": "ACTIVE"}
             for n in range(3) for m, host in enumerate(("c1", "c2"))]
    ips = {"c1": "192.0.2.1", "c2": "192.0.2.2"}
    found = flows.audit_host("c1", {}, neutron.build_expected(networks, ports, ips), ips)
    tunnels = [item for item in found if item["kind"] == "tunnel_missing"]
    assert len(tunnels) == 1 and "3 VNIs" in tunnels[0]["detail"]
    assert kinds(found).count("flood_missing") == 3
