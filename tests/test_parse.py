"""Tests for kolla_ovs_doctor.parse."""
from helpers import BR_TUN_DUMP, shared_vlan

from kolla_ovs_doctor import parse


def test_present_vnis_include_shared_vlans():
    assert parse.present_vnis(shared_vlan()) == {0x12c, 0x3e7}


def test_split_flow_tables():
    tables = parse.split_flow_tables(BR_TUN_DUMP)
    assert set(tables) == {"table20", "table22", "table4"}
    assert "dl_dst" in tables["table20"]


def test_parsers_are_cached_and_small():
    table20 = parse.split_flow_tables(BR_TUN_DUMP)["table20"]
    assert parse.parse_unicast_flows(table20) is parse.parse_unicast_flows(table20)
    assert parse.parse_unicast_flows.cache_info().maxsize == 16
    assert parse.unicast_by_vni(table20) == {0x64: {"fa:16:3e:00:00:09": ((False, (2,)),)}}


def test_has_arp_flows_reads_the_count():
    assert parse.has_arp_flows({"arp_count": "NXST_AGGREGATE reply: flow_count=4"})
    assert not parse.has_arp_flows({"arp_count": "NXST_AGGREGATE reply: flow_count=0"})
