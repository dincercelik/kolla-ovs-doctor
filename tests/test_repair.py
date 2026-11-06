"""Tests for kolla_ovs_doctor.repair."""
import types

from helpers import empty_context, multi_segment, shared_vlan

from kolla_ovs_doctor import neutron, remote, repair


def test_multi_segment_flows_are_not_deleted():
    known = neutron.build_known(*multi_segment())
    sections = {
        "table20": "table=20, priority=2,dl_vlan=7,dl_dst=fa:16:3e:00:00:01 "
                   "actions=strip_vlan,load:0xc8->NXM_NX_TUN_ID[],output:2",
        "table21": "table=21, priority=1,arp,dl_vlan=7,arp_tpa=10.0.0.5 "
                   "actions=mod_dl_src:fa:16:3e:00:00:01,IN_PORT",
        "table22": "", "table4": "table=4, priority=1,tun_id=0xc8 actions=mod_vlan_vid:7",
    }
    assert repair.plan_stale_deletions(sections, known, None) == []


def test_orphan_on_shared_vlan_is_kept():
    known = neutron.build_known(*multi_segment())
    plans, kept = repair.plan_orphan_cleanup(shared_vlan(), empty_context(known))
    assert plans == [] and "shared" in kept[0][2]


def test_orphan_on_unused_vlan_is_deleted():
    table4 = "table=4, priority=1,tun_id=0x3e7 actions=mod_vlan_vid:9,resubmit(,10)"
    sections = dict(shared_vlan(), table4=table4)
    known = neutron.build_known(*multi_segment())
    plans, _ = repair.plan_orphan_cleanup(sections, empty_context(known))
    assert len(plans) == 1 and plans[0][1] == 9


def test_reread_after_change(monkeypatch):
    def down(*args, **kwargs):
        raise RuntimeError("ssh down")

    monkeypatch.setattr(remote, "collect_host", down)
    args = types.SimpleNamespace(ssh_user=None, timeout=1)
    after, error = repair.reread_after_change("h", args, True)
    assert after is None and str(error) == "ssh down"
    assert repair.reread_after_change("h", args, False) == (None, None)
    assert "fix applied" in repair.changed_but_unread("fix", error)
