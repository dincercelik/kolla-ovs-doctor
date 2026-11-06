"""Tests for kolla_ovs_doctor.findings."""
import importlib
import pkgutil

import kolla_ovs_doctor
from kolla_ovs_doctor import findings


def test_kind_names():
    for info in pkgutil.walk_packages(kolla_ovs_doctor.__path__, "kolla_ovs_doctor."):
        if info.name != "kolla_ovs_doctor.__main__":
            assert not hasattr(importlib.import_module(info.name), "OLD_KIND_NAMES")
    assert not any(kind.startswith(("missing_", "stale_", "wrong_")) for kind in findings.SEVERITY)


def test_finding_order_is_host_then_most_severe_first():
    items = [findings.make_finding("b", "version_drift", "x"),
             findings.make_finding("a", "unicast_missing", "x", vni=7),
             findings.make_finding("a", "tunnel_missing", "x"),
             findings.make_finding("a", "flood_stale", "x")]
    ordered = sorted(items, key=findings.finding_order)
    assert [(item["host"], item["kind"]) for item in ordered] == [
        ("a", "tunnel_missing"), ("a", "unicast_missing"), ("a", "flood_stale"),
        ("b", "version_drift")]
