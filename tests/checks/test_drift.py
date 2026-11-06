"""Tests for kolla_ovs_doctor.checks.drift."""
from kolla_ovs_doctor.checks import drift


def drift_hosts(**values):
    return {host: {"drift": f"host_kernel=6.8\n{line}"} for host, line in values.items()}


def test_boolean_spelling_is_not_config_drift():
    collected = drift_hosts(hv01="enable_distributed_routing=true",
                            hv02="enable_distributed_routing=true",
                            hv07="enable_distributed_routing=True",
                            hv08="enable_distributed_routing=yes",
                            hv09="enable_distributed_routing=ON ")
    assert drift.audit_drift(collected) == []


def test_real_config_drift_is_still_found():
    collected = drift_hosts(hv01="l2_population=True", hv02="l2_population=true",
                            hv07="l2_population=False")
    found = drift.audit_drift(collected)
    assert [(item["host"], item["kind"], item["detail"]) for item in found] == [
        ("hv07", "config_drift", "l2_population=false (most hosts: true)")]


def test_numbers_and_versions_are_compared_as_written():
    collected = {host: {"drift": text} for host, text in (
        ("hv01", "heartbeat_timeout_threshold=0\nimage=kolla/neutron:2025.1"),
        ("hv02", "heartbeat_timeout_threshold=0\nimage=kolla/neutron:2025.1"),
        ("hv07", "heartbeat_timeout_threshold=false\nimage=Kolla/neutron:2025.1"))}
    assert sorted((item["kind"], item["detail"]) for item in drift.audit_drift(collected)) == [
        ("config_drift", "heartbeat_timeout_threshold=false (most hosts: 0)"),
        ("version_drift", "image=Kolla/neutron:2025.1 (most hosts: kolla/neutron:2025.1)")]
