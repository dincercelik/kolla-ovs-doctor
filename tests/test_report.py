"""Tests for kolla_ovs_doctor.report."""
from kolla_ovs_doctor import report


def test_prometheus_labels_are_escaped(tmp_path):
    path = tmp_path / "out.prom"
    finding = {"detail": "", "host": 'a"b\\c', "kind": "arp_stale", "vni": 0}
    report.write_prometheus_file(str(path), [finding], ['a"b\\c'], {'a"b\\c'})
    assert 'host="a\\"b\\\\c"' in path.read_text()


def test_host_up_follows_collection(tmp_path):
    path = tmp_path / "y.prom"
    report.write_prometheus_file(str(path), [], ["h1", "h2"], {"h1"})
    body = path.read_text()
    assert 'ovs_doctor_host_up{host="h1"} 1' in body
    assert 'ovs_doctor_host_up{host="h2"} 0' in body
