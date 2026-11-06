"""Tests for kolla_ovs_doctor.util."""
import pytest

from kolla_ovs_doctor import util


def test_fail_exits_2():
    with pytest.raises(SystemExit) as exc:
        util.fail("x")
    assert exc.value.code == 2


def test_run_parallel_keeps_host_order_and_errors():
    def work(host):
        if host == "b":
            raise RuntimeError("boom")
        return host.upper()

    results = util.run_parallel(["c", "a", "b"], work, 3)
    assert list(results) == ["c", "a", "b"]
    assert results["a"] == ("A", None) and results["c"] == ("C", None)
    assert results["b"][0] is None and str(results["b"][1]) == "boom"
