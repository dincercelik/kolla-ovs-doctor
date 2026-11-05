"""Compare seeded random runs with the saved outputs in tests/golden.

Run `pytest --update-golden` after an output change on purpose, and check the diff.
"""
import json
import os

import pytest
import scenarios

GOLDEN = os.path.join(os.path.dirname(__file__), "golden")


def check_golden(name, results, update):
    """Compare results with golden/<name>.json, or rewrite the file if update is set."""
    path = os.path.join(GOLDEN, f"{name}.json")
    results = json.loads(json.dumps(results))  # Tuples become lists, as in the file.
    if update:
        with open(path, "w") as handle:
            json.dump(results, handle, indent=1, sort_keys=True)
            handle.write("\n")
        pytest.skip(f"rewrote {path}")
    with open(path) as handle:
        golden = json.load(handle)
    changed = sorted(seed for seed in golden if golden[seed] != results.get(seed))
    assert not changed, f"{len(changed)} of {len(golden)} seeds changed, first: {changed[:5]}"
    assert sorted(results) == sorted(golden)


def test_routers(update_golden):
    results = {str(seed): scenarios.run_routers(seed) for seed in range(500)}
    check_golden("routers", results, update_golden)


def test_fdb_watch(monkeypatch, update_golden):
    results = {}
    for seed in range(300):
        with monkeypatch.context() as patch:
            results[str(seed)] = scenarios.run_fdb_watch(patch, seed)
    check_golden("fdb_watch", results, update_golden)


def test_main(monkeypatch, tmp_path, update_golden):
    results = {}
    for seed in range(300):
        with monkeypatch.context() as patch:
            results[str(seed)] = scenarios.run_main(patch, seed, str(tmp_path))
    check_golden("main", results, update_golden)
