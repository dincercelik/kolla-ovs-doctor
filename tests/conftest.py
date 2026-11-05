"""Shared pytest fixtures for ovs-doctor."""
import sys

import pytest

from kolla_ovs_doctor import cli


def pytest_addoption(parser):
    parser.addoption("--update-golden", action="store_true",
                     help="rewrite tests/golden from the current code")


@pytest.fixture
def update_golden(request):
    """Return True if the golden files should be rewritten."""
    return request.config.getoption("--update-golden")


@pytest.fixture
def ssh_scripts(monkeypatch):
    """Replace run_ssh. Return {host: script} for every call."""
    scripts = {}

    def fake(host, user, timeout, script):
        scripts[host] = script
        return "/x\n"

    monkeypatch.setattr(cli, "run_ssh", fake)
    return scripts


@pytest.fixture
def run_main(monkeypatch, capsys):
    """Return a function that runs main() with argv. It returns (code, stdout, stderr)."""
    def run(argv):
        monkeypatch.setattr(sys, "argv", ["ovs-doctor", *argv])
        try:
            code = cli.main()
        except SystemExit as exc:
            code = exc.code
        out, err = capsys.readouterr()
        return code, out, err

    return run
