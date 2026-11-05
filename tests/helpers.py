"""Plain helpers shared by the tests."""
import subprocess
import sys


def kinds(findings):
    """Return the sorted kinds of findings."""
    return sorted(item["kind"] for item in findings)


def run_cli(*argv):
    """Run ovs-doctor in a new process. Return the CompletedProcess."""
    return subprocess.run([sys.executable, "-m", "kolla_ovs_doctor", *argv],
                          capture_output=True, check=False, text=True)
