"""Small helpers used by many modules."""
import sys
from concurrent.futures import ThreadPoolExecutor


def run_parallel(hosts, func, workers):
    """Run func(host) on each host in parallel.

    Return {host: (result, exception or None)} in the order of hosts.
    """
    def call(host):
        try:
            return host, func(host), None
        except Exception as exc:  # One host must not stop the others.
            return host, None, exc

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return {host: (result, error) for host, result, error in pool.map(call, list(hosts))}


def fail(message):
    """Print an error and stop with exit code 2 (collection, fix or preflight error)."""
    print(f"ERROR {message}", file=sys.stderr)
    sys.exit(2)
