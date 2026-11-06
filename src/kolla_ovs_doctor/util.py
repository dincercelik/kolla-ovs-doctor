"""Small helpers used by many modules."""
import sys
from concurrent.futures import ThreadPoolExecutor

import prettytable


def parse_hosts(value):
    """Return the --hosts list sorted, without duplicates and empty entries."""
    return sorted({host.strip() for host in value.split(",") if host.strip()})


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


def table(fields, rows, right=()):
    """Return rows as a table like the OpenStack CLI draws, or "" if there are no rows.

    Columns in right are aligned to the right, for numbers. Other columns are aligned
    to the left.
    """
    grid = prettytable.PrettyTable(field_names=fields, print_empty=False)
    for field in fields:
        grid.align[field] = "r" if field in right else "l"
    for row in rows:
        grid.add_row(row)
    return grid.get_string()


def fail(message):
    """Print an error and stop with exit code 2 (collection, fix or preflight error)."""
    print(f"ERROR {message}", file=sys.stderr)
    sys.exit(2)
