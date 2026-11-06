"""Print the findings and save them for --summary-state and Prometheus."""
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict

from kolla_ovs_doctor import util
from kolla_ovs_doctor.findings import SEVERITY, SEVERITY_ORDER, finding_order, severity_of

# Table columns are in reading order, not sorted.
FINDING_COLUMNS = ("Host", "Severity", "Kind", "VNI", "Detail")
SUMMARY_COLUMNS = ("Severity", "Kind", "Count", "Change", "Top hosts")


def print_summary(findings, previous):
    """Print one row per kind: most severe first, then by count, with the change."""
    counts = Counter(item["kind"] for item in findings)
    kinds = set(counts) | set(previous)
    order = sorted(kinds, key=lambda kind: (
        SEVERITY_ORDER.index(SEVERITY.get(kind, "warning")), -counts[kind], kind))
    by_kind = defaultdict(Counter)
    for item in findings:
        by_kind[item["kind"]][item["host"]] += 1
    rows = []
    for kind in order:
        busiest = sorted(by_kind[kind].items(), key=lambda pair: (-pair[1], pair[0]))[:4]
        top = " ".join(f"{host}:{count}" for host, count in busiest)
        change = counts[kind] - previous[kind] if kind in previous else None
        delta = "" if change is None else f"{change:+d}"
        rows.append([SEVERITY.get(kind, "warning"), kind, counts[kind], delta, top])
    text = util.table(SUMMARY_COLUMNS, rows, right=("Change", "Count"))
    if text:
        print(text)


def read_summary_state(path):
    """Return the counts of the previous run, or {} if there are none."""
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def write_summary_state(path, findings):
    """Save the counts of this run for the next --summary."""
    counts = dict(Counter(item["kind"] for item in findings))
    directory = os.path.dirname(os.path.abspath(path))
    with tempfile.NamedTemporaryFile("w", delete=False, dir=directory) as handle:
        json.dump(counts, handle, indent=2, sort_keys=True)
    os.replace(handle.name, path)


def prometheus_label(value):
    """Escape a Prometheus label value."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def write_prometheus_file(path, findings, hosts, collected):
    """Write finding counts and per-host collection status for Prometheus."""
    counts = defaultdict(int)
    for item in findings:
        counts[(item["host"], item["vni"], item["kind"], severity_of(item))] += 1
    lines = [
        "# HELP ovs_doctor_findings Neutron/OVS inconsistencies by type.",
        "# TYPE ovs_doctor_findings gauge",
    ]
    for (host, vni, kind, severity), value in sorted(counts.items()):
        labels = ",".join(f'{name}="{prometheus_label(label)}"' for name, label in
                          (("host", host), ("kind", kind), ("severity", severity), ("vni", vni)))
        lines.append(f"ovs_doctor_findings{{{labels}}} {value}")
    lines += [
        "# HELP ovs_doctor_host_up 1 if the host's flows were collected.",
        "# TYPE ovs_doctor_host_up gauge",
    ]
    for host in sorted(hosts):
        up = 1 if host in collected else 0
        lines.append(f'ovs_doctor_host_up{{host="{prometheus_label(host)}"}} {up}')
    directory = os.path.dirname(os.path.abspath(path))
    with tempfile.NamedTemporaryFile("w", delete=False, dir=directory) as handle:
        handle.write("\n".join(lines) + "\n")
    os.chmod(handle.name, 0o644)
    os.replace(handle.name, path)


def print_report(state):
    """Print and save the results. Return the exit code."""
    args = state.args
    all_findings = sorted(state.findings, key=finding_order)
    errors = dict(sorted(state.errors.items()))
    allowed = SEVERITY_ORDER[:SEVERITY_ORDER.index(args.severity) + 1] if args.severity else (
        SEVERITY_ORDER)
    findings = [item for item in all_findings if severity_of(item) in allowed]
    if args.prometheus_file:
        write_prometheus_file(args.prometheus_file, findings, sorted(state.hosts + state.dead),
                              state.collected)
    previous = read_summary_state(args.summary_state) if args.summary_state else {}
    # Compare only the kinds that --severity shows.
    previous = {kind: count for kind, count in previous.items()
                if SEVERITY.get(kind, "warning") in allowed}
    if args.json:
        for item in findings:
            item["severity"] = severity_of(item)
        print(json.dumps({"errors": errors, "findings": findings}, indent=2,
                         sort_keys=True))
    else:
        if args.summary:
            print_summary(findings, previous)
        else:
            rows = [[item["host"], severity_of(item), item["kind"], item["vni"] or "",
                     item["detail"]] for item in findings]
            text = util.table(FINDING_COLUMNS, rows, right=("VNI",))
            if text:
                print(text)
        for host, message in errors.items():
            print(f"{host:<8} ERROR {message}", file=sys.stderr)
        kinds = Counter(item["kind"] for item in findings)
        summary = " ".join(f"{kind}={count}" for kind, count in sorted(kinds.items()))
        print(f"errors={len(errors)} findings={len(findings)} hosts={len(state.hosts)} "
              f"networks={len(state.expected)} {summary}".rstrip())
    if args.summary_state:
        # Save every finding, so the next run compares the same thing with or without
        # --severity.
        write_summary_state(args.summary_state, all_findings)
    if errors:
        return 2
    return 1 if findings else 0
