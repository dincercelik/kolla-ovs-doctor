"""The drift check: config and version differences between OVS agents."""
from collections import Counter

from kolla_ovs_doctor.findings import make_finding

# oslo.config reads booleans in any case and in these words. 1 and 0 are left out,
# because they are often plain numbers.
CONFIG_BOOLEANS = {"false": "false", "no": "false", "off": "false", "on": "true", "true": "true",
                   "yes": "true"}
VERSION_KEYS = (
    "agent_container_os", "host_kernel", "host_os", "image", "neutron", "oslo.messaging",
    "ovs_container_os", "ovs_image", "ovs_version", "ovsdb_image",
)


def parse_drift(text):
    """Return {key: value} from the drift section."""
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.strip().split("=", 1)
            values[key] = value
    return values


def config_value(key, value):
    """Return a config value in one spelling, so True and true do not count as drift."""
    if key in VERSION_KEYS:
        return value
    return CONFIG_BOOLEANS.get(value.strip().lower(), value.strip())


def audit_drift(collected):
    """Compare each host's versions and config with the most common value."""
    values = {host: {key: config_value(key, value)
                     for key, value in parse_drift(sections.get("drift", "")).items()}
              for host, sections in collected.items()}
    values = {host: data for host, data in values.items() if data}
    findings = []
    for key in sorted({key for data in values.values() for key in data}):
        counts = Counter(data.get(key, "<unset>") for data in values.values())
        common = counts.most_common(1)[0][0]
        kind = "version_drift" if key in VERSION_KEYS else "config_drift"
        for host, data in sorted(values.items()):
            value = data.get(key, "<unset>")
            if value != common:
                findings.append(make_finding(host, kind, f"{key}={value} (most hosts: {common})"))
    return findings
