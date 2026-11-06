# kolla-ovs-doctor

[![tests](https://github.com/dincercelik/kolla-ovs-doctor/actions/workflows/tests.yml/badge.svg)](https://github.com/dincercelik/kolla-ovs-doctor/actions/workflows/tests.yml)

`ovs-doctor` checks that Neutron and Open vSwitch agree on a Kolla-Ansible
cloud. It finds missing and stale flows on br-tun, router and SNAT problems,
DVR MAC problems and config drift between agents. It can also repair some of
them.

It works only on Kolla-Ansible clouds that use ML2/OVS and Docker. It does not
support OVN.

## Install

Install it into the same venv as Kolla-Ansible:

```
source /path/to/kolla-ansible-venv/bin/activate
pip install git+https://github.com/dincercelik/kolla-ovs-doctor.git
ovs-doctor --version
```

To install from a local copy instead, use `pip install /path/to/kolla-ovs-doctor`.

pip only adds what is missing (openstacksdk and its libraries). It does not change
the packages that Kolla-Ansible already uses.

If you built your Kolla-Ansible venv with an OpenStack upper-constraints file,
use the same file here, so both stay on the same versions:

```
pip install -c https://releases.openstack.org/constraints/upper/2026.2 \
    git+https://github.com/dincercelik/kolla-ovs-doctor.git
```

## Use

Run it on the deploy host. It needs SSH key access to every hypervisor, and the
SSH user must be able to use sudo without a password there. Load admin
credentials first:

```
source /etc/kolla/admin-openrc.sh
ovs-doctor                 # check everything
ovs-doctor --summary       # one line per kind of problem
ovs-doctor --vni 0x285     # check one network
ovs-doctor --fix --dry-run # show what --fix would change
```

Before it runs anything on a host, it checks that the host is a Kolla-Ansible
OVS host, and that sudo works without a password. A host that fails is reported
as an error and skipped. Each script runs on a host under one `sudo -n bash -s`.

Results come as tables, like the OpenStack CLI draws them:

```
+------+----------+----------------+-----+----------------------------------+
| Host | Severity | Kind           | VNI | Detail                           |
+------+----------+----------------+-----+----------------------------------+
| c1   | critical | flood_missing  | 100 | c2 (192.0.2.2)                   |
| c1   | critical | tunnel_missing |     | c2 (192.0.2.2), needed by 3 VNIs |
+------+----------+----------------+-----+----------------------------------+
errors=0 findings=2 hosts=2 networks=1 flood_missing=1 tunnel_missing=1
```

Use `--json` for output that other tools read.

See `ovs-doctor --help` for all options.

## Checks

By default all VXLAN networks are checked. Use `--vni` to check one. Tables 4,
20, 21 and 22 are checked for missing flows, and for flows that Neutron does not
know. A full run also does these checks (see `--checks`):

- `drift`: config and version differences between agents
- `dvr`: DVR MACs in tables 1 and 9
- `routers`: L3 HA state, and qrouter and SNAT namespaces

A host whose OVS agent is down is reported as `agent_down`. It is not checked.

A network can have more than one VXLAN segment. Its ports count as known in
every segment, so their flows are never deleted. They are not checked for
missing flows, because Neutron does not say which segment a port uses.

`--fdb-watch MAC --vni N` follows one port. It shows how long each host takes
to add the l2pop flows for it. This shows if agents are slow or stuck.

## SSH

ovs-doctor connects with Paramiko, one connection per host for the whole run.

- From `~/.ssh/config` it reads `HostName`, `User`, `Port` and `IdentityFile`.
  `--ssh-user` wins over `User`. With neither, it uses your local user name, as
  ssh does.
- It logs in with your ssh-agent or your key files.
- A host that is not in `~/.ssh/known_hosts` or `/etc/ssh/ssh_known_hosts` is
  accepted for the run, but not saved there. A host whose key changed is refused.
- Jump hosts (`ProxyJump`, `ProxyCommand`) are not supported.

## Exit codes

- `0`: no problems found
- `1`: problems found
- `2`: collection, fix or preflight errors

## Repairs

`--cleanup`, `--fix` and `--restore` change flows on the hosts. Run them with
`--dry-run` first. Each change makes a backup of the br-tun flows in
`--backup-dir` on the host first (default `/var/backups/kolla-ovs-doctor`). The
OVS agent can overwrite these repairs, so they are a temporary fix. If a host
fails the preflight check, they stop before they change anything.

- `--cleanup` removes `flood_stale` tunnels from flood flows, and deletes the
  flows of `vni_orphan` entries. A tunnel is kept if its host has a port on the
  network, in any state (DOWN too). An orphan VNI is kept if an OVS port still
  uses its local VLAN, or if another VNI uses the same VLAN (`vlan_conflict`).
- `--fix` adds missing tunnels to flood flows. It deletes ARP responder and
  unicast flows that Neutron does not know. Other findings are not changed.
- `--restore` puts back the flood flow of one VNI on each host, from a backup.
  Only that flow changes, not the whole bridge. By default it uses the newest
  backup. A restore makes its own backup first, so running it again undoes it.
  It does not bring back flows that `--fix` deleted. They stay in the backup.

## Tests

```
pip install -e '.[test]'
pytest
```

## License

Apache-2.0. See `LICENSE`.
