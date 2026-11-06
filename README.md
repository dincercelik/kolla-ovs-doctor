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
OVS host, and that sudo works without a password.

See `ovs-doctor --help` for all options.

## SSH

ovs-doctor connects with Paramiko, one connection per host for the whole run.

- From `~/.ssh/config` it reads `HostName`, `User`, `Port` and `IdentityFile`.
  `--ssh-user` wins over `User`.
- It logs in with your ssh-agent or your key files.
- A host key must already be in `~/.ssh/known_hosts` or
  `/etc/ssh/ssh_known_hosts`. An unknown host is refused, not added.
- Jump hosts (`ProxyJump`, `ProxyCommand`) are not supported.

## Exit codes

- `0`: no problems found
- `1`: problems found
- `2`: collection, fix or preflight errors

## Repairs

`--fix`, `--cleanup` and `--restore` change flows on the hosts. Run them with
`--dry-run` first. Each change makes a backup of the br-tun flows in
`/var/backups/kolla-ovs-doctor` on the host first. The OVS agent can overwrite
these repairs, so they are a temporary fix.

## Tests

```
pip install -e '.[test]'
pytest
```

## License

Apache-2.0. See `LICENSE`.
