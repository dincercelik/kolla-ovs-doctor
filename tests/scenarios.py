"""Random but seeded clouds for the golden tests.

Each run_* function patches cli with fakes, runs one part of the tool and returns
everything it printed or returned, as plain JSON data.
"""
import contextlib
import io
import json
import os
import random
import sys
import types

from kolla_ovs_doctor import cli

HOSTS = ["c1", "c2", "c3", "net1"]
IPS = {host: f"192.0.2.{n + 1}" for n, host in enumerate(HOSTS)}
MAC = "fa:16:3e:00:00:09"
MAIN_EXTRAS = [[], ["--json"], ["--summary"], ["--severity", "warning"], ["--vni", "101"],
               ["--hosts", "c1,c2"], ["--checks", "flows,dvr"], ["--checks", "routers,drift"]]
MAIN_OPTIONS = [[], ["--fix"], ["--fix", "--dry-run"], ["--cleanup"], ["--cleanup", "--dry-run"],
                ["--restore", "--vni", "100"], ["--restore", "--dry-run", "--vni", "100"]]


def call(func, host):
    """Run func(host) like cli.run_parallel does, but in this thread."""
    try:
        return func(host), None
    except Exception as exc:  # The tool records the error per host.
        return None, exc


def fake_preflight(bad):
    """Return a preflight that fails the hosts in bad."""
    return lambda hosts, args: {host: "no sudo" for host in sorted(hosts) if host in bad}


def sequential(hosts, func, workers):
    return {host: call(func, host) for host in list(hosts)}


def capture(run):
    """Run a function. Return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = run()
        except SystemExit as exc:
            code = f"exit {exc.code}"
    return code, out.getvalue(), err.getvalue()


# --- routers ---

def router_case(seed):
    """Return (routers, ports, netns) for one random router setup."""
    rng = random.Random(seed)
    routers, ports = [], []
    netns = {host: {} for host in HOSTS if rng.random() < 0.9}
    for number in range(rng.randint(1, 4)):
        router_id = f"r{number}"
        agents = []
        for host in rng.sample(HOSTS, rng.randint(0, 3)):
            agent = {"alive": rng.random() < 0.8, "host": host,
                     "ha_state": rng.choice([None, "active", "standby"])}
            if rng.random() < 0.8:
                agent["configurations"] = {"agent_mode": rng.choice(["dvr", "dvr_snat", "legacy"])}
            agents.append(agent)
        gateway = [f"203.0.113.{number + 1}"] if rng.random() < 0.8 else []
        routers.append({"agents": agents, "agents_known": rng.random() < 0.9,
                        "distributed": rng.random() < 0.5, "gateway_ips": gateway,
                        "ha": rng.random() < 0.5, "id": router_id,
                        "name": router_id if rng.random() < 0.5 else "",
                        "snat_enabled": rng.random() < 0.8})
        network = f"n{number}"
        ports.append({"device": router_id, "ips": [f"10.{number}.0.1"], "mac": "fa:16:3e:00:00:01",
                      "network_id": network,
                      "owner": rng.choice(["network:ha_router_replicated_interface",
                                           "network:router_interface",
                                           "network:router_interface_distributed"])})
        if rng.random() < 0.7:
            ports.append({"device": router_id, "ips": [f"10.{number}.0.5"],
                          "mac": "fa:16:3e:00:00:05", "network_id": network,
                          "owner": "network:router_centralized_snat"})
        for host in rng.sample(HOSTS, rng.randint(0, 2)):
            ports.append({"host": host, "ips": [], "mac": "x", "network_id": network,
                          "owner": "compute:nova"})
        for host in list(netns):
            for prefix in ("qrouter-", "snat-"):
                if rng.random() < 0.6:
                    netns[host][prefix + router_id] = namespace(rng, number, gateway)
    return routers, ports, netns


def namespace(rng, number, gateway):
    """Return one random qrouter or snat namespace for router number."""
    # Keep the order of the rng calls: the golden files depend on it.
    addresses = gateway + [f"10.{number}.0.1", f"10.{number}.0.5"]
    routes = ["default via 203.0.113.254 dev qg", f"default via 10.{number}.0.5 dev qr table 7"]
    addr = [f"2: qg inet {ip}/24" for ip in addresses if rng.random() < 0.7]
    nat = [f"-A x -j SNAT --to-source {ip}" for ip in gateway if rng.random() < 0.7]
    neigh = ([f"10.{number}.0.5 dev qr lladdr fa:16:3e:00:00:0{rng.choice([5, 6])} PERMANENT"]
             if rng.random() < 0.7 else [])
    route = [rng.choice(routes)] if rng.random() < 0.8 else []
    return {"addr": addr, "nat": nat, "neigh": neigh, "route": route}


def run_routers(seed):
    """Return the sorted findings of audit_routers for one random setup."""
    findings = cli.audit_routers(*router_case(seed))
    return sorted(sorted(item.items()) for item in findings)


# --- fdb-watch ---

def fdb_sections(entries, owner, arp_on):
    port = HOSTS.index(owner) + 2
    tunnels = "\n".join(f'ofport : {n + 2}\noptions : {{remote_ip="{IPS[host]}"}}'
                        for n, host in enumerate(HOSTS))
    flood = (f"table=22, priority=1,dl_vlan=3 actions=strip_vlan,"
             f"load:0x64->NXM_NX_TUN_ID[],output:{port if 'flood' in entries else 99}")
    unicast = (f"table=20, priority=2,dl_vlan=3,dl_dst={MAC} "
               f"actions=strip_vlan,load:0x64->NXM_NX_TUN_ID[],output:{port}")
    arp = f"table=21, priority=1,arp,dl_vlan=3,arp_tpa=10.0.0.5 actions=mod_dl_src:{MAC},IN_PORT"
    return {
        "arp_count": f"NXST_AGGREGATE reply: flow_count={1 if arp_on else 0}",
        "table20": unicast if "unicast" in entries else "",
        "table21": arp if "arp" in entries else "",
        "table22": flood,
        "table4": "table=4, priority=1,tun_id=0x64 actions=mod_vlan_vid:3,resubmit(,10)",
        "tunnels": tunnels,
    }


def run_fdb_watch(monkeypatch, seed):
    """Run run_fdb_watch with a fake clock and fake hosts. Return (code, stdout, stderr)."""
    rng = random.Random(seed)
    clock = types.SimpleNamespace(now=1000.0)
    owner = rng.choice(HOSTS)
    start_active = rng.random() < 0.6
    active_after = rng.choice([1, 2, 5, 1000])
    move_at = rng.choice([None, None, 3, 6])
    port = {"created": None, "host": owner, "ips": ["fd00::5"] if rng.random() < 0.15
            else ["10.0.0.5", "fd00::5"], "mac": MAC,
            "owner": rng.choice(["compute:nova", "network:dhcp", "network:router_gateway"]),
            "status": "ACTIVE" if start_active else "DOWN"}
    calls = {"port": 0}

    def collect_port(mac):
        calls["port"] += 1
        host = owner
        if move_at and calls["port"] >= move_at:
            host = HOSTS[(HOSTS.index(owner) + 1) % len(HOSTS)]
        status = "ACTIVE" if start_active or calls["port"] >= active_after else "DOWN"
        return dict(port, host=host, status=status)

    bad = set(rng.sample(HOSTS, rng.choice([0, 0, 1])))
    arrive = {(host, entry): rng.choice([0, 15, 30, 45, 10**9])
              for host in HOSTS for entry in cli.FDB_ENTRIES}
    has_vni = {host: rng.random() < 0.85 for host in HOSTS}
    arp_on = {host: rng.random() < 0.7 for host in HOSTS}
    flaky = {host: rng.random() < 0.15 for host in HOSTS}

    def collect_fdb_flows(host, args, mac, ip):
        if flaky[host] and int(clock.now) % 30 == 0:
            raise RuntimeError("ssh: timeout")
        elapsed = clock.now - 1000.0
        entries = {entry for (name, entry), at in arrive.items() if name == host and elapsed >= at}
        sections = fdb_sections(entries, owner, arp_on[host])
        if not has_vni[host]:
            sections["table4"] = sections["table22"] = ""
        return sections

    monkeypatch.setattr(cli, "collect_fdb_flows", collect_fdb_flows)
    monkeypatch.setattr(cli, "collect_port", collect_port)
    monkeypatch.setattr(cli, "port_age", lambda item: rng.choice([None, 5.0]))
    monkeypatch.setattr(cli, "preflight", fake_preflight(bad))
    monkeypatch.setattr(cli, "run_parallel", sequential)
    monkeypatch.setattr(cli, "time", types.SimpleNamespace(
        sleep=lambda seconds: setattr(clock, "now", clock.now + seconds), time=lambda: clock.now))
    args = types.SimpleNamespace(fdb_watch=MAC, fdb_watch_interval=15,
                                 fdb_watch_time=rng.choice([60, 120]), hosts=None, vni=0x64,
                                 workers=4)
    return capture(lambda: cli.run_fdb_watch(args, [port], dict(IPS)))


# --- main ---

def cloud(seed):
    """Return (networks, ports, tunnel_ips, ip_hosts) for one random cloud."""
    rng = random.Random(seed)
    vnis = [100 + n for n in range(rng.randint(1, 4))]
    networks = [{"id": f"n{vni}", "vni": vni} for vni in vnis]
    ports = []
    for vni in vnis:
        for number in range(rng.randint(1, 4)):
            ports.append({"address_pairs": [], "created": None, "device": f"vm{vni}{number}",
                          "host": rng.choice(HOSTS), "ips": [f"10.{vni % 256}.0.{number + 2}"],
                          "mac": f"fa:16:3e:00:{vni % 256:02x}:{number:02x}",
                          "network_id": f"n{vni}",
                          "owner": rng.choice(["compute:nova", "network:dhcp"]),
                          "status": rng.choice(["ACTIVE", "ACTIVE", "DOWN"])})
    dead = set(rng.sample(HOSTS, rng.choice([0, 0, 1])))
    tunnel_ips = {host: IPS[host] for host in HOSTS if host not in dead}
    return networks, ports, tunnel_ips, {IPS[host]: host for host in HOSTS}


def host_sections(rng, host, networks, ports):
    """Return random collected sections for one host, with some missing and stale flows."""
    tunnels = "\n".join(f'ofport : {n + 2}\noptions : {{remote_ip="{IPS[name]}"}}'
                        for n, name in enumerate(HOSTS) if name != host and rng.random() < 0.9)
    table4, table20, table21, table22 = [], [], [], []
    extra = [{"id": "x", "vni": 999}] if rng.random() < 0.2 else []
    for number, network in enumerate(networks + extra):
        vlan, vni = number + 1, network["vni"]
        table4.append(f" table=4, priority=1,tun_id={vni:#x} "
                      f"actions=mod_vlan_vid:{vlan},resubmit(,10)")
        outputs = ",".join(f"output:{n + 2}" for n, name in enumerate(HOSTS)
                           if name != host and rng.random() < 0.8)
        table22.append(f" table=22, priority=1,dl_vlan={vlan} actions=strip_vlan,"
                       f"load:{vni:#x}->NXM_NX_TUN_ID[],{outputs or 'output:2'}")
        stranger = [{"host": "c1", "ips": ["10.9.9.9"], "mac": "fa:16:3e:ff:ff:ff"}]
        members = [item for item in ports if item["network_id"] == network["id"]]
        for item in members + (stranger if rng.random() < 0.2 else []):
            if item["host"] == host or rng.random() < 0.15:
                continue
            output = HOSTS.index(item["host"]) + 2
            table20.append(f" table=20, priority=2,dl_vlan={vlan},dl_dst={item['mac']} "
                           f"actions=strip_vlan,load:{vni:#x}->NXM_NX_TUN_ID[],output:{output}")
            if rng.random() < 0.85:
                table21.append(f" table=21, priority=1,arp,dl_vlan={vlan},arp_tpa={item['ips'][0]}"
                               f" actions=mod_dl_src:{item['mac']},IN_PORT")
    return {
        "drift": f"host_kernel={rng.choice(['6.8', '6.8', '6.5'])}\nl2_population=True",
        "netns": "@ns qrouter-r1\n@addr\n2: qr inet 10.100.0.1/24\n"
                 "@route\ndefault via 10.100.0.5 dev qr table 7",
        "table1": f"table=1, actions=mod_dl_src:fa:16:3f:00:00:{HOSTS.index(host):02x}",
        "table20": "\n".join(table20), "table21": "\n".join(table21),
        "table22": "\n".join(table22), "table4": "\n".join(table4),
        "table9": "\n".join(f"table=9, priority=1,dl_src=fa:16:3f:00:00:{n:02x} actions=output:1"
                            for n in range(len(HOSTS)) if rng.random() < 0.8),
        "tags": "1\n2", "tunnels": tunnels,
    }


def main_argv(seed):
    """Return the argv for one random run. {tmp} stands for a temporary folder."""
    rng = random.Random(seed)
    argv = list(rng.choice(MAIN_OPTIONS)) + list(rng.choice(MAIN_EXTRAS))
    if "--restore" in argv and "--vni" in argv[argv.index("--restore") + 2:]:
        argv = argv[:-2]
    if rng.random() < 0.3:
        argv += ["--prometheus-file", "{tmp}/p.prom"]
    if rng.random() < 0.3:
        argv += ["--summary-state", "{tmp}/s.json"]
    return argv


def run_main(monkeypatch, seed, tmp):
    """Run main() on one random cloud. Return (argv, code, stdout, stderr, files)."""
    networks, ports, tunnel_ips, ip_hosts = cloud(seed)
    calls = {"hosts": {}, "neutron": 0}

    def collect_neutron():
        calls["neutron"] += 1
        shrink_roll = random.Random(seed * 7 + calls["neutron"]).random()
        shrink = calls["neutron"] > 1 and shrink_roll < 0.05
        return ((networks[:1] if shrink else networks), (ports[:1] if shrink else ports),
                dict(tunnel_ips), dict(ip_hosts))

    def collect_host(host, user, timeout, extra=""):
        number = calls["hosts"][host] = calls["hosts"].get(host, -1) + 1
        rng = random.Random(f"{seed}-{host}-{number}")
        if rng.random() < 0.05:
            raise RuntimeError("ssh: timeout")
        return host_sections(rng, host, networks, ports)

    def run_ssh(host, user, timeout, script):
        if "dump-flows br-tun >" in script:
            return f"/var/backups/kolla-ovs-doctor/br-tun-2026-11-06-010101-{len(host)}.flows\n"
        if "grep 'table=22'" in script:
            backup = host_sections(random.Random(f"{seed}-{host}-backup"), host, networks, ports)
            return ("/var/backups/kolla-ovs-doctor/br-tun-2026-11-06-000000-1.flows\n"
                    + backup["table22"])
        return ""

    bad = set(random.Random(seed + 1).sample(HOSTS, random.Random(seed + 2).choice([0, 0, 0, 1])))
    router = {"agents": [{"alive": True, "configurations": {"agent_mode": "dvr_snat"},
                          "ha_state": "active", "host": "net1"}],
              "agents_known": True, "distributed": False, "gateway_ips": ["203.0.113.1"],
              "ha": True, "id": "r1", "name": "r1", "snat_enabled": True}
    argv = main_argv(seed)
    state = os.path.join(tmp, "s.json")
    if "--summary-state" in argv:
        with open(state, "w") as handle:
            json.dump({"arp_stale": 1}, handle)
    monkeypatch.setattr(cli, "collect_host", collect_host)
    monkeypatch.setattr(cli, "collect_neutron", collect_neutron)
    monkeypatch.setattr(cli, "collect_routers", lambda workers: [router])
    monkeypatch.setattr(cli, "preflight", fake_preflight(bad))
    monkeypatch.setattr(cli, "run_parallel", sequential)
    monkeypatch.setattr(cli, "run_ssh", run_ssh)
    monkeypatch.setattr(cli, "ssh_control_dir", lambda: tmp)
    monkeypatch.setattr(sys, "argv", ["ovs-doctor"] + [arg.format(tmp=tmp) for arg in argv])
    code, out, err = capture(cli.main)
    files = {}
    for name in ("p.prom", "s.json"):
        path = os.path.join(tmp, name)
        if os.path.exists(path):
            with open(path) as handle:
                files[name] = handle.read()
            os.remove(path)
    return argv, code, out, err, files
