"""Unit tests for kolla_ovs_doctor.cli, grouped by topic."""
import json
import re
import subprocess
import time
import types

import pytest
from helpers import kinds, run_cli

from kolla_ovs_doctor import cli

ARP_FLOW = ("table=21, priority=1,arp,dl_vlan=5,arp_tpa=10.9.9.9 "
            "actions=mod_dl_src:fa:16:3e:99:99:99,IN_PORT")
BR_TUN_DUMP = """NXST_FLOW reply (xid=0x4):
 cookie=0x1, duration=1.0s, table=4, n_packets=0, priority=1,tun_id=0x64 actions=mod_vlan_vid:3,resubmit(,10)
 cookie=0x1, duration=1.0s, table=20, n_packets=0, priority=2,dl_vlan=3,dl_dst=fa:16:3e:00:00:09 actions=strip_vlan,load:0x64->NXM_NX_TUN_ID[],output:2
 cookie=0x1, duration=1.0s, table=22, n_packets=0, priority=1,dl_vlan=3 actions=strip_vlan,load:0x64->NXM_NX_TUN_ID[],output:2"""  # noqa: E501
GOOD_PREFLIGHT = "@preflight done\n"
BAD_PREFLIGHT = "@problem passwordless sudo is not available\n@preflight done\n"


def multi_segment():
    """Return (networks, ports) for a network with two VXLAN segments and one with one."""
    networks = [{"id": "net1", "vni": 100}, {"id": "net1", "vni": 200},
                {"id": "net2", "vni": 300}]
    ports = [
        {"address_pairs": [], "host": "c1", "ips": ["10.0.0.5"], "mac": "FA:16:3E:00:00:01",
         "network_id": "net1", "owner": "compute:nova", "status": "ACTIVE"},
        {"address_pairs": [], "host": "c1", "ips": ["10.1.0.5"], "mac": "fa:16:3e:00:00:03",
         "network_id": "net2", "owner": "compute:nova", "status": "ACTIVE"},
    ]
    return networks, ports


def shared_vlan():
    """Return host sections where two VNIs use local VLAN 5."""
    return {
        "table20": "", "table21": ARP_FLOW, "table22": "", "tags": "[]\n12", "tunnels": "",
        "table4": "table=4, priority=1,tun_id=0x12c actions=mod_vlan_vid:5,resubmit(,10)\n"
                  "table=4, priority=1,tun_id=0x3e7 actions=mod_vlan_vid:5,resubmit(,10)",
    }


def empty_context(known=None, bound=None):
    return {"bound_hosts": bound or {}, "collected": set(), "ip_hosts": {}, "known": known or {},
            "only_vni": None, "present_vnis": {}}


def dvr_router(**changes):
    router = {"agents": [{"alive": True, "configurations": {"agent_mode": "dvr_snat"},
                          "host": "net1"},
                         {"alive": True, "configurations": {"agent_mode": "dvr"}, "host": "c1"}],
              "agents_known": True, "distributed": True, "gateway_ips": ["203.0.113.5"],
              "ha": False, "id": "r1", "name": "r1", "snat_enabled": True}
    router.update(changes)
    return router


# --- multi-segment networks ---

def test_multi_segment_macs_are_known_in_every_segment():
    known = cli.build_known(*multi_segment())
    assert "fa:16:3e:00:00:01" in known[100]["macs"]
    assert "fa:16:3e:00:00:01" in known[200]["macs"]


def test_multi_segment_ports_are_not_expected():
    networks, ports = multi_segment()
    expected = cli.build_expected(networks, ports, {"c1": "192.0.2.1", "c2": "192.0.2.2"})
    assert 100 not in expected and 200 not in expected and 300 in expected


def test_multi_segment_ports_are_bound_in_every_segment():
    bound = cli.build_bound(*multi_segment())
    assert "c1" in bound[100] and "c1" in bound[200]


def test_multi_segment_flows_are_not_deleted():
    known = cli.build_known(*multi_segment())
    sections = {
        "table20": "table=20, priority=2,dl_vlan=7,dl_dst=fa:16:3e:00:00:01 "
                   "actions=strip_vlan,load:0xc8->NXM_NX_TUN_ID[],output:2",
        "table21": "table=21, priority=1,arp,dl_vlan=7,arp_tpa=10.0.0.5 "
                   "actions=mod_dl_src:fa:16:3e:00:00:01,IN_PORT",
        "table22": "", "table4": "table=4, priority=1,tun_id=0xc8 actions=mod_vlan_vid:7",
    }
    assert cli.plan_stale_deletions(sections, known, None) == []


# --- shared local VLANs ---

def test_shared_vlan_is_reported_and_arp_is_not_stale():
    known = cli.build_known(*multi_segment())
    found = cli.audit_host("c1", shared_vlan(), {}, {}, empty_context(known))
    assert "vlan_conflict" in kinds(found)
    assert any(item["kind"] == "vni_orphan" and item["vni"] == 0x3e7 for item in found)
    assert "arp_stale" not in kinds(found)


def test_orphan_on_shared_vlan_is_kept():
    known = cli.build_known(*multi_segment())
    plans, kept = cli.plan_orphan_cleanup(shared_vlan(), empty_context(known))
    assert plans == [] and "shared" in kept[0][2]


def test_present_vnis_include_shared_vlans():
    assert cli.present_vnis(shared_vlan()) == {0x12c, 0x3e7}


def test_orphan_on_unused_vlan_is_deleted():
    table4 = "table=4, priority=1,tun_id=0x3e7 actions=mod_vlan_vid:9,resubmit(,10)"
    sections = dict(shared_vlan(), table4=table4)
    plans, _ = cli.plan_orphan_cleanup(sections, empty_context(cli.build_known(*multi_segment())))
    assert len(plans) == 1 and plans[0][1] == 9


# --- routers ---

def test_dvr_missing_snat_namespace():
    found = cli.audit_routers([dvr_router()], [], {"c1": {}, "net1": {}})
    assert any(item["kind"] == "snat_ns_missing" and item["host"] == "net1" for item in found)


def test_dvr_without_dvr_snat_agent_is_unscheduled():
    router = dvr_router(agents=[dvr_router()["agents"][1]])
    assert "router_unscheduled" in kinds(cli.audit_routers([router], [], {"c1": {}, "net1": {}}))


def test_dvr_with_all_snat_agents_down():
    router = dvr_router(agents=[dict(dvr_router()["agents"][0], alive=False)])
    assert "router_agents_down" in kinds(cli.audit_routers([router], [], {"c1": {}, "net1": {}}))


def test_dvr_unknown_agents_give_no_scheduling_finding():
    router = dvr_router(agents=[], agents_known=False)
    assert kinds(cli.audit_routers([router], [], {"c1": {}, "net1": {}})) == []


def test_centralized_failed_agent_call_is_not_unscheduled():
    router = dvr_router(agents=[], agents_known=False, distributed=False)
    assert "router_unscheduled" not in kinds(cli.audit_routers([router], [], {}))


def test_parse_netns_merges_the_two_passes():
    text = ("@ns snat-r1\n@addr\n1: qg inet 203.0.113.5/24\n"
            "@ns snat-r1\n@nat\n-A x -j SNAT --to-source 203.0.113.5")
    parsed = cli.parse_netns(text)
    assert parsed["snat-r1"]["addr"] and parsed["snat-r1"]["nat"]


def test_collect_routers(monkeypatch):
    class Router:
        def __init__(self, number):
            self.external_gateway_info = None
            self.id = self.name = f"r{number}"
            self.is_distributed = self.is_ha = False

    class Response:
        ok = True

        def json(self):
            return {"agents": [{"host": "net1"}]}

    network = types.SimpleNamespace(get=lambda path: Response(),
                                    routers=lambda: [Router(n) for n in range(5)])
    monkeypatch.setattr(cli, "openstack_connection",
                        lambda: types.SimpleNamespace(network=network))
    routers = cli.collect_routers(4)
    assert [router["id"] for router in routers] == [f"r{n}" for n in range(5)]
    assert all(router["agents"] == [{"host": "net1"}] and router["agents_known"]
               for router in routers)


# --- flows ---

def test_tunnel_missing_once_per_peer():
    networks = [{"id": f"n{n}", "vni": 10 + n} for n in range(3)]
    ports = [{"address_pairs": [], "host": host, "ips": [], "mac": f"fa:16:3e:00:0{n}:{m}",
              "network_id": f"n{n}", "owner": "compute:x", "status": "ACTIVE"}
             for n in range(3) for m, host in enumerate(("c1", "c2"))]
    ips = {"c1": "192.0.2.1", "c2": "192.0.2.2"}
    found = cli.audit_host("c1", {}, cli.build_expected(networks, ports, ips), ips)
    tunnels = [item for item in found if item["kind"] == "tunnel_missing"]
    assert len(tunnels) == 1 and "3 VNIs" in tunnels[0]["detail"]
    assert kinds(found).count("flood_missing") == 3


def test_split_flow_tables():
    tables = cli.split_flow_tables(BR_TUN_DUMP)
    assert set(tables) == {"table20", "table22", "table4"}
    assert "dl_dst" in tables["table20"]


def test_collect_host_splits_the_br_tun_dump(monkeypatch):
    monkeypatch.setattr(cli, "run_ssh", lambda host, user, timeout, script: (
        '=====AUDIT:tunnels=====\nofport : 2\noptions : {remote_ip="192.0.2.9"}\n'
        "=====AUDIT:tags=====\n3\n=====AUDIT:brtun=====\n" + BR_TUN_DUMP))
    sections = cli.collect_host("h", None, 1)
    assert "brtun" not in sections
    assert cli.present_vnis(sections) == {0x64}
    assert cli.parse_tunnels(sections["tunnels"]) == {2: "192.0.2.9"}


def test_parsers_are_cached_and_small():
    table20 = cli.split_flow_tables(BR_TUN_DUMP)["table20"]
    assert cli.parse_unicast_flows(table20) is cli.parse_unicast_flows(table20)
    assert cli.parse_unicast_flows.cache_info().maxsize == 16
    assert cli.unicast_by_vni(table20) == {0x64: {"fa:16:3e:00:00:09": ((False, (2,)),)}}


def test_fix_deletions_are_sorted_by_vni_then_ip_as_a_number():
    sections = {
        "table20": "", "table22": "",
        "table21": "\n".join(
            f"table=21, priority=1,arp,dl_vlan={vlan},arp_tpa={ip} "
            f"actions=mod_dl_src:fa:16:3e:00:00:0{n},IN_PORT"
            for n, (vlan, ip) in enumerate([(7, "10.0.0.10"), (8, "10.0.0.9"), (7, "10.0.0.9")])),
        "table4": "table=4, priority=1,tun_id=0x64 actions=mod_vlan_vid:7,resubmit(,10)\n"
                  "table=4, priority=1,tun_id=0x9 actions=mod_vlan_vid:8,resubmit(,10)",
    }
    known = cli.build_known([{"id": "a", "vni": 0x64}, {"id": "b", "vni": 0x9}], [])
    labels = [(vni, label) for vni, _, label in cli.plan_stale_deletions(sections, known, None)]
    assert labels == [(9, "arp 10.0.0.9 -> fa:16:3e:00:00:01"),
                      (100, "arp 10.0.0.9 -> fa:16:3e:00:00:02"),
                      (100, "arp 10.0.0.10 -> fa:16:3e:00:00:00")]
    printed = []
    cli.fix_host("h", sections, [], types.SimpleNamespace(dry_run=True, vni=None), known,
                 printed.append)
    assert [line.split()[1] for line in printed] == ["vni=9", "vni=100", "vni=100"]


# --- drift ---

def drift_hosts(**values):
    return {host: {"drift": f"host_kernel=6.8\n{line}"} for host, line in values.items()}


def test_boolean_spelling_is_not_config_drift():
    collected = drift_hosts(hv01="enable_distributed_routing=true",
                            hv02="enable_distributed_routing=true",
                            hv07="enable_distributed_routing=True",
                            hv08="enable_distributed_routing=yes",
                            hv09="enable_distributed_routing=ON ")
    assert cli.audit_drift(collected) == []


def test_real_config_drift_is_still_found():
    collected = drift_hosts(hv01="l2_population=True", hv02="l2_population=true",
                            hv07="l2_population=False")
    found = cli.audit_drift(collected)
    assert [(item["host"], item["kind"], item["detail"]) for item in found] == [
        ("hv07", "config_drift", "l2_population=false (most hosts: true)")]


def test_numbers_and_versions_are_compared_as_written():
    collected = {host: {"drift": text} for host, text in (
        ("hv01", "heartbeat_timeout_threshold=0\nimage=kolla/neutron:2025.1"),
        ("hv02", "heartbeat_timeout_threshold=0\nimage=kolla/neutron:2025.1"),
        ("hv07", "heartbeat_timeout_threshold=false\nimage=Kolla/neutron:2025.1"))}
    assert sorted((item["kind"], item["detail"]) for item in cli.audit_drift(collected)) == [
        ("config_drift", "heartbeat_timeout_threshold=false (most hosts: 0)"),
        ("version_drift", "image=Kolla/neutron:2025.1 (most hosts: kolla/neutron:2025.1)")]


# --- fdb-watch ---

def test_fdb_expected_entries():
    arp = {"table21": ARP_FLOW}
    assert cli.expected_fdb_entries(arp, "compute:nova") == {"arp", "flood", "unicast"}
    assert cli.expected_fdb_entries({}, "compute:nova") == {"flood", "unicast"}
    assert cli.expected_fdb_entries(arp, "network:router_gateway") == {"flood", "unicast"}
    assert cli.expected_fdb_entries(arp, "compute:nova", False) == {"flood", "unicast"}


def test_has_arp_flows_reads_the_count():
    assert cli.has_arp_flows({"arp_count": "NXST_AGGREGATE reply: flow_count=4"})
    assert not cli.has_arp_flows({"arp_count": "NXST_AGGREGATE reply: flow_count=0"})


def test_watch_script_passes_mac_and_ip():
    script = cli.WATCH_SCRIPT.format(ip="10.0.0.5", mac="fa:16:3e:00:00:09")
    assert "bash -s -- fa:16:3e:00:00:09 10.0.0.5 <<'OVS'" in script


# --- remote scripts and SSH ---

def test_remote_scripts_parse(ssh_scripts):
    args = types.SimpleNamespace(backup_dir="/var/backups/kolla ovs doctor", ssh_user=None,
                                 timeout=1)
    cli.apply_changes("apply", args, ["table=22,dl_vlan=1,actions=output:2"],
                      ["table=21,dl_vlan=1"])
    cli.read_backup("latest", args, "latest")
    cli.read_backup("named", args, "br-tun-2026-11-05-101010-1.flows")
    scripts = dict(ssh_scripts, collect=cli.COLLECT_SCRIPT + cli.ROUTER_SCRIPT + cli.DRIFT_SCRIPT,
                   preflight=cli.PREFLIGHT_SCRIPT,
                   watch=cli.WATCH_SCRIPT.format(ip="10.0.0.5", mac="fa:16:3e:00:00:09"))
    for name, script in sorted(scripts.items()):
        result = subprocess.run(["bash", "-n"], capture_output=True, check=False, input=script,
                                text=True)
        assert result.returncode == 0, (name, result.stderr)


def test_backup_script(ssh_scripts):
    args = types.SimpleNamespace(backup_dir="/var/backups/kolla ovs doctor", ssh_user=None,
                                 timeout=1)
    cli.apply_changes("apply", args, [], [])
    cli.read_backup("latest", args, "latest")
    cli.read_backup("named", args, "br-tun-2026-11-05-101010-1.flows")
    assert "DIR='/var/backups/kolla ovs doctor'" in ssh_scripts["apply"]
    assert '-$$.flows"' in ssh_scripts["apply"]
    assert 'mv "$BACKUP.tmp" "$BACKUP"' in ssh_scripts["apply"]
    assert "/tmp" not in ssh_scripts["latest"] and "/tmp" not in ssh_scripts["named"]


def test_one_docker_exec_and_no_sudo_inside_scripts(ssh_scripts):
    args = types.SimpleNamespace(backup_dir="/b", ssh_user=None, timeout=1)
    cli.apply_changes("apply", args, [], [])
    scripts = [cli.COLLECT_SCRIPT, cli.DRIFT_SCRIPT, cli.PREFLIGHT_SCRIPT, cli.ROUTER_SCRIPT,
               cli.WATCH_SCRIPT, ssh_scripts["apply"]]
    assert cli.COLLECT_SCRIPT.count("docker exec") == 1
    assert not any(re.search(r"(^|[\s;|&(`$])sudo\s", script.replace("'@problem sudo", ""))
                   for script in scripts)


def test_ssh_command(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = " ".join(command)
        return types.SimpleNamespace(returncode=0, stderr="", stdout="ok")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    cli.run_ssh("h", "u", 5, "true")
    assert "ControlMaster=auto" in seen["command"] and "ControlPersist=60" in seen["command"]
    assert "ControlPath=/tmp/ovs-doctor-ssh-" in seen["command"]
    assert seen["command"].endswith("sudo -n bash -s")


def test_local_preflight_reports_a_problem():
    result = subprocess.run(["bash", "-s"], capture_output=True, check=False,
                            input=cli.PREFLIGHT_SCRIPT, text=True, timeout=60)
    assert result.returncode == 0
    assert "@preflight done" in result.stdout and "@problem" in result.stdout


# --- preflight ---

def test_parse_preflight():
    assert cli.parse_preflight("@preflight done\n") == []
    assert cli.parse_preflight("@problem a\n@problem b\n@preflight done") == ["a", "b"]
    assert cli.parse_preflight("@problem a\n") == ["preflight output incomplete"]


@pytest.mark.parametrize(("code", "start"), [(1, "passwordless sudo is not available"),
                                             (255, "ssh:")])
def test_preflight_host_errors(monkeypatch, code, start):
    def fail_ssh(*args, **kwargs):
        raise cli.RemoteError("sudo: a password is required", code)

    monkeypatch.setattr(cli, "run_ssh", fail_ssh)
    args = types.SimpleNamespace(ssh_user=None, timeout=1)
    assert cli.preflight_host("h", args).startswith(start)


@pytest.fixture
def two_hosts(monkeypatch):
    """A cloud with a good and a bad host. Return the list of (host, kind) SSH calls."""
    calls = []

    def fake_ssh(host, user, timeout, script):
        calls.append((host, "preflight" if script == cli.PREFLIGHT_SCRIPT else "other"))
        if script == cli.PREFLIGHT_SCRIPT:
            return BAD_PREFLIGHT if host == "bad" else GOOD_PREFLIGHT
        return ""

    monkeypatch.setattr(cli, "run_ssh", fake_ssh)
    monkeypatch.setattr(cli, "collect_neutron", lambda: (
        [], [], {"bad": "192.0.2.2", "good": "192.0.2.1"},
        {"192.0.2.1": "good", "192.0.2.2": "bad"}))
    return calls


def test_preflight_failure_stops_fix_before_anything_else(two_hosts, run_main):
    code, _, _ = run_main(["--checks", "flows", "--dry-run", "--fix"])
    assert code == 2
    assert all(kind == "preflight" for _, kind in two_hosts)


def test_preflight_failure_skips_the_host_in_an_audit(two_hosts, run_main):
    code, _, _ = run_main(["--checks", "flows", "--json"])
    assert code == 2
    assert ("bad", "other") not in two_hosts and ("good", "other") in two_hosts


def test_no_host_passing_preflight_exits_2(monkeypatch, two_hosts, run_main):
    monkeypatch.setattr(cli, "collect_neutron", lambda: ([], [], {"bad": "192.0.2.2"}, {}))
    assert run_main(["--checks", "flows"])[0] == 2


# --- hosts and dead agents ---

def test_parse_hosts():
    assert cli.parse_hosts(" c2,a,,c2 , b") == ["a", "b", "c2"]


def test_hosts_are_sorted_and_deduplicated(monkeypatch, run_main):
    collected = []
    monkeypatch.setattr(cli, "run_ssh", lambda *args: GOOD_PREFLIGHT)
    monkeypatch.setattr(cli, "collect_neutron",
                        lambda: ([], [], {"a": "192.0.2.1", "b": "192.0.2.2"}, {}))
    monkeypatch.setattr(cli, "collect_host", lambda host, *a, **k: collected.append(host) or {})
    run_main(["--checks", "flows", "--hosts", "b,a,b,", "--json"])
    assert collected == ["a", "b"]


def test_empty_hosts_option_is_rejected(run_main):
    assert run_main(["--hosts", ","])[0] == 2


def test_no_hosts_exits_2(monkeypatch, run_main):
    monkeypatch.setattr(cli, "collect_neutron", lambda: ([], [], {}, {}))
    assert run_main(["--checks", "flows"])[0] == 2


@pytest.fixture
def dead_agent(monkeypatch):
    monkeypatch.setattr(cli, "run_ssh", lambda *args: GOOD_PREFLIGHT)
    monkeypatch.setattr(cli, "collect_neutron", lambda: (
        [], [], {"a": "192.0.2.1"}, {"192.0.2.1": "a", "192.0.2.9": "dead1"}))
    monkeypatch.setattr(cli, "collect_host", lambda host, *a, **k: {})


def test_dead_agent_is_reported(dead_agent, run_main, tmp_path):
    prometheus = tmp_path / "x.prom"
    code, out, _ = run_main(["--checks", "flows", "--json", "--prometheus-file",
                             str(prometheus)])
    findings = json.loads(out)["findings"]
    assert code == 1
    assert [item["host"] for item in findings if item["kind"] == "agent_down"] == ["dead1"]
    body = prometheus.read_text()
    assert 'host_up{host="dead1"} 0' in body and 'host_up{host="a"} 1' in body


def test_hosts_option_with_only_a_dead_host(dead_agent, run_main):
    code, out, _ = run_main(["--checks", "flows", "--hosts", "dead1", "--json"])
    assert code == 1 and "agent_down" in out


def test_cannot_reach_openstack(monkeypatch, run_main):
    def broken():
        raise RuntimeError("Cloud envvars was not found.")

    monkeypatch.setattr(cli, "collect_neutron", broken)
    code, _, err = run_main([])
    assert code == 2 and "cannot reach OpenStack" in err


# --- repairs ---

def test_repair_parallel_keeps_each_host_together(capsys):
    def slow(host, out):
        out(f"{host} one")
        time.sleep(0.05 if host == "a" else 0)
        out(f"{host} two")
        if host == "c":
            raise RuntimeError("boom")
        return host.upper()

    errors = {}
    done = cli.repair_parallel(["a", "b", "c"], slow, types.SimpleNamespace(workers=3), errors,
                               "fix")
    assert capsys.readouterr().out.split("\n")[:6] == [
        "a one", "a two", "b one", "b two", "c one", "c two"]
    assert done == {"a": "A", "b": "B"} and errors == {"c": "fix failed: boom"}


def test_reread_after_change(monkeypatch):
    def down(*args, **kwargs):
        raise RuntimeError("ssh down")

    monkeypatch.setattr(cli, "collect_host", down)
    args = types.SimpleNamespace(ssh_user=None, timeout=1)
    after, error = cli.reread_after_change("h", args, True)
    assert after is None and str(error) == "ssh down"
    assert cli.reread_after_change("h", args, False) == (None, None)
    assert "fix applied" in cli.changed_but_unread("fix", error)


# --- output ---

def test_prometheus_labels_are_escaped(tmp_path):
    path = tmp_path / "out.prom"
    cli.write_prometheus_file(str(path), [{"detail": "", "host": 'a"b\\c', "kind": "arp_stale",
                                           "vni": 0}], ['a"b\\c'], {'a"b\\c'})
    assert 'host="a\\"b\\\\c"' in path.read_text()


def test_host_up_follows_collection(tmp_path):
    path = tmp_path / "y.prom"
    cli.write_prometheus_file(str(path), [], ["h1", "h2"], {"h1"})
    body = path.read_text()
    assert 'ovs_doctor_host_up{host="h1"} 1' in body
    assert 'ovs_doctor_host_up{host="h2"} 0' in body


def test_fail_exits_2():
    with pytest.raises(SystemExit) as exc:
        cli.fail("x")
    assert exc.value.code == 2


# --- command line ---

def test_help_and_version():
    help_text = run_cli("--help").stdout
    assert help_text.startswith("usage: ovs-doctor")
    for option in ("--fdb-watch-time", "--prometheus-file", "--summary-state", "--version"):
        assert option in help_text
    assert run_cli("--version").stdout.strip() == f"ovs-doctor {cli.__version__}"


@pytest.mark.parametrize("option", ["--state", "--textfile", "--watch-interval", "--watch-time"])
def test_old_option_names_are_gone(option):
    result = run_cli(option, "1")
    assert result.returncode == 2 and "unrecognized arguments" in result.stderr


@pytest.mark.parametrize(("name", "accepted"), [("br-tun-2026-11-06-101010-4242.flows", True),
                                                ("br-tun-2026-11-06-101010.flows", False)])
def test_restore_file_names(name, accepted):
    rejected = "--restore needs a br-tun" in run_cli("--restore", name, "--vni", "1").stderr
    assert rejected != accepted


def test_kind_names():
    assert not hasattr(cli, "OLD_KIND_NAMES")
    assert not any(kind.startswith(("missing_", "stale_", "wrong_")) for kind in cli.SEVERITY)
