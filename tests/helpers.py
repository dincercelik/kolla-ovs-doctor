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
