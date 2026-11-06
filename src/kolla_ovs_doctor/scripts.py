"""The shell scripts that run on the hosts.

A script for a container runs as `docker exec -i <container> bash -s [-- args]`.
The script is in a quoted heredoc, so it needs no extra quoting."""


SECTION_MARKER = "=====AUDIT:{}====="
# One docker exec and one br-tun dump. collect_host splits the dump into tables.
COLLECT_SCRIPT = """
set -e
docker exec -i openvswitch_vswitchd bash -s <<'OVS'
set -e
echo "{brtun}"; ovs-ofctl --no-names dump-flows br-tun
echo "{tags}"; ovs-vsctl --bare --columns=tag list port
echo "{tunnels}"; ovs-vsctl --columns=ofport,options find interface type=vxlan
OVS
""".format(
    brtun=SECTION_MARKER.format("brtun"),
    tags=SECTION_MARKER.format("tags"),
    tunnels=SECTION_MARKER.format("tunnels"),
)
DRIFT_SCRIPT = r"""
echo '=====AUDIT:drift====='
# Blocks are in the order of the keys they print.
docker exec -i neutron_openvswitch_agent bash -s <<'AGENT' || true
. /etc/os-release; echo "agent_container_os=$PRETTY_NAME"
/var/lib/kolla/venv/bin/python3 -c "
import importlib.metadata as m
for name in ('neutron', 'oslo.messaging'):
    print(name + '=' + m.version(name))
"
AGENT
KEYS='amqp_[a-z_]+|arp_responder|enable_distributed_routing|heartbeat_[a-z_]+'
KEYS="$KEYS|l2_population|rabbit_[a-z_]+|tunnel_types"
cat /etc/kolla/neutron-openvswitch-agent/*.conf \
    /etc/kolla/neutron-openvswitch-agent/*.ini 2>/dev/null \
  | grep -E "^ *($KEYS) *=" \
  | grep -viE 'password|user *=|userid' | sed 's/ *= */=/' | sort -u || true
echo "host_kernel=$(uname -r)"
(. /etc/os-release; echo "host_os=$PRETTY_NAME") || true
docker inspect --format '{{.Name}} {{.Config.Image}}' \
    neutron_openvswitch_agent openvswitch_db openvswitch_vswitchd 2>/dev/null \
  | awk '$1 == "/neutron_openvswitch_agent" {print "image=" $2}
         $1 == "/openvswitch_db" {print "ovsdb_image=" $2}
         $1 == "/openvswitch_vswitchd" {print "ovs_image=" $2}' || true
docker exec -i openvswitch_vswitchd bash -s <<'OVS' || true
. /etc/os-release; echo "ovs_container_os=$PRETTY_NAME"
ovs-vswitchd --version | awk 'NR==1{print "ovs_version=" $NF}'
OVS
"""
# Runs under sudo, like every other script. If sudo asks for a password, the script
# does not start. preflight_host sees this in the exit code.
PREFLIGHT_SCRIPT = r"""
if [ "$(id -u)" != 0 ]; then
  echo '@problem sudo did not run the script as root'
  echo '@preflight done'
  exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
  if command -v podman >/dev/null 2>&1; then
    echo '@problem podman deployments are not supported'
  else
    echo '@problem docker not found'
  fi
  echo '@preflight done'
  exit 0
fi
test -f /etc/kolla/neutron-openvswitch-agent/config.json \
  || echo '@problem /etc/kolla/neutron-openvswitch-agent/config.json not found'
for c in neutron_openvswitch_agent openvswitch_db openvswitch_vswitchd; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] \
    || echo "@problem container $c is not running"
done
if label=$(docker inspect -f '{{index .Config.Labels "kolla_version"}}' \
    neutron_openvswitch_agent 2>/dev/null); then
  case "$label" in
    ''|'<no value>') echo '@problem neutron_openvswitch_agent has no kolla_version label' ;;
  esac
fi
echo '@preflight done'
exit 0
"""
ROUTER_SCRIPT = r"""
echo '=====AUDIT:netns====='
# A subshell with set +e, because grep may find nothing here.
(
set +e
NS=$(ip netns list | awk '{print $1}' | grep -E '^(qrouter|snat)-')
for ns in $NS; do
  echo "@ns $ns"
  echo "@addr"; ip -n "$ns" -o -4 addr show
  echo "@neigh"; ip -n "$ns" -4 neigh show nud permanent
  echo "@route"; ip -n "$ns" -4 route show table all | grep '^default'
done
# Read SNAT rules with the iptables of the l3 agent. The host may use the other
# iptables backend (legacy or nft), and then it shows no rules.
if [ -n "$NS" ] && docker ps --format '{{.Names}}' | grep -qx neutron_l3_agent; then
  docker exec -i -u root neutron_l3_agent bash -s -- $NS <<'L3' | grep -E '^@|-j SNAT'
for ns in "$@"; do
  echo "@ns $ns"; echo "@nat"
  ip netns exec "$ns" iptables -t nat -S
done
L3
else
  for ns in $NS; do
    echo "@ns $ns"; echo "@nat"
    for ipt in iptables iptables-legacy iptables-nft; do
      command -v "$ipt" >/dev/null && ip netns exec "$ns" "$ipt" -t nat -S 2>/dev/null
    done | grep -- '-j SNAT' | sort -u
  done
fi
exit 0
)
"""
# --fdb-watch reads only the flows of one port. $1 is its MAC and $2 its IPv4
# address. $2 is empty if the port has no IPv4 address. Then table 21 is skipped.
WATCH_SCRIPT = """
set -e
docker exec -i openvswitch_vswitchd bash -s -- {{mac}} {{ip}} <<'OVS'
set -e
echo "{arp_count}"; ovs-ofctl dump-aggregate br-tun table=21,arp
echo "{table4}"; ovs-ofctl --no-names dump-flows br-tun table=4
echo "{table20}"; ovs-ofctl --no-names dump-flows br-tun "table=20,dl_dst=$1"
echo "{table21}"; [ -z "$2" ] || ovs-ofctl --no-names dump-flows br-tun "table=21,arp,arp_tpa=$2"
echo "{table22}"; ovs-ofctl --no-names dump-flows br-tun table=22
echo "{tunnels}"; ovs-vsctl --columns=ofport,options find interface type=vxlan
OVS
""".format(
    arp_count=SECTION_MARKER.format("arp_count"),
    table4=SECTION_MARKER.format("table4"),
    table20=SECTION_MARKER.format("table20"),
    table21=SECTION_MARKER.format("table21"),
    table22=SECTION_MARKER.format("table22"),
    tunnels=SECTION_MARKER.format("tunnels"),
)
