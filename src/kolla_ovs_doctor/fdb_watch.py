"""--fdb-watch: time how long each host takes to add the l2pop flows of one port."""
import datetime
import sys
import time
import types

from kolla_ovs_doctor import neutron, parse, remote, util

# Table columns are in reading order: the host, then the entries of FDB_ENTRIES.
FDB_COLUMNS = ("Host", "ARP", "Flood", "Unicast")
FDB_ENTRIES = ("arp", "flood", "unicast")


def present_fdb_entries(sections, vni, mac, ip, owner_ip):
    """Return which l2pop entries for one port exist in a host's tables."""
    vlans = parse.parse_unique_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    tunnels = parse.parse_tunnels(sections.get("tunnels", ""))
    arp = any(vlans.get(vlan) == vni and entry_ip == ip and entry_mac == mac
              for vlan, entry_ip, entry_mac in parse.parse_arp_flows(sections.get("table21", "")))
    unicast = any(entry_vni == vni and entry_mac == mac and not learned
                  and any(tunnels.get(port) == owner_ip for port in outputs)
                  for entry_vni, entry_mac, learned, outputs
                  in parse.parse_unicast_flows(sections.get("table20", "")))
    flood_ports = parse.parse_flood_ports(sections.get("table22", "")).get(vni, set())
    return {"arp": arp,
            "flood": any(tunnels.get(port) == owner_ip for port in flood_ports),
            "unicast": unicast}


def expected_fdb_entries(sections, port_owner, has_ipv4=True):
    """Return the l2pop entries a host should get for a port.

    ARP responder entries exist only for IPv4 addresses of compute and DHCP ports.
    They exist only on hosts with arp_responder on. Such hosts have ARP flows in table 21.
    """
    owner = port_owner or ""
    arp = (has_ipv4 and (owner.startswith("compute:") or owner == "network:dhcp")
           and parse.has_arp_flows(sections))
    return {entry for entry in FDB_ENTRIES if arp or entry != "arp"}


def port_age(port):
    """Return the seconds since the port was created, or None if unknown."""
    created = port.get("created")
    if not created:
        return None
    moment = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
    return datetime.datetime.now(datetime.timezone.utc).timestamp() - moment.timestamp()


def find_fdb_port(args, ports):
    """Return the port that --fdb-watch follows, or stop if it cannot be followed."""
    mac = args.fdb_watch.lower()
    port = next((item for item in ports if item["mac"].lower() == mac), None)
    if port is None or not port.get("ips"):
        util.fail(f"no port with an IP found for {mac}")
    if port.get("owner") in neutron.SKIPPED_PORT_OWNERS:
        util.fail(f"{mac} is a {port['owner']} port. l2pop adds no flows for it")
    return port


def wait_until_bound(args, port, bound):
    """Wait until the port is ACTIVE on a host. Return (port, start time)."""
    mac = args.fdb_watch.lower()
    if bound(port):
        started = time.time() - (port_age(port) or 0)
        print(f"port {mac} {port['ips'][0]} on {port['host']}, vni {args.vni}, "
              f"port age {time.time() - started:.0f}s")
        return port, started
    print(f"waiting up to {args.fdb_watch_time}s for {mac} to become ACTIVE on a host")
    limit = time.time() + args.fdb_watch_time
    while not bound(port):
        if time.time() >= limit:
            util.fail(f"{mac} did not become ACTIVE on a host")
        time.sleep(args.fdb_watch_interval)
        port = neutron.collect_port(mac) or port
    started = time.time()
    print(f"port {mac} {port['ips'][0]} on {port['host']}, vni {args.vni}, from ACTIVE")
    return port, started


def record_fdb_poll(watch, results, moment):
    """Store what one poll found. Print each entry the first time it shows up."""
    for host, (sections, error) in results.items():
        if error:
            watch.failed[host] = str(error)
            continue
        watch.failed.pop(host, None)
        if watch.vni not in parse.present_vnis(sections):
            continue
        wanted = watch.targets.setdefault(host, set())
        wanted |= expected_fdb_entries(sections, watch.port_owner, bool(watch.arp_ip))
        state = present_fdb_entries(sections, watch.vni, watch.mac, watch.ip, watch.owner_ip)
        for entry, present in state.items():
            if present and (host, entry) not in watch.seen:
                wanted.add(entry)
                watch.seen[(host, entry)] = moment
                print(f"{host:<8} {entry:<8} seen at {moment:.0f}s")


def fdb_watch_complete(watch):
    """Return True when every host has every entry it should get."""
    return bool(watch.targets) and all((host, entry) in watch.seen
                                       for host, wanted in watch.targets.items()
                                       for entry in wanted)


def print_fdb_table(watch, owner):
    """Print when each host got each entry. Return True if an entry never came."""
    print(f"owner {owner}")
    missing, rows = False, []
    for host in sorted(watch.targets):
        row = [host]
        for entry in FDB_ENTRIES:
            value = watch.seen.get((host, entry))
            if value is not None:
                row.append(f"{value:.0f}s")
            elif entry in watch.targets[host]:
                missing = True
                row.append("never")
            else:
                row.append("n/a")
        rows.append(row)
    text = util.table(FDB_COLUMNS, rows)
    if text:
        print(text)
    return missing


def run_fdb_watch(args, ports, tunnel_ips):
    """Report how long each host needs to add the l2pop flows of one port."""
    def bound(item):
        return item.get("status") == "ACTIVE" and item.get("host") in tunnel_ips

    port, started = wait_until_bound(args, find_fdb_port(args, ports), bound)
    # ARP responder entries exist only for IPv4 addresses.
    ip = next((address for address in port["ips"] if ":" not in address), port["ips"][0])
    owner = port["host"]
    all_hosts = set(util.parse_hosts(args.hosts) if args.hosts else tunnel_ips)
    # The owner is never polled, but it is checked too: the port can move away later.
    problems = remote.preflight(all_hosts | {owner}, args)
    all_hosts -= set(problems)
    watch = types.SimpleNamespace(
        arp_ip="" if ":" in ip else ip,
        failed={host: f"preflight: {problem}" for host, problem in problems.items()},
        ip=ip, mac=args.fdb_watch.lower(), owner_ip=None, port_owner=None, seen={},
        targets={}, vni=args.vni)
    deadline = time.time() + args.fdb_watch_time
    try:
        while True:
            latest = neutron.collect_port(watch.mac) or port
            if bound(latest) and latest["host"] != owner:
                moved = time.time() - started
                print(f"port moved from {owner} to {latest['host']} at {moved:.0f}s. "
                      f"Timing starts again.")
                owner = latest["host"]
                started = time.time()
                deadline = started + args.fdb_watch_time
                watch.seen, watch.targets = {}, {}
            port = latest
            watch.owner_ip, watch.port_owner = tunnel_ips[owner], port.get("owner")
            results = util.run_parallel(
                sorted(all_hosts - {owner}),
                lambda host: remote.collect_fdb_flows(host, args, watch.mac, watch.arp_ip),
                args.workers)
            record_fdb_poll(watch, results, time.time() - started)
            if fdb_watch_complete(watch) or time.time() >= deadline:
                break
            time.sleep(args.fdb_watch_interval)
    except KeyboardInterrupt:
        print("interrupted")
    missing = print_fdb_table(watch, owner)
    for host, error in sorted(watch.failed.items()):
        print(f"{host:<8} ERROR {error}", file=sys.stderr)
    return 2 if watch.failed else (1 if missing else 0)
