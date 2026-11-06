"""--cleanup, --fix and --restore: plan flow changes and apply them on the hosts."""
import ipaddress
import re
from collections import defaultdict

from kolla_ovs_doctor import checks, neutron, parse, remote, util
from kolla_ovs_doctor.findings import FLOW_KINDS


def plan_stale_deletions(sections, known, only_vni):
    """Return [(vni, flow spec, label)] for stale flows to delete, sorted by VNI."""
    vlans = parse.parse_unique_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    deletions = []
    for vlan, ip, mac in parse.parse_arp_flows(sections.get("table21", "")):
        vni = vlans.get(vlan)
        if (vni in known and only_vni in (None, vni)
                and not checks.flows.arp_is_known(known[vni], ip, mac)):
            deletions.append(((vni, "arp", int(ipaddress.ip_address(ip)), mac),
                              (vni, f"table=21,arp,dl_vlan={vlan},arp_tpa={ip}",
                               f"arp {ip} -> {mac}")))
    for vlan, vni, mac in parse.parse_static_unicast_flows(sections.get("table20", "")):
        if vni in known and only_vni in (None, vni) and mac not in known[vni]["macs"]:
            deletions.append(((vni, "unicast", 0, mac),
                              (vni, f"table=20,dl_vlan={vlan},dl_dst={mac}",
                               f"unicast {mac}")))
    return [item for _, item in sorted(deletions)]


def plan_flood_fix(sections, vni, peer_ips):
    """Return (vlan, new_actions, added_ports). vlan is None if there is nothing to do."""
    ports = {ip: port for port, ip in parse.parse_tunnels(sections.get("tunnels", "")).items()}
    missing = sorted(set(peer_ips) - set(ports))
    if missing:
        raise ValueError(f"no tunnel port for {', '.join(missing)}")
    flows = parse.parse_flood_flows(sections.get("table22", "")).get(vni, [])
    if len(flows) != 1:
        raise ValueError(f"expected one table 22 flow for VNI {vni}, found {len(flows)}")
    vlan, actions = flows[0]
    present = set(parse.line_outputs(actions))
    added = sorted({ports[ip] for ip in peer_ips} - present)
    if not added:
        return None, actions, []
    return vlan, actions + "".join(f",output:{port}" for port in added), added


def plan_restore(sections, backup_text, vni):
    """Return (vlan, actions, removed, added). vlan is None if there is nothing to do."""
    current = parse.parse_flood_flows(sections.get("table22", "")).get(vni, [])
    saved = parse.parse_flood_flows(backup_text).get(vni, [])
    if len(current) != 1 or len(saved) != 1:
        raise ValueError(f"expected one flood flow for VNI {vni}, found "
                         f"{len(current)} live and {len(saved)} in backup")
    (vlan, live_actions), (saved_vlan, actions) = current[0], saved[0]
    if vlan != saved_vlan:
        raise ValueError(f"local vlan changed from {saved_vlan} to {vlan}")
    tunnels = parse.parse_tunnels(sections.get("tunnels", ""))
    gone = sorted(set(parse.line_outputs(actions)) - set(tunnels))
    if gone:
        raise ValueError(f"backup uses ports that no longer exist: {gone}")
    live, wanted = set(parse.line_outputs(live_actions)), set(parse.line_outputs(actions))
    if live == wanted:
        return None, actions, [], []
    return vlan, actions, sorted(live - wanted), sorted(wanted - live)


def plan_orphan_cleanup(sections, context):
    """Return ([(vni, vlan, flow specs)], [(vni, vlan, reason)] that are kept)."""
    if "tags" not in sections:
        return [], []
    used = {int(value) for value in sections["tags"].split() if value.isdigit()}
    vlans = parse.parse_vlan_vnis(sections.get("table4", ""), sections.get("table22", ""))
    plans, kept = [], []
    for vlan, vnis in sorted(vlans.items()):
        for vni in sorted(vnis):
            if vni in context["known"] or context["only_vni"] not in (None, vni):
                continue
            others = vnis - {vni}
            if others:
                # Deleting by dl_vlan would also delete the other VNI's flows.
                shared = ", ".join(f"{other:#x}" for other in sorted(others))
                kept.append((vni, vlan, f"local vlan {vlan} is shared with VNI {shared}"))
            elif vlan in used:
                kept.append((vni, vlan, f"local vlan {vlan} still has OVS ports"))
            else:
                plans.append((vni, vlan, orphan_flow_specs(vni, vlan)))
    return plans, kept


def orphan_flow_specs(vni, vlan):
    """Return the flow specs that delete an orphan VNI on its local VLAN."""
    return [f"table=4,tun_id={vni:#x}", f"table=1,dl_vlan={vlan}",
            f"table=20,dl_vlan={vlan}", f"table=21,dl_vlan={vlan}",
            f"table=22,dl_vlan={vlan}"]


def plan_flood_cleanup(sections, expected, context):
    """Return [(vni, vlan, new actions, removed ports, reasons)]."""
    tunnels = parse.parse_tunnels(sections.get("tunnels", ""))
    plans = []
    for vni, flows in sorted(parse.parse_flood_flows(sections.get("table22", "")).items()):
        if (len(flows) != 1 or vni not in context["known"]
                or context["only_vni"] not in (None, vni)):
            continue
        vlan, actions = flows[0]
        reasons = {}
        for port in parse.line_outputs(actions):
            if port in tunnels:
                reason = checks.flows.stale_flood_reason(tunnels[port], vni, expected, context)
                if reason:
                    reasons[port] = reason
        remaining = [port for port in parse.line_outputs(actions) if port not in reasons]
        if reasons and remaining:
            new_actions = actions
            for port in reasons:
                new_actions = re.sub(rf",output:{port}(?=,|$)", "", new_actions)
            plans.append((vni, vlan, new_actions, sorted(reasons), reasons))
    return plans


def restore_host(host, args, out=print):
    """Put back the flood flow of --vni from a backup on one host."""
    path, backup_text = remote.read_backup(host, args, args.restore)
    if path is None:
        out(f"{host:<8} restore: no backup")
        return
    sections = remote.collect_host(host, args.ssh_user, args.timeout)
    vlan, actions, removed, added = plan_restore(sections, backup_text, args.vni)
    if vlan is None:
        out(f"{host:<8} restore: already matches {path}")
    elif args.dry_run:
        out(f"{host:<8} restore: would remove ports {removed}, add {added} "
            f"from {path}: {actions}")
    else:
        backup = remote.apply_flood_flow(host, args, vlan, actions)
        out(f"{host:<8} restore: removed ports {removed}, added {added} "
            f"from {path}, backup {backup}")


def fix_host(host, sections, findings, args, known, out=print):
    """Repair one host. Return (applied, problems)."""
    peers, problems, blocked, changes = defaultdict(list), [], set(), []
    lines = []
    for item in findings:
        if item["kind"] == "flood_missing":
            peers[item["vni"]].append(item["peer_ip"])
    for vni, ips in sorted(peers.items()):
        try:
            vlan, actions, added = plan_flood_fix(sections, vni, ips)
        except ValueError as exc:
            problems.append(f"vni {vni}: {exc}")
            blocked.add(vni)
            continue
        if vlan is not None:
            changes.append(f"table=22,dl_vlan={vlan},actions={actions}")
            lines.append((vni, 0, f"add flood ports {added}"))
    deletions = [item for item in plan_stale_deletions(sections, known, args.vni)
                 if item[0] not in blocked]
    lines += [(vni, 1 + index, f"delete {label}")
              for index, (vni, _, label) in enumerate(deletions)]
    for vni, _, text in sorted(lines):
        out(f"{host:<8} vni={vni:<8} {text}")
    if args.dry_run or not (changes or deletions):
        return False, problems
    backup = remote.apply_changes(host, args, changes, [spec for _, spec, _ in deletions])
    out(f"{host:<8} fix: applied, backup {backup}")
    return True, problems


def repair_parallel(hosts, action, args, errors, label):
    """Run action(host, out) on hosts in parallel and print each host's lines in order.

    Return {host: result} for the hosts that finished. Failures are added to errors.
    """
    outputs = {host: [] for host in hosts}
    results = util.run_parallel(hosts, lambda host: action(host, outputs[host].append),
                                args.workers)
    done = {}
    for host, (result, error) in results.items():
        for line in outputs[host]:
            print(line)
        if error:
            errors[host] = f"{label} failed: {error}"
        else:
            done[host] = result
    return done


def reread_after_change(host, args, changed):
    """Read a host again after its flows changed. Return (sections, error)."""
    if not changed:
        return None, None
    try:
        return remote.collect_host(host, args.ssh_user, args.timeout), None
    except Exception as exc:  # The change worked. Only the new state is unknown.
        return None, exc


def changed_but_unread(action, error):
    """Return the error text for a change that worked but could not be re-read."""
    return (f"{action} applied, but reading the host again failed ({error}). "
            f"Its findings are from before the {action}")


def refresh_context(hosts, args, context):
    """Read the hosts, then Neutron. Then a port made in the meantime counts as in use."""
    results = util.run_parallel(
        hosts, lambda host: remote.collect_host(host, args.ssh_user, args.timeout), args.workers)
    fresh = {host: sections for host, (sections, error) in results.items() if not error}
    networks, ports, tunnel_ips, ip_hosts = neutron.collect_neutron()
    expected = neutron.build_expected(networks, ports, tunnel_ips)
    if args.vni is not None:
        expected = {key: value for key, value in expected.items() if key == args.vni}
    context.update(
        bound_hosts=neutron.build_bound(networks, ports), collected=set(fresh), ip_hosts=ip_hosts,
        known=neutron.build_known(networks, ports),
        present_vnis={host: parse.present_vnis(sections) for host, sections in fresh.items()})
    return fresh, expected, tunnel_ips, networks, ports


def cleanup_host(host, sections, expected, context, args, out=print):
    """Remove stale flood ports and orphan VNIs. Return True if flows changed."""
    plans = plan_flood_cleanup(sections, expected, context)
    orphans, kept = plan_orphan_cleanup(sections, context)
    lines = [(vni, vlan, 0, f"delete orphan flows on local vlan {vlan}")
             for vni, vlan, _ in orphans]
    lines += [(vni, vlan, 0, f"keep orphan: {reason}") for vni, vlan, reason in kept]
    lines += [(vni, vlan, port, f"remove flood port {port}: {reasons[port]}")
              for vni, vlan, _, removed, reasons in plans for port in removed]
    for vni, _, _, text in sorted(lines):
        out(f"{host:<8} vni={vni:<8} {text}")
    if args.dry_run or not (plans or orphans):
        return False
    changes = [f"table=22,dl_vlan={vlan},actions={actions}"
               for _, vlan, actions, _, _ in plans]
    deletions = [spec for _, _, specs in orphans for spec in specs]
    backup = remote.apply_changes(host, args, changes, deletions)
    out(f"{host:<8} cleanup: applied, backup {backup}")
    return True


def replace_flow_findings(findings, host, new):
    """Return the findings with one host's flow findings replaced by new ones."""
    return [item for item in findings
            if item["host"] != host or item["kind"] not in FLOW_KINDS] + new


def stop_if_neutron_shrank(state, networks, ports):
    """Stop if Neutron now returns far fewer ports or networks than at the start."""
    if len(ports) < len(state.ports) / 2 or len(networks) < len(state.networks) / 2:
        util.fail("Neutron returned far fewer ports or networks. Nothing was changed")


def run_fix(state):
    """Add missing flood ports and delete stale flows (--fix)."""
    args = state.args
    fix_kinds = {"arp_stale", "flood_missing", "unicast_stale"}
    targets = sorted({item["host"] for item in state.findings if item["kind"] in fix_kinds})
    fresh = {}
    results = util.run_parallel(targets, lambda host: remote.collect_host(
        host, args.ssh_user, args.timeout), args.workers)
    for host, (sections, error) in results.items():
        if error:
            state.errors[host] = f"fix failed: {error}"
        else:
            fresh[host] = sections
    # Read Neutron after the hosts. Then a port made in the meantime is not stale.
    latest_networks, latest_ports, _, _ = neutron.collect_neutron()
    stop_if_neutron_shrank(state, latest_networks, latest_ports)
    state.known = neutron.build_known(latest_networks, latest_ports)
    state.context["known"] = state.known
    own = defaultdict(list)
    for item in state.findings:
        own[item["host"]].append(item)

    def fix_one(host, out):
        applied, problems = fix_host(host, fresh[host], own[host], args, state.known, out)
        return (problems, *reread_after_change(host, args, applied))

    done = repair_parallel(list(fresh), fix_one, args, state.errors, "fix")
    for host, (problems, after, reread_error) in done.items():
        messages = ["fix incomplete: " + "; ".join(problems)] if problems else []
        if reread_error:
            messages.append(changed_but_unread("fix", reread_error))
        if messages:
            state.errors[host] = "; ".join(messages)
        if after is not None:
            state.findings = replace_flow_findings(state.findings, host, checks.flows.audit_host(
                host, after, state.expected, state.tunnel_ips, state.context))


def run_cleanup(state):
    """Remove stale flood ports and orphan VNIs (--cleanup)."""
    args = state.args
    cleanup_kinds = {"flood_stale", "vni_orphan"}
    if not any(item["kind"] in cleanup_kinds for item in state.findings):
        return
    fresh, latest_expected, latest_ips, latest_networks, latest_ports = refresh_context(
        state.usable, args, state.context)
    stop_if_neutron_shrank(state, latest_networks, latest_ports)
    targets = sorted({item["host"] for item in state.findings
                      if item["kind"] in cleanup_kinds})
    for host in targets:
        if host not in fresh:
            state.errors[host] = "cleanup failed: host could not be read again"

    def cleanup_one(host, out):
        changed = cleanup_host(host, fresh[host], latest_expected, state.context, args, out)
        return reread_after_change(host, args, changed)

    done = repair_parallel([host for host in targets if host in fresh], cleanup_one,
                           args, state.errors, "cleanup")
    for host, (after, reread_error) in done.items():
        if reread_error:
            state.errors[host] = changed_but_unread("cleanup", reread_error)
        if after is not None:
            state.findings = replace_flow_findings(state.findings, host, checks.flows.audit_host(
                host, after, latest_expected, latest_ips, state.context))
