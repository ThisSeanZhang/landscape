//! Per-WAN-link kernel IPv4 policy routing for `SkipRoute`-marked sockets.
//!
//! Each active IPv4 WAN link with an assigned `link_chain_id` gets:
//! - a dedicated kernel routing table (`SKIP_ROUTE_TABLE_BASE + chain_id`)
//!   containing its default route (`via <gw> dev <ifindex> src <ip> onlink`, or
//!   `dev <ifindex> src <ip>` for point-to-point `dev_only_nexthop` links), and
//! - a single IPv4 policy rule (`pref 10000 fwmark SkipRoute(chain_id)/0xffffffff
//!   lookup <table>`) evaluated before `main` (32766) and after `local` (0).
//!
//! This keeps non-default WAN health probes (and recovery probes for a failed
//! primary WAN) independent of the `main` table's default route without
//! polluting `main` or colliding with regular forwarded traffic.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use futures::TryStreamExt;
use landscape_common::flow::mark::SocketMark;
use landscape_common::sys_service::route_service::WanRouteTarget;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::route::{
    RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
};
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleHeader, RuleMessage};
use rtnetlink::{IpVersion, RouteMessageBuilder};

/// Base Linux routing table ID reserved for per-WAN `SkipRoute` IPv4 tables.
/// Valid WAN chain IDs (`1..=1023`) map to `10001..=11023`, staying clear of
/// reserved tables (`0`, `253..=255`) and common user/VPN tables.
pub const SKIP_ROUTE_TABLE_BASE: u32 = 10_000;

/// Fixed IPv4 `ip rule` priority for Landscape-managed `SkipRoute` rules:
/// strictly after `local` (`0`) and strictly before `main` (`32766`).
pub const SKIP_ROUTE_RULE_PRIORITY: u32 = 10_000;

const NETLINK_ENOENT: i32 = -libc::ENOENT;
const NETLINK_ESRCH: i32 = -libc::ESRCH;
const NETLINK_EEXIST: i32 = -libc::EEXIST;

/// Map a WAN link's `chain_id` to its dedicated Linux routing table ID.
/// Chain `0` means unassigned and has no policy table.
pub const fn skip_route_table_id(chain_id: u16) -> Option<u32> {
    if chain_id == 0 { None } else { Some(SKIP_ROUTE_TABLE_BASE + chain_id as u32) }
}

/// Build the canonical IPv4 `RuleMessage` for `chain_id`:
/// `pref 10000 fwmark SkipRoute(chain_id)/0xffffffff lookup (10000 + chain_id)`.
pub fn build_skip_route_rule_message(chain_id: u16) -> Option<RuleMessage> {
    let table_id = skip_route_table_id(chain_id)?;
    let mark = u32::from(SocketMark::skip_route(chain_id));

    let mut msg = RuleMessage::default();
    msg.header = RuleHeader {
        family: AddressFamily::Inet,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: RouteHeader::RT_TABLE_UNSPEC,
        action: RuleAction::ToTable,
        ..Default::default()
    };
    msg.attributes = vec![
        RuleAttribute::Priority(SKIP_ROUTE_RULE_PRIORITY),
        RuleAttribute::FwMark(mark),
        RuleAttribute::FwMask(u32::MAX),
        RuleAttribute::Table(table_id),
    ];
    Some(msg)
}

/// Build the IPv4 default `RouteMessage` installed inside `chain_id`'s
/// dedicated routing table.
pub fn build_skip_route_route_message(target: &WanRouteTarget) -> Option<RouteMessage> {
    let table_id = skip_route_table_id(target.link_chain_id)?;
    if target.info.ifindex == 0 {
        return None;
    }

    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
        .table_id(table_id)
        .output_interface(target.info.ifindex)
        .protocol(RouteProtocol::Static);

    if target.info.dev_only_nexthop {
        builder = builder.scope(RouteScope::Link);
    } else {
        let IpAddr::V4(gateway) = target.info.gateway_ip else {
            return None;
        };
        if gateway.is_unspecified() {
            return None;
        }
        // `onlink` handles both connected subnets and `/32` peer/host links
        // (e.g. native PPPoE `local peer gw/32` or `/32` DHCPv4 leases).
        builder = builder.scope(RouteScope::Universe).gateway(gateway).onlink();
    }

    if let IpAddr::V4(iface_ip) = target.info.iface_ip
        && !iface_ip.is_unspecified()
    {
        builder = builder.pref_source(iface_ip);
    }

    let mut msg = builder.build();
    // Match iproute2 wire format: `RTA_TABLE` holds IDs > 255 while `rtm_table` stays 0.
    if table_id > u32::from(u8::MAX) {
        msg.header.table = RouteHeader::RT_TABLE_UNSPEC;
    }
    Some(msg)
}

/// Recognize an IPv4 `RuleMessage` owned by Landscape's `SkipRoute` policy
/// routing and return its `chain_id`. Any rule with extra selectors, a custom
/// mask, a different priority, or a mismatched table returns `None` and is
/// never modified.
pub fn parse_managed_skip_route_rule(msg: &RuleMessage) -> Option<u16> {
    if msg.header.family != AddressFamily::Inet
        || msg.header.action != RuleAction::ToTable
        || msg.header.dst_len != 0
        || msg.header.src_len != 0
        || msg.header.tos != 0
        || !msg.header.flags.is_empty()
    {
        return None;
    }

    let mut priority: Option<u32> = None;
    let mut fwmark: Option<u32> = None;
    let mut fwmask: Option<u32> = None;
    let mut table: Option<u32> = None;

    for attr in &msg.attributes {
        match attr {
            RuleAttribute::Priority(p) => priority = Some(*p),
            RuleAttribute::FwMark(m) => fwmark = Some(*m),
            RuleAttribute::FwMask(m) => fwmask = Some(*m),
            RuleAttribute::Table(t) => table = Some(*t),
            // Linux includes unsuppressed sentinel values (`-1`) and protocol
            // metadata in `RTM_GETRULE` dumps even for plain fwmark rules.
            RuleAttribute::SuppressPrefixLen(u32::MAX)
            | RuleAttribute::SuppressIfGroup(u32::MAX)
            | RuleAttribute::Protocol(_) => {}
            _ => return None,
        }
    }

    if priority != Some(SKIP_ROUTE_RULE_PRIORITY) {
        return None;
    }
    if !matches!(fwmask, None | Some(u32::MAX)) {
        return None;
    }
    let mark = fwmark?;
    let chain_id = SocketMark::from(mark).skip_route_chain_id()?;
    let expected_table = skip_route_table_id(chain_id)?;
    let actual_table = table.unwrap_or(u32::from(msg.header.table));
    if actual_table != expected_table {
        return None;
    }

    Some(chain_id)
}

fn route_table_id(msg: &RouteMessage) -> u32 {
    msg.attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Table(t) => Some(*t),
            _ => None,
        })
        .unwrap_or(u32::from(msg.header.table))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PolicyReconcilePlan {
    pub(crate) add_rules: Vec<u16>,
    /// One entry per duplicate or stale managed rule deletion to issue.
    pub(crate) del_rules: Vec<u16>,
    /// Mapping of `table_id -> chain_id` for stale tables whose routes must be purged.
    pub(crate) del_route_tables: BTreeMap<u32, u16>,
}

/// Compute the minimal, idempotent rule and table-cleanup operations needed to
/// converge kernel policy rules to `desired_chains`.
pub(crate) fn plan_policy_reconcile(
    existing_rules: &[RuleMessage],
    previous_chains: &BTreeSet<u16>,
    desired_chains: &BTreeSet<u16>,
) -> PolicyReconcilePlan {
    let mut existing_counts: BTreeMap<u16, usize> = BTreeMap::new();
    for rule in existing_rules {
        if let Some(chain_id) = parse_managed_skip_route_rule(rule) {
            *existing_counts.entry(chain_id).or_default() += 1;
        }
    }

    let mut plan = PolicyReconcilePlan::default();

    for &chain_id in desired_chains {
        match existing_counts.get(&chain_id).copied().unwrap_or(0) {
            0 => plan.add_rules.push(chain_id),
            1 => {}
            extra => {
                for _ in 0..(extra - 1) {
                    plan.del_rules.push(chain_id);
                }
            }
        }
    }

    for (&chain_id, &count) in &existing_counts {
        if !desired_chains.contains(&chain_id) {
            for _ in 0..count {
                plan.del_rules.push(chain_id);
            }
            if let Some(table_id) = skip_route_table_id(chain_id) {
                plan.del_route_tables.insert(table_id, chain_id);
            }
        }
    }

    for &chain_id in previous_chains {
        if !desired_chains.contains(&chain_id)
            && let Some(table_id) = skip_route_table_id(chain_id)
        {
            plan.del_route_tables.insert(table_id, chain_id);
        }
    }

    plan
}

fn is_netlink_missing(err: &rtnetlink::Error) -> bool {
    matches!(
        err,
        rtnetlink::Error::NetlinkError(msg)
            if msg.raw_code() == NETLINK_ENOENT || msg.raw_code() == NETLINK_ESRCH
    )
}

fn is_netlink_exists(err: &rtnetlink::Error) -> bool {
    matches!(err, rtnetlink::Error::NetlinkError(msg) if msg.raw_code() == NETLINK_EEXIST)
}

/// Synchronize per-WAN IPv4 `SkipRoute` policy routes and rules via rtnetlink.
/// Returns `false` when any netlink operation fails so the caller's reconcile
/// loop keeps its cache dirty and retries.
pub async fn sync_kernel_wan_policy_ipv4(
    targets: &[WanRouteTarget],
    last_chains: &Mutex<BTreeSet<u16>>,
) -> bool {
    let (connection, handle, _) = match rtnetlink::new_connection() {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("open rtnetlink connection for WAN policy routes failed: {e:?}");
            return false;
        }
    };
    let conn_task = tokio::spawn(connection);

    let result = sync_with_handle(&handle, targets, last_chains).await;

    drop(handle);
    conn_task.abort();
    result
}

async fn sync_with_handle(
    handle: &rtnetlink::Handle,
    targets: &[WanRouteTarget],
    last_chains: &Mutex<BTreeSet<u16>>,
) -> bool {
    let mut all_ok = true;
    let mut desired_chains = BTreeSet::new();
    let mut route_ok_chains = BTreeSet::new();

    // 1. Replace per-chain default routes first so rules never point to empty tables.
    for target in targets {
        let Some(route_msg) = build_skip_route_route_message(target) else {
            continue;
        };
        let chain_id = target.link_chain_id;
        desired_chains.insert(chain_id);

        match handle.route().add(route_msg).replace().execute().await {
            Ok(()) => {
                route_ok_chains.insert(chain_id);
            }
            Err(e) => {
                tracing::error!(
                    chain_id,
                    iface = %target.info.iface_name,
                    gateway = %target.info.gateway_ip,
                    "replace SkipRoute IPv4 policy route failed: {e:?}"
                );
                all_ok = false;
            }
        }
    }

    // 2. Inspect existing IPv4 policy rules and compute minimal delta.
    let existing_rules: Vec<RuleMessage> =
        match handle.rule().get(IpVersion::V4).execute().try_collect().await {
            Ok(rules) => rules,
            Err(e) => {
                tracing::error!("dump IPv4 policy rules failed: {e:?}");
                return false;
            }
        };

    let previous_chains = last_chains.lock().unwrap().clone();
    let plan = plan_policy_reconcile(&existing_rules, &previous_chains, &desired_chains);
    let mut retry_cleanup_chains = BTreeSet::new();

    // 3. Delete duplicate or stale rules before purging stale tables.
    for chain_id in plan.del_rules {
        let Some(rule_msg) = build_skip_route_rule_message(chain_id) else {
            continue;
        };
        match handle.rule().del(rule_msg).execute().await {
            Ok(()) => {}
            Err(e) if is_netlink_missing(&e) => {}
            Err(e) => {
                tracing::error!(chain_id, "delete SkipRoute IPv4 policy rule failed: {e:?}");
                all_ok = false;
                if !desired_chains.contains(&chain_id) {
                    retry_cleanup_chains.insert(chain_id);
                }
            }
        }
    }

    // 4. Add missing rules for links whose policy route is installed.
    for chain_id in plan.add_rules {
        if !route_ok_chains.contains(&chain_id) {
            continue;
        }
        let Some(rule_msg) = build_skip_route_rule_message(chain_id) else {
            continue;
        };
        let mut req = handle.rule().add().v4();
        *req.message_mut() = rule_msg;
        match req.execute().await {
            Ok(()) => {}
            Err(e) if is_netlink_exists(&e) => {}
            Err(e) => {
                tracing::error!(chain_id, "add SkipRoute IPv4 policy rule failed: {e:?}");
                all_ok = false;
            }
        }
    }

    // 5. Purge any remaining routes from removed/stale policy tables.
    if !plan.del_route_tables.is_empty() {
        let query = RouteMessageBuilder::<Ipv4Addr>::new().build();
        match handle.route().get(query).execute().try_collect::<Vec<RouteMessage>>().await {
            Ok(routes) => {
                for route in routes {
                    let table_id = route_table_id(&route);
                    let Some(&chain_id) = plan.del_route_tables.get(&table_id) else {
                        continue;
                    };
                    match handle.route().del(route).execute().await {
                        Ok(()) => {}
                        Err(e) if is_netlink_missing(&e) => {}
                        Err(e) => {
                            tracing::error!(
                                chain_id,
                                table_id,
                                "delete stale SkipRoute IPv4 policy route failed: {e:?}"
                            );
                            all_ok = false;
                            retry_cleanup_chains.insert(chain_id);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("dump IPv4 routes for stale policy table cleanup failed: {e:?}");
                all_ok = false;
                retry_cleanup_chains.extend(plan.del_route_tables.values().copied());
            }
        }
    }

    let mut tracked = desired_chains;
    tracked.extend(retry_cleanup_chains);
    *last_chains.lock().unwrap() = tracked;

    all_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::flow::mark::{FlowMark, FlowMarkAction, MarkType};
    use landscape_common::sys_service::route_service::RouteTargetInfo;
    use netlink_packet_route::route::{RouteAddress, RouteFlags};
    use netlink_packet_route::rule::RuleFlags;

    fn kernel_style_rule(chain_id: u16, include_fwmask: bool) -> RuleMessage {
        let table_id = skip_route_table_id(chain_id).unwrap();
        let mut attrs = vec![
            RuleAttribute::Table(table_id),
            RuleAttribute::SuppressPrefixLen(u32::MAX),
            RuleAttribute::Protocol(RouteProtocol::Unspec),
            RuleAttribute::Priority(SKIP_ROUTE_RULE_PRIORITY),
            RuleAttribute::FwMark(u32::from(SocketMark::skip_route(chain_id))),
        ];
        if include_fwmask {
            attrs.push(RuleAttribute::FwMask(u32::MAX));
        }
        let mut msg = RuleMessage::default();
        msg.header = RuleHeader {
            family: AddressFamily::Inet,
            table: RouteHeader::RT_TABLE_UNSPEC,
            action: RuleAction::ToTable,
            ..Default::default()
        };
        msg.attributes = attrs;
        msg
    }

    #[test]
    fn table_ids_are_unique_and_disjoint_from_reserved_linux_tables() {
        assert_eq!(skip_route_table_id(0), None);
        let mut seen = BTreeSet::new();
        for chain_id in 1..=1023u16 {
            let table = skip_route_table_id(chain_id).expect("valid chain");
            assert_eq!(table, SKIP_ROUTE_TABLE_BASE + u32::from(chain_id));
            assert!(!matches!(table, 0 | 253 | 254 | 255));
            assert!(seen.insert(table), "duplicate table id {table}");
        }
    }

    #[test]
    fn build_route_message_handles_pppoe_gateway_and_p2p_dev_only() {
        let pppoe = WanRouteTarget::link(
            3,
            RouteTargetInfo::new_gateway_v4(
                37,
                "enp1s0.101",
                None,
                Ipv4Addr::new(100, 65, 247, 59),
                Ipv4Addr::new(100, 65, 0, 1),
                false,
            ),
        );
        let msg = build_skip_route_route_message(&pppoe).expect("pppoe route message");
        assert_eq!(msg.header.address_family, AddressFamily::Inet);
        assert_eq!(msg.header.destination_prefix_length, 0);
        assert_eq!(msg.header.table, RouteHeader::RT_TABLE_UNSPEC);
        assert_eq!(msg.header.scope, RouteScope::Universe);
        assert!(msg.header.flags.contains(RouteFlags::Onlink));
        assert!(msg.attributes.contains(&RouteAttribute::Table(10_003)));
        assert!(msg.attributes.contains(&RouteAttribute::Oif(37)));
        assert!(
            msg.attributes.contains(&RouteAttribute::Gateway(RouteAddress::Inet(Ipv4Addr::new(
                100, 65, 0, 1
            ))))
        );
        assert!(msg.attributes.contains(&RouteAttribute::PrefSource(RouteAddress::Inet(
            Ipv4Addr::new(100, 65, 247, 59)
        ))));

        let pppd = WanRouteTarget::link(
            4,
            RouteTargetInfo::new_p2p_v4(
                40,
                "ppp0",
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 1),
                false,
            ),
        );
        let msg = build_skip_route_route_message(&pppd).expect("pppd route message");
        assert_eq!(msg.header.scope, RouteScope::Link);
        assert!(!msg.header.flags.contains(RouteFlags::Onlink));
        assert!(msg.attributes.contains(&RouteAttribute::Table(10_004)));
        assert!(msg.attributes.contains(&RouteAttribute::Oif(40)));
        assert!(!msg.attributes.iter().any(|a| matches!(a, RouteAttribute::Gateway(_))));
        assert!(
            msg.attributes.contains(&RouteAttribute::PrefSource(RouteAddress::Inet(
                Ipv4Addr::new(10, 0, 0, 2)
            )))
        );

        // Unassigned chain or zero ifindex is rejected.
        let mut bad = pppoe.clone();
        bad.link_chain_id = 0;
        assert!(build_skip_route_route_message(&bad).is_none());
        let mut no_if = pppoe;
        no_if.info.ifindex = 0;
        assert!(build_skip_route_route_message(&no_if).is_none());
    }

    #[test]
    fn parse_managed_rule_matches_canonical_and_kernel_dumps_only() {
        let canonical = build_skip_route_rule_message(3).unwrap();
        assert!(canonical.attributes.contains(&RuleAttribute::FwMark(0x0200_0003)));
        assert_eq!(parse_managed_skip_route_rule(&canonical), Some(3));
        assert_eq!(parse_managed_skip_route_rule(&kernel_style_rule(2, true)), Some(2));
        assert_eq!(parse_managed_skip_route_rule(&kernel_style_rule(3, false)), Some(3));

        // Non-managed: different priority.
        let mut wrong_prio = kernel_style_rule(3, true);
        wrong_prio.attributes.retain(|a| !matches!(a, RuleAttribute::Priority(_)));
        wrong_prio.attributes.push(RuleAttribute::Priority(32766));
        assert_eq!(parse_managed_skip_route_rule(&wrong_prio), None);

        // Non-managed: partial fwmask.
        let mut partial_mask = kernel_style_rule(3, true);
        partial_mask.attributes.retain(|a| !matches!(a, RuleAttribute::FwMask(_)));
        partial_mask.attributes.push(RuleAttribute::FwMask(0x00ff));
        assert_eq!(parse_managed_skip_route_rule(&partial_mask), None);

        // Non-managed: Normal-layout fwmark.
        let mut normal_mark = kernel_style_rule(3, true);
        normal_mark.attributes.retain(|a| !matches!(a, RuleAttribute::FwMark(_)));
        normal_mark.attributes.push(RuleAttribute::FwMark(u32::from(SocketMark::new(
            MarkType::Normal(FlowMark::new(FlowMarkAction::Redirect, 3, false)),
            0,
        ))));
        assert_eq!(parse_managed_skip_route_rule(&normal_mark), None);

        // Non-managed: SkipRouteAndStage (tag=1) or SkipAll (tag=3) fwmark.
        let mut skip_stage_mark = kernel_style_rule(3, true);
        skip_stage_mark.attributes.retain(|a| !matches!(a, RuleAttribute::FwMark(_)));
        skip_stage_mark.attributes.push(RuleAttribute::FwMark(u32::from(SocketMark::new(
            MarkType::SkipRouteAndStage { chain_id: 3 },
            0,
        ))));
        assert_eq!(parse_managed_skip_route_rule(&skip_stage_mark), None);

        let mut skip_all_mark = kernel_style_rule(3, true);
        skip_all_mark.attributes.retain(|a| !matches!(a, RuleAttribute::FwMark(_)));
        skip_all_mark.attributes.push(RuleAttribute::FwMark(u32::from(SocketMark::new(
            MarkType::SkipAll { chain_id: 3 },
            0,
        ))));
        assert_eq!(parse_managed_skip_route_rule(&skip_all_mark), None);

        // Non-managed: mismatched table ID.
        let mut wrong_table = kernel_style_rule(3, true);
        wrong_table.attributes.retain(|a| !matches!(a, RuleAttribute::Table(_)));
        wrong_table.attributes.push(RuleAttribute::Table(10_009));
        assert_eq!(parse_managed_skip_route_rule(&wrong_table), None);

        // Non-managed: extra selector or invert flag.
        let mut with_iif = kernel_style_rule(3, true);
        with_iif.attributes.push(RuleAttribute::Iifname("br0".to_string()));
        assert_eq!(parse_managed_skip_route_rule(&with_iif), None);

        let mut with_suppress = kernel_style_rule(3, true);
        with_suppress.attributes.retain(|a| !matches!(a, RuleAttribute::SuppressPrefixLen(_)));
        with_suppress.attributes.push(RuleAttribute::SuppressPrefixLen(8));
        assert_eq!(parse_managed_skip_route_rule(&with_suppress), None);

        let mut inverted = kernel_style_rule(3, true);
        inverted.header.flags.insert(RuleFlags::Invert);
        assert_eq!(parse_managed_skip_route_rule(&inverted), None);
    }

    #[test]
    fn reconcile_planner_is_idempotent_dedups_and_cleans_stale_tables() {
        let empty = BTreeSet::new();
        let active_2_3 = BTreeSet::from([2u16, 3u16]);

        // 1. Cold start: adds rules for chains 2 and 3.
        let plan = plan_policy_reconcile(&[], &empty, &active_2_3);
        assert_eq!(plan.add_rules, vec![2, 3]);
        assert!(plan.del_rules.is_empty());
        assert!(plan.del_route_tables.is_empty());

        // 2. Steady state with one rule per chain: complete no-op.
        let steady_rules = vec![kernel_style_rule(2, true), kernel_style_rule(3, false)];
        let plan = plan_policy_reconcile(&steady_rules, &active_2_3, &active_2_3);
        assert_eq!(plan, PolicyReconcilePlan::default());

        // 3. Duplicate rule for chain 3: deletes exactly the extra copy without dropping table 10003.
        let dup_rules = vec![
            kernel_style_rule(2, true),
            kernel_style_rule(3, true),
            kernel_style_rule(3, true),
        ];
        let plan = plan_policy_reconcile(&dup_rules, &active_2_3, &active_2_3);
        assert!(plan.add_rules.is_empty());
        assert_eq!(plan.del_rules, vec![3]);
        assert!(plan.del_route_tables.is_empty());

        // 4. WAN2 goes down: deletes chain 3's rule and purges table 10003, keeping chain 2 intact.
        let active_2 = BTreeSet::from([2u16]);
        let plan = plan_policy_reconcile(&steady_rules, &active_2_3, &active_2);
        assert!(plan.add_rules.is_empty());
        assert_eq!(plan.del_rules, vec![3]);
        assert_eq!(plan.del_route_tables, BTreeMap::from([(10_003, 3)]));

        // 5. Crash recovery on startup (`previous_chains` empty, `desired` empty, leftover rules in kernel).
        let plan = plan_policy_reconcile(&steady_rules, &empty, &empty);
        assert!(plan.add_rules.is_empty());
        assert_eq!(plan.del_rules, vec![2, 3]);
        assert_eq!(plan.del_route_tables, BTreeMap::from([(10_002, 2), (10_003, 3)]));

        // 6. Previously tracked chain whose rule was already absent still purges its orphaned table.
        let plan = plan_policy_reconcile(&[], &active_2_3, &active_2);
        assert_eq!(plan.add_rules, vec![2]);
        assert!(plan.del_rules.is_empty());
        assert_eq!(plan.del_route_tables, BTreeMap::from([(10_003, 3)]));
    }
}
