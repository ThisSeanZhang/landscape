//! First-packet (slow-path) matrix of the v4 LAN-ingress worker: scan →
//! neighbour learn → lan_redirect_check (rt4_lan_map rows) → flow verdict /
//! classification → pick_wan → set_cache_in_lan.

use super::*;

// ---------------------------------------------------------------------------
// passthrough / early exits
// ---------------------------------------------------------------------------

#[test]
fn lan_ingress_arp_frame_passes_untouched() {
    load_skel!("tc-lan-flow-arp", skel);
    let mut ctx = lan_ctx();

    let pkt = arp_frame();
    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_OK, "non-IP frames must pass to the stack");
    assert_eq!(out, pkt, "ARP frame must not be modified");
    assert_eq!(mark, 0, "no mark must be written");
    assert!(
        lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_none(),
        "nothing may be learned from a non-IP frame"
    );
}

// NOTE: LD_SCAN_ERR (eth-header read failure) is not reachable under
// PROG_TEST_RUN: the kernel rejects data_size_in < ETH_HLEN before the
// program runs (test_run.c `if (size < ETH_HLEN) return -EINVAL`).

#[test]
fn lan_ingress_ipv6_frame_hands_to_stack() {
    // route4_read_context_from_scan's non-v4 row: an IPv6 frame passes the
    // scan (only ARP/unknown ethertypes stop there) and is rejected by the
    // l3_protocol check — mapped to "pass to the stack" by the worker.
    load_skel!("tc-lan-flow-v6frame", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    let pkt = simple_ipv6_tcp_syn(
        Ipv6Addr::from_str("fd00::10").unwrap(),
        Ipv6Addr::from_str("fd00::20").unwrap(),
    );
    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_OK, "v6 frame must pass the v4 worker");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
    assert!(lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_none());
}

#[test]
fn lan_ingress_broadcast_dst_hands_to_stack() {
    load_skel!("tc-lan-flow-bcast", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    let mut ctx = lan_ctx();

    let pkt = simple_ipv4_tcp(client_addr(), Ipv4Addr::BROADCAST);
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_UNSPEC, "broadcast must hand to the stack (UNSPEC)");
    assert_eq!(mark, 0, "no mark must be written");
    assert!(lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_none());
    assert!(lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        Ipv4Addr::BROADCAST
    )
    .is_none());
}

#[test]
fn lan_ingress_unspecified_and_multicast_dst_hands_to_stack() {
    // is_broadcast_ip4 sub-rows beyond 255.255.255.255: 0.0.0.0 and the
    // 224.0.0.0/4 multicast range are "broadcast-like" for the worker
    // (landscape.h is_broadcast_ip4).
    load_skel!("tc-lan-flow-bcast-subrows", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);

    for dst in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::from_str("224.0.0.1").unwrap()] {
        let pkt = simple_ipv4_tcp(client_addr(), dst);
        let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

        assert_eq!(ret, RET_UNSPEC, "{dst} must hand to the stack like broadcast");
        assert_eq!(mark, 0, "no mark must be written");
    }
    assert!(
        lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_none(),
        "nothing may be learned from broadcast-like frames"
    );
}

// ---------------------------------------------------------------------------
// flow verdict + pick_wan + cache write (the "first request" path)
// ---------------------------------------------------------------------------

#[test]
fn lan_ingress_default_flow_without_slot_target_drops() {
    // Baseline divergence: the TC lan worker drops default-flow traffic when
    // no slot target exists (the XDP twin returns UNSPEC instead).
    load_skel!("tc-lan-flow-default-drop", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    let mut ctx = lan_ctx();

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_SHOT, "default flow without slot target must drop");
    assert_eq!(mark, 0x0200_0000, "mark must carry FLOW_FROM_LAN source only");
    assert!(
        lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_some(),
        "neighbour learning happens before the verdict/lookup"
    );
    assert!(lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr()
    )
    .is_none());
}

#[test]
fn lan_ingress_flow_redirect_populates_lan_cache() {
    load_skel!("tc-lan-flow-redirect", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "no mac rewrite expected for a mac-less slot target");
    assert_eq!(mark, 0x0200_0305, "mark = flow mark + FLOW_FROM_LAN source");
    assert_eq!(forwarded, 1, "pick_wan must set the forwarded cb flag");

    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
    )
    .expect("LAN cache entry must be written after redirect");
    assert_eq!(cache.mark_value, FLOW_REDIRECT_MARK);
    assert_eq!(cache.ifindex, TARGET_IFINDEX);

    let (mac, _dev, ifindex) =
        lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).expect("sender must be learned");
    assert_eq!(mac, CLIENT_MAC);
    assert_eq!(ifindex, WAN_IFINDEX, "learned ifindex must be the ingress ifindex");
}

#[test]
fn lan_ingress_flow_drop_shots_with_untouched_mark() {
    load_skel!("tc-lan-flow-drop", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_DROP_MARK);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "FLOW_DROP rule must drop");
    assert_eq!(mark, 0, "drop returns before the mark-source write");
    assert!(lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_some());
    assert!(lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr()
    )
    .is_none());
}

#[test]
fn lan_ingress_flow_direct_resets_flow_id_to_default() {
    // FLOW_DIRECT semantics: the action survives but the flow id is reset to
    // 0, so pick_wan resolves through flow 0's slots while the ip-trie rule
    // was matched under the *incoming* flow id (5 here, via ctx.mark).
    load_skel!("tc-lan-flow-direct", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    let rules = vec![IpMarkInfo {
        mark: FlowMark::from(FLOW_DIRECT_MARK),
        cidr: IpConfig { ip: IpAddr::V4(remote_wan_addr()), prefix: 32 },
        priority: 100,
    }];
    create_inner_flow_match_map_v4(&skel.maps.flow4_ip_map, 5, &rules).unwrap();
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: WAN_IFINDEX,
        mark: 5, // incoming flow id from an earlier stage
        ..Default::default()
    };
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(mark, 0x0200_0100, "source LAN + DIRECT mark with reset id");

    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
    )
    .expect("LAN cache entry must be written");
    assert_eq!(cache.mark_value, FLOW_DIRECT_MARK, "cached mark must carry the reset id 0");
    assert_eq!(cache.ifindex, TARGET_IFINDEX);
}

#[test]
fn lan_ingress_docker_slot_pushes_vlan_and_redirects() {
    load_skel!("tc-lan-flow-docker", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, true, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // bpf_skb_vlan_push only sets the hwaccel tag under PROG_TEST_RUN (no
    // data growth, vlan_tci not copied back into ctx_out), so the frame must
    // stay byte-identical here.
    assert_eq!(out, pkt);
    assert_eq!(forwarded, 0, "docker branch returns before the forwarded cb flag");

    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
    )
    .expect("LAN cache entry must be written after docker redirect");
    assert_eq!(cache.mark_value, FLOW_REDIRECT_MARK);
    assert_eq!(cache.ifindex, TARGET_IFINDEX);
}

#[test]
fn lan_ingress_flow_redirect_marks_xdp_redirect_able() {
    // route4_set_cache_in_lan insert row: the xdp flag comes from the
    // xdp_redirect_able map (TRUE row).
    load_skel!("tc-lan-flow-xdp-able", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);
    let able: u32 = 1;
    skel.maps
        .xdp_redirect_able
        .update(as_bytes(&TARGET_IFINDEX), as_bytes(&able), MapFlags::ANY)
        .expect("seed xdp_redirect_able[target]");

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
    )
    .expect("LAN cache entry must be written");
    assert_eq!(cache.xdp_redirect_able, 1, "xdp-able target must flag the cache entry");
}

#[test]
fn lan_ingress_flow_redirect_zero_flag_stays_disabled() {
    // FALSE sub-row: an xdp_redirect_able entry with value 0 must not enable
    // the flag (predicate is `able != NULL && *able != 0`).
    load_skel!("tc-lan-flow-xdp-disable", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);
    let disabled: u32 = 0;
    skel.maps
        .xdp_redirect_able
        .update(as_bytes(&TARGET_IFINDEX), as_bytes(&disabled), MapFlags::ANY)
        .expect("seed xdp_redirect_able[target] = 0");

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
    )
    .expect("LAN cache entry must be written");
    assert_eq!(cache.xdp_redirect_able, 0, "present-but-zero entry must stay disabled");
}

// ---------------------------------------------------------------------------
// flow classification (match_flow_id_v4) + DNS rules (route4_flow_verdict)
// ---------------------------------------------------------------------------

// flow_match_map seeding lives in map_helper (seed_flow_match_mac /
// seed_flow_match_ip_v4); the v4 IP key mirrors the BPF construction,
// including the harmless mac[4..6] union-tail leak (see notes there).

/// Seed flow `flow_id`'s ip-trie with a single dst rule.
fn seed_flow_rule_under(skel: &TcLanIngressIntroSkel<'_>, flow_id: u32, dst: Ipv4Addr, mark: u32) {
    let rules = vec![IpMarkInfo {
        mark: FlowMark::from(mark),
        cidr: IpConfig { ip: IpAddr::V4(dst), prefix: 32 },
        priority: 100,
    }];
    create_inner_flow_match_map_v4(&skel.maps.flow4_ip_map, flow_id, &rules).unwrap();
}

#[test]
fn lan_ingress_flow_match_by_src_mac_selects_flow() {
    // match_flow_id_v4 MAC row: the sender's mac classifies the packet into
    // flow 5, whose rules/slots apply even though ctx.mark is 0.
    load_skel!("tc-lan-flow-class-mac", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_match_mac(&skel.maps.flow_match_map, CLIENT_MAC, 5);
    seed_flow_rule_under(&skel, 5, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "mac-classified flow 5 must drive the redirect");
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan_ingress_flow_match_by_src_ip_selects_flow() {
    // match_flow_id_v4 IP row: same classification via the /32 src address.
    load_skel!("tc-lan-flow-class-ip", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_match_ip_v4(&skel.maps.flow_match_map, client_addr(), CLIENT_MAC, 5);
    seed_flow_rule_under(&skel, 5, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "ip-classified flow 5 must drive the redirect");
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan_ingress_flow_match_ip_entry_overrides_mac_entry() {
    // Both lookups run and the IP row is applied last: with mac→5 and ip→7,
    // the packet resolves to flow 7 (which has no rules/slots) and drops,
    // even though flow 5 is fully provisioned.
    load_skel!("tc-lan-flow-class-override", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_match_mac(&skel.maps.flow_match_map, CLIENT_MAC, 5);
    seed_flow_match_ip_v4(&skel.maps.flow_match_map, client_addr(), CLIENT_MAC, 7);
    seed_flow_rule_under(&skel, 5, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "resolved flow 7 has no slots → drop");
    assert_eq!(mark, 0x0200_0007, "mark must carry the ip-resolved flow id 7");
}

#[test]
fn lan_ingress_dns_rule_redirects_when_no_ip_rule() {
    // DNS rule row: with an empty ip-trie, the dns mark alone drives the
    // verdict (and gets cached like a normal redirect).
    load_skel!("tc-lan-flow-dns-only", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V4(remote_wan_addr()),
            mark: FLOW_REDIRECT_MARK,
            priority: 100,
        }],
    );
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "dns-only rule must drive the redirect");
    assert_eq!(mark, 0x0200_0305);
    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
    )
    .expect("dns redirect must populate the lan cache");
    assert_eq!(cache.mark_value, FLOW_REDIRECT_MARK);
}

#[test]
fn lan_ingress_dns_rule_lower_or_equal_priority_wins() {
    // The dns comparison is `dns.priority <= priority`: with equal
    // priorities the dns rule overrides the ip rule.
    load_skel!("tc-lan-flow-dns-wins", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_wan_addr(), FLOW_REDIRECT_MARK); // ip priority 100
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V4(remote_wan_addr()),
            mark: FLOW_DROP_MARK,
            priority: 100, // equal → dns wins
        }],
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "dns rule with equal priority must win");
    assert_eq!(mark, 0, "drop returns before the mark-source write");
}

#[test]
fn lan_ingress_dns_rule_higher_priority_loses_to_ip_rule() {
    load_skel!("tc-lan-flow-dns-loses", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_wan_addr(), FLOW_REDIRECT_MARK); // ip priority 100
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V4(remote_wan_addr()),
            mark: FLOW_DROP_MARK,
            priority: 200, // higher → ip rule wins
        }],
    );
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "lower-priority dns rule must not override");
    assert_eq!(mark, 0x0200_0305);
}

// ---------------------------------------------------------------------------
// rt4_lan_map (lan_redirect_check_in_lan) rows
// ---------------------------------------------------------------------------

#[test]
fn lan_ingress_lan_map_wan_typed_own_addr_hands_to_stack() {
    // F2 WAN row: addr == daddr → UNSPEC straight away.
    load_skel!("tc-lan-flow-wan-own", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        remote_wan_addr(), // addr == daddr
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC);
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
}

#[test]
fn lan_ingress_lan_map_wan_typed_other_falls_to_verdict_drop() {
    // F2 WAN row: addr != daddr → OK, packet continues into the verdict/pick
    // pipeline (and lands in the default-flow drop here).
    load_skel!("tc-lan-flow-wan-other", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.0").unwrap(), // addr != daddr
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "fall-through reaches the default-flow drop");
    assert_eq!(mark, 0x0200_0000, "verdict path stamps the LAN source bits");
}

#[test]
fn lan_ingress_lan_map_has_mac_without_ip_mac_falls_to_neigh() {
    // F2 LAN-type with has_mac but no ip_mac_v4[daddr] → redirect_neigh
    // fallback, no rewrite.
    load_skel!("tc-lan-flow-lan-macmiss", skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
    // no ip_mac_v4 entry for daddr

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
}

#[test]
fn lan_ingress_flow_slot_with_mac_rewrites_header() {
    // Shared pick_wan has_mac branch: dst mac from ip_mac_v4[slot gate],
    // src mac from the slot's own mac.
    load_skel!("tc-lan-flow-slot-mac", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    let target_mac = MacAddr::from_str("02:22:33:44:55:66").unwrap();
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, Some(target_mac));
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, wan_gateway(), gw_mac, gw_dev, TARGET_IFINDEX);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // store_mac_v4(dst = ip_mac[gate_addr].mac, src = slot target mac)
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &target_mac.octets());
    assert_eq!(&out[12..14], &[0x08, 0x00]);
    assert_eq!(mark, 0x0200_0305);
    assert_eq!(forwarded, 1);
}

#[test]
fn lan_ingress_flow_slot_on_ingress_iface_sets_cb_and_redirects() {
    // First-packet pick_wan row: a slot target on the ingress device itself
    // skips the whole rewrite block (guard at tc_lan_ingress_intro.bpf.c:50)
    // but the forwarded cb flag and the plain redirect still happen.
    load_skel!("tc-lan-flow-sameif-slot", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, WAN_IFINDEX, false, None); // == ingress_ifindex

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "same-ingress slot must still redirect");
    assert_eq!(out, pkt, "no rewrite expected for a mac-less slot target");
    assert_eq!(mark, 0x0200_0305);
    assert_eq!(forwarded, 1, "the cb flag is stamped outside the rewrite block");

    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
    )
    .expect("LAN cache entry must be written");
    assert_eq!(cache.ifindex, WAN_IFINDEX);
}

#[test]
fn lan_ingress_flow_slot_with_mac_gateway_miss_falls_to_neigh() {
    // First-packet pick_wan row: has_mac slot whose gate address has no
    // ip_mac_v4 entry → mac_stored stays false, the cb flag is stamped and
    // the packet leaves via bpf_redirect_neigh(gate) without a rewrite.
    load_skel!("tc-lan-flow-gwmiss", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    let target_mac = MacAddr::from_str("02:22:33:44:55:66").unwrap();
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, Some(target_mac));
    // no ip_mac_v4 entry for the slot gate address

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
    assert_eq!(mark, 0x0200_0305);
    assert_eq!(forwarded, 1, "the cb flag is stamped before the neigh fallback");

    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
    )
    .expect("LAN cache entry must be written after the redirect");
    assert_eq!(cache.ifindex, TARGET_IFINDEX);
    assert_eq!(cache.has_mac, 1, "cache mirrors the slot's has_mac even on the neigh path");
}

#[test]
fn lan_ingress_runt_ipv4_frame_passes_to_stack() {
    // read_context truncation row: ethertype claims IPv4 but the IP header is
    // cut short → TC_ACT_SHOT from read_context, which every worker maps to
    // "pass to the stack".
    load_skel!("tc-lan-flow-runt", skel);
    let mut pkt = vec![0xff_u8; 16]; // eth header + 2 bytes of "IP"
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_OK, "truncated IP header must pass, not drop");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
}

#[test]
fn lan_ingress_lan_map_own_addr_hands_to_stack() {
    load_skel!("tc-lan-flow-own-addr", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        remote_wan_addr(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "LAN-typed entry for the target address itself");
    assert_eq!(mark, 0, "lan_redirect short return leaves the mark untouched");
    assert!(lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr()
    )
    .is_none());
}

#[test]
fn lan_ingress_lan_map_other_iface_without_mac_redirects_before_verdict() {
    load_skel!("tc-lan-flow-lan-nomac", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "mac-less LAN entry on another iface plain-redirects");
    assert_eq!(mark, 0, "lan_redirect return path must not touch the mark");
    assert_eq!(forwarded, 0);
    assert!(
        lookup_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            LAN_CACHE,
            client_addr(),
            remote_wan_addr()
        )
        .is_none(),
        "no cache write before pick_wan"
    );
}

#[test]
fn lan_ingress_lan_map_hairpin_rewrites_with_ip_mac() {
    load_skel!("tc-lan-flow-hairpin", skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        WAN_IFINDEX, // == ingress_ifindex under test_run
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
    let host_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, remote_wan_addr(), host_mac, dev_mac, WAN_IFINDEX);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "same-ingress-iface entry with a known host mac");
    // The hairpin branch stores the ip_mac value (mac + dev_mac), not the lan
    // entry mac_addr.
    assert_eq!(&out[0..6], &host_mac.octets());
    assert_eq!(&out[6..12], &dev_mac.octets());
    assert_eq!(&out[12..14], &[0x08, 0x00]);
}

#[test]
fn lan_ingress_lan_map_hairpin_without_ip_mac_is_unspec() {
    load_skel!("tc-lan-flow-hairpin-miss", skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        WAN_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "no ip_mac entry → no rewrite → hand to stack");
    assert_eq!(out, pkt, "packet must stay untouched");
}

#[test]
fn lan_ingress_lan_map_nexthop_resolves_gateway_mac() {
    load_skel!("tc-lan-flow-nexthop", skel);
    let entry_mac = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.1").unwrap(), // nexthop address
        ROUTE_TYPE_NEXTHOP,
        TARGET_IFINDEX,
        true,
        entry_mac,
    );
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v4(
        &skel.maps.ip_mac_v4,
        Ipv4Addr::from_str("192.168.1.1").unwrap(),
        gw_mac,
        gw_dev,
        TARGET_IFINDEX,
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // store_mac_v4(dst = ip_mac[nexthop].mac, src = lan entry mac_addr)
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &entry_mac);
    assert_eq!(&out[12..14], &[0x08, 0x00]);
}
