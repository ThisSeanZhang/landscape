//! First-packet (slow-path) matrix of the v6 LAN-ingress worker: scan →
//! neighbour learn → lan_redirect_check (rt6_lan_map rows) → flow verdict /
//! classification → pick_wan → set_cache_in_lan.

use super::*;

// ---------------------------------------------------------------------------
// passthrough / early exits
// ---------------------------------------------------------------------------

#[test]
fn lan6_ingress_arp_frame_passes_untouched() {
    load_skel!("tc-lan6-arp", skel);
    let mut ctx = lan_ctx();

    let pkt = arp_frame();
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_OK, "non-IP frames must pass to the stack");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
    assert!(
        lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).is_none(),
        "nothing may be learned from a non-IP frame"
    );
}

#[test]
fn lan6_ingress_ipv4_frame_hands_to_stack() {
    // route6_read_context_from_scan non-v6 row: an IPv4 frame passes the scan
    // and is rejected by the l3_protocol check.
    load_skel!("tc-lan6-v4frame", skel);
    let pkt = simple_ipv4_tcp(
        Ipv4Addr::from_str("192.168.1.10").unwrap(),
        Ipv4Addr::from_str("10.0.0.20").unwrap(),
    );
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_OK, "v4 frame must pass the v6 worker");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
}

#[test]
fn lan6_ingress_multicast_dst_hands_to_stack() {
    // is_broadcast_ip6 row 1: ff00::/8 multicast.
    load_skel!("tc-lan6-mcast", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    let pkt = simple_ipv6_tcp_syn(local_addr(), Ipv6Addr::from_str("ff02::1").unwrap());
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "multicast must hand to the stack (UNSPEC)");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
    assert!(lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).is_none());
}

#[test]
fn lan6_ingress_link_local_dst_hands_to_stack() {
    // is_broadcast_ip6 row 2 (v6-specific): fe80::/10 link-local targets are
    // never routed by the worker.
    load_skel!("tc-lan6-linklocal", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    let pkt = simple_ipv6_tcp_syn(local_addr(), Ipv6Addr::from_str("fe80::1").unwrap());
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "link-local must hand to the stack (UNSPEC)");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
    assert!(lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).is_none());
}

#[test]
fn lan6_ingress_fe_non_link_local_dst_routes_normally() {
    // is_broadcast_ip6 mask boundary (v6-specific): the link-local check is
    // `(second_byte & 0xc0) == 0x80`, so fec0::/10 ("site-local", fe but not
    // fe80..febf) is NOT intercepted and routes normally.
    load_skel!("tc-lan6-fe-site", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    let pkt = simple_ipv6_tcp_syn(local_addr(), Ipv6Addr::from_str("fec0::1").unwrap());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "fec0:: is not link-local → falls into routing (default drop)");
    assert_eq!(mark, 0x0200_0000);
}

#[test]
fn lan6_ingress_runt_ipv6_frame_passes_to_stack() {
    // read_context truncation row (v6): the ip6 header read requires 40 bytes
    // at l3_offset 14, so the runt threshold is 54 bytes total (vs 34 for v4).
    load_skel!("tc-lan6-runt", skel);
    let mut pkt = vec![0xff_u8; 14 + 20]; // eth + partial ip6 header
    pkt[12] = 0x86;
    pkt[13] = 0xdd;

    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_OK, "truncated ip6 header must pass, not drop");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
}

#[test]
fn lan6_ingress_ext_header_packet_routes_normally() {
    // The route path reads saddr/daddr at fixed offsets in the ip6 header and
    // never walks extension headers: a hop-by-hop header between the ip6 and
    // TCP headers must not change the routing decision.
    load_skel!("tc-lan6-exthdr", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = ipv6_tcp_with_hop_by_hop(local_addr(), remote_addr());
    assert_eq!(pkt[20], 0, "builder sanity: ip6 next_header == hop-by-hop");
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "extension headers must not affect routing");
    assert_eq!(mark, 0x0200_0305);
}

/// Hand-built IPv6 + hop-by-hop + TCP frame (the etherparse builder cannot
/// emit extension headers). next_header 0 (hop-by-hop, 8 bytes), then TCP.
fn ipv6_tcp_with_hop_by_hop(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&CLIENT_MAC); // eth dst
    pkt.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // eth src
    pkt.extend_from_slice(&[0x86, 0xdd]);
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // ver/tc/flow
    pkt.extend_from_slice(&32_u16.to_be_bytes()); // payload_len = 8 hbh + 20 tcp + 4 payload
    pkt.push(0); // next_header = hop-by-hop
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    pkt.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]); // hbh: next=TCP, hdr_ext_len=0
                                                      // TCP header (20 bytes) + 4-byte payload
    pkt.extend_from_slice(&12345_u16.to_be_bytes());
    pkt.extend_from_slice(&443_u16.to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 1]); // seq
    pkt.extend_from_slice(&[0, 0, 0, 1]); // ack
    pkt.extend_from_slice(&[0x50, 0x18]); // data offset 5, PSH|ACK
    pkt.extend_from_slice(&4096_u16.to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 0]); // csum + urg
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    pkt
}

// ---------------------------------------------------------------------------
// flow verdict + pick_wan + cache write (the "first request" path)
// ---------------------------------------------------------------------------

#[test]
fn lan6_ingress_default_flow_without_slot_target_drops() {
    load_skel!("tc-lan6-default-drop", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "default flow without slot target must drop");
    assert_eq!(mark, 0x0200_0000, "mark must carry FLOW_FROM_LAN source only");
    assert!(
        lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).is_some(),
        "neighbour learning happens before the verdict/lookup"
    );
    assert!(lookup_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr()
    )
    .is_none());
}

#[test]
fn lan6_ingress_flow_redirect_populates_lan_cache() {
    load_skel!("tc-lan6-flow-redirect", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "no mac rewrite expected for a mac-less slot target");
    assert_eq!(mark, 0x0200_0305, "mark = flow mark + FLOW_FROM_LAN source");
    assert_eq!(forwarded, 1, "pick_wan must set the forwarded cb flag");

    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .expect("LAN cache entry must be written after redirect");
    assert_eq!(cache.mark_value, FLOW_REDIRECT_MARK);
    assert_eq!(cache.ifindex, TARGET_IFINDEX);

    let (mac, _dev, ifindex) =
        lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).expect("sender must be learned");
    assert_eq!(mac, CLIENT_MAC);
    assert_eq!(ifindex, WAN_IFINDEX, "learned ifindex must be the ingress ifindex");
}

#[test]
fn lan6_ingress_flow_drop_shots_with_untouched_mark() {
    load_skel!("tc-lan6-flow-drop", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_DROP_MARK);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "FLOW_DROP rule must drop");
    assert_eq!(mark, 0, "drop returns before the mark-source write");
    assert!(lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).is_some());
    assert!(lookup_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr()
    )
    .is_none());
}

#[test]
fn lan6_ingress_flow_direct_resets_flow_id_to_default() {
    // Rule matched under the *incoming* flow id (5 via ctx.mark); FLOW_DIRECT
    // resets the id so pick_wan resolves through flow 0's slots.
    load_skel!("tc-lan6-flow-direct", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    let rules = vec![IpMarkInfo {
        mark: FlowMark::from(FLOW_DIRECT_MARK),
        cidr: IpConfig { ip: IpAddr::V6(remote_addr()), prefix: 128 },
        priority: 100,
    }];
    create_inner_flow_match_map_v6(&skel.maps.flow6_ip_map, 5, &rules).unwrap();
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: WAN_IFINDEX,
        mark: 5,
        ..Default::default()
    };
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(mark, 0x0200_0100, "source LAN + DIRECT mark with reset id");

    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .expect("LAN cache entry must be written");
    assert_eq!(cache.mark_value, FLOW_DIRECT_MARK, "cached mark must carry the reset id 0");
    assert_eq!(cache.ifindex, TARGET_IFINDEX);
}

#[test]
fn lan6_ingress_docker_slot_pushes_vlan_and_redirects() {
    load_skel!("tc-lan6-flow-docker", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, true, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "vlan push only sets the hwaccel tag under test_run");
    assert_eq!(forwarded, 0, "docker branch returns before the forwarded cb flag");

    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .expect("LAN cache entry must be written after the docker redirect");
    assert_eq!(cache.mark_value, FLOW_REDIRECT_MARK);
    assert_eq!(cache.ifindex, TARGET_IFINDEX);
}

#[test]
fn lan6_ingress_flow_slot_with_mac_rewrites_header() {
    // Shared pick_wan has_mac branch: store_mac_v6 writes the 86dd ethertype.
    load_skel!("tc-lan6-flow-slot-mac", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    let target_mac = MacAddr::from_str("02:22:33:44:55:66").unwrap();
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, Some(target_mac));
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, gateway_addr(), gw_mac, gw_dev, TARGET_IFINDEX);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &target_mac.octets());
    assert_eq!(&out[12..14], &[0x86, 0xdd], "store_mac_v6 stamps the v6 ethertype");
    assert_eq!(mark, 0x0200_0305);
    assert_eq!(forwarded, 1);
}

#[test]
fn lan6_ingress_flow_slot_on_ingress_iface_sets_cb_and_redirects() {
    // First-packet pick_wan row: a slot target on the ingress device itself
    // skips the rewrite block but the forwarded cb flag and the plain
    // redirect still happen.
    load_skel!("tc-lan6-sameif-slot", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, WAN_IFINDEX, false, None); // == ingress_ifindex

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "same-ingress slot must still redirect");
    assert_eq!(out, pkt, "no rewrite expected for a mac-less slot target");
    assert_eq!(mark, 0x0200_0305);
    assert_eq!(forwarded, 1, "the cb flag is stamped outside the rewrite block");

    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .expect("LAN cache entry must be written");
    assert_eq!(cache.ifindex, WAN_IFINDEX);
}

#[test]
fn lan6_ingress_flow_slot_with_mac_gateway_miss_falls_to_neigh() {
    // First-packet pick_wan row: has_mac slot whose gate address has no
    // ip_mac_v6 entry → cb flag stamped, packet leaves via
    // bpf_redirect_neigh(gate) without a rewrite.
    load_skel!("tc-lan6-flow-gwmiss", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    let target_mac = MacAddr::from_str("02:22:33:44:55:66").unwrap();
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, Some(target_mac));
    // no ip_mac_v6 entry for the slot gate address

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
    assert_eq!(mark, 0x0200_0305);
    assert_eq!(forwarded, 1, "the cb flag is stamped before the neigh fallback");

    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .expect("LAN cache entry must be written after the redirect");
    assert_eq!(cache.ifindex, TARGET_IFINDEX);
    assert_eq!(cache.has_mac, 1, "cache mirrors the slot's has_mac even on the neigh path");
}

// ---------------------------------------------------------------------------
// flow classification (match_flow_id_v6) + DNS rules
// ---------------------------------------------------------------------------

// The MAC-mode seeder is shared with the v4 tests (map_helper::
// seed_flow_match_mac); the v6 IP-mode key below has no v4-style union-tail
// leak (COPY_ADDR_FROM overwrites the full 16 address bytes).

/// v6 IP-mode key: unlike the v4 twin, `match_flow_id_v6` overwrites the full
/// 16 address bytes (COPY_ADDR_FROM), so there is no mac[4..6] union leak —
/// plain ipv6 entries match.
#[allow(clippy::field_reassign_with_default)]
fn seed_flow_match_ip(skel: &TcLanIngressIntroSkel<'_>, addr: Ipv6Addr, flow_id: u32) {
    let mut key = FlowMatchKey::default();
    key.prefixlen = 160; // FLOW_IP_IPV6_MATCH_LEN
    key.l3_protocol = 1; // LANDSCAPE_IPV6_TYPE
    key.is_match_ip = 1; // FLOW_ENTRY_MODE_IP
    key.set_src_ipv6(addr);
    skel.maps
        .flow_match_map
        .update(as_bytes(&key), as_bytes(&flow_id), MapFlags::ANY)
        .expect("insert flow_match ip entry");
}

#[test]
fn lan6_ingress_flow_match_by_src_mac_selects_flow() {
    load_skel!("tc-lan6-class-mac", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_match_mac(&skel.maps.flow_match_map, CLIENT_MAC, 5);
    seed_flow_rule_under(&skel, 5, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "mac-classified flow 5 must drive the redirect");
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan6_ingress_flow_match_by_src_ip_selects_flow() {
    load_skel!("tc-lan6-class-ip", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_match_ip(&skel, local_addr(), 5);
    seed_flow_rule_under(&skel, 5, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "ip-classified flow 5 must drive the redirect");
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan6_ingress_flow_match_ip_entry_overrides_mac_entry() {
    load_skel!("tc-lan6-class-override", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_match_mac(&skel.maps.flow_match_map, CLIENT_MAC, 5);
    seed_flow_match_ip(&skel, local_addr(), 7);
    seed_flow_rule_under(&skel, 5, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "resolved flow 7 has no slots → drop");
    assert_eq!(mark, 0x0200_0007, "mark must carry the ip-resolved flow id 7");
}

#[test]
fn lan6_ingress_dns_rule_redirects_when_no_ip_rule() {
    load_skel!("tc-lan6-dns-only", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    create_flow_dns_inner_map_v6(
        &skel.maps.flow6_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V6(remote_addr()),
            mark: FLOW_REDIRECT_MARK,
            priority: 100,
        }],
    );
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "dns-only rule must drive the redirect");
    assert_eq!(mark, 0x0200_0305);
    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .expect("dns redirect must populate the lan cache");
    assert_eq!(cache.mark_value, FLOW_REDIRECT_MARK);
}

#[test]
fn lan6_ingress_dns_rule_lower_or_equal_priority_wins() {
    load_skel!("tc-lan6-dns-wins", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    create_flow_dns_inner_map_v6(
        &skel.maps.flow6_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V6(remote_addr()),
            mark: FLOW_DROP_MARK,
            priority: 100, // equal → dns wins (`dns.priority <= priority`)
        }],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "dns rule with equal priority must win");
    assert_eq!(mark, 0, "drop returns before the mark-source write");
}

#[test]
fn lan6_ingress_dns_rule_higher_priority_loses_to_ip_rule() {
    load_skel!("tc-lan6-dns-loses", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    create_flow_dns_inner_map_v6(
        &skel.maps.flow6_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V6(remote_addr()),
            mark: FLOW_DROP_MARK,
            priority: 200, // higher → ip rule wins
        }],
    );
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "lower-priority dns rule must not override");
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan6_ingress_flow_redirect_marks_xdp_redirect_able() {
    // route6_set_cache_in_lan insert row (TRUE row of the xdp flag).
    load_skel!("tc-lan6-xdp-able", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);
    let able: u32 = 1;
    skel.maps
        .xdp_redirect_able
        .update(as_bytes(&TARGET_IFINDEX), as_bytes(&able), MapFlags::ANY)
        .expect("seed xdp_redirect_able[target]");

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .expect("LAN cache entry must be written");
    assert_eq!(cache.xdp_redirect_able, 1, "xdp-able target must flag the cache entry");
}

#[test]
fn lan6_ingress_flow_redirect_zero_flag_stays_disabled() {
    // FALSE sub-row of route6_set_cache_in_lan: a present-but-zero
    // xdp_redirect_able entry must not enable the flag
    // (predicate: `able != NULL && *able != 0`).
    load_skel!("tc-lan6-xdp-disable", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);
    let disabled: u32 = 0;
    skel.maps
        .xdp_redirect_able
        .update(as_bytes(&TARGET_IFINDEX), as_bytes(&disabled), MapFlags::ANY)
        .expect("seed xdp_redirect_able[target] = 0");

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .expect("LAN cache entry must be written");
    assert_eq!(cache.xdp_redirect_able, 0, "present-but-zero entry must stay disabled");
}

// ---------------------------------------------------------------------------
// rt6_lan_map (lan_redirect_check_in_lan) rows
// ---------------------------------------------------------------------------

#[test]
fn lan6_ingress_lan_map_own_addr_hands_to_stack() {
    load_skel!("tc-lan6-own-addr", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        remote_addr(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "LAN-typed entry for the target address itself");
    assert_eq!(mark, 0, "lan_redirect short return leaves the mark untouched");
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .is_none(),
        "no cache write before pick_wan"
    );
}

#[test]
fn lan6_ingress_lan_map_wan_typed_own_addr_hands_to_stack() {
    // F2 WAN row: addr == daddr → UNSPEC straight away.
    load_skel!("tc-lan6-wan-own", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        remote_addr(),
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC);
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
}

#[test]
fn lan6_ingress_lan_map_wan_typed_other_falls_to_verdict_drop() {
    load_skel!("tc-lan6-wan-other", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::99").unwrap(), // addr != daddr
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "fall-through reaches the default-flow drop");
    assert_eq!(mark, 0x0200_0000, "verdict path stamps the LAN source bits");
}

#[test]
fn lan6_ingress_lan_map_other_iface_without_mac_redirects_before_verdict() {
    load_skel!("tc-lan6-lan-nomac", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "mac-less LAN entry on another iface plain-redirects");
    assert_eq!(mark, 0, "lan_redirect return path must not touch the mark");
    assert_eq!(forwarded, 0);
}

#[test]
fn lan6_ingress_lan_map_has_mac_without_ip_mac_falls_to_neigh() {
    load_skel!("tc-lan6-lan-macmiss", skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
}

#[test]
fn lan6_ingress_lan_map_hairpin_rewrites_with_ip_mac() {
    // F2 same-iface branch compares skb->ingress_ifindex (6 here).
    load_skel!("tc-lan6-hairpin", skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        WAN_IFINDEX, // == ingress_ifindex under test_run
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
    let host_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, remote_addr(), host_mac, dev_mac, WAN_IFINDEX);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "same-ingress-iface entry with a known host mac");
    assert_eq!(&out[0..6], &host_mac.octets());
    assert_eq!(&out[6..12], &dev_mac.octets());
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
}

#[test]
fn lan6_ingress_lan_map_hairpin_without_ip_mac_is_unspec() {
    load_skel!("tc-lan6-hairpin-miss", skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        WAN_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "no ip_mac entry → no rewrite → hand to stack");
    assert_eq!(out, pkt, "packet must stay untouched");
}

#[test]
fn lan6_ingress_lan_map_hairpin_zero_addr_is_unspec() {
    // F2 same-iface condition row (v6): `ip_addr_is_zero_in6(addr)` skips the
    // mac-rewrite attempt for entries with addr = :: even when has_mac.
    load_skel!("tc-lan6-hairpin-zero", skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::UNSPECIFIED, // addr == ::
        LAN_ROUTE_TYPE,
        WAN_IFINDEX, // == ingress_ifindex under test_run
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "zero-addr entry must hand to the stack");
    assert_eq!(out, pkt, "no rewrite attempted");
}

#[test]
fn lan6_ingress_lan_map_nexthop_resolves_gateway_mac() {
    load_skel!("tc-lan6-nexthop", skel);
    let entry_mac = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::1").unwrap(), // nexthop address
        ROUTE_TYPE_NEXTHOP,
        TARGET_IFINDEX,
        true,
        entry_mac,
    );
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v6(
        &skel.maps.ip_mac_v6,
        Ipv6Addr::from_str("fd00::1").unwrap(),
        gw_mac,
        gw_dev,
        TARGET_IFINDEX,
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // store_mac_v6(dst = ip_mac[nexthop].mac, src = lan entry mac_addr)
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &entry_mac);
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
}
