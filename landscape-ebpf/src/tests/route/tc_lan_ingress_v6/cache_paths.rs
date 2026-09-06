//! Cache fast-path matrix of the v6 LAN-ingress worker
//! (`route6_search_cache_in_lan`): LAN-cache hits (including the
//! zero-ifindex legacy pick_wan handoff) and reply-learned WAN-cache hits.

use super::*;

// ---------------------------------------------------------------------------
// LAN-cache hit (the "second request" fast path)
// ---------------------------------------------------------------------------

#[test]
fn lan6_ingress_lan_cache_hit_short_circuits_without_learning() {
    load_skel!("tc-lan6-cache-hit", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        false,
        0x0305,
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "cache hit must redirect straight away");
    assert_eq!(mark, 0x0200_0305, "mark must come from the cache mark value");
    assert_eq!(forwarded, 0, "cache-hit redirect bypasses pick_wan (no cb flag)");
    assert!(
        lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).is_none(),
        "learning must not run on the cache fast path"
    );
}

#[test]
fn lan6_ingress_lan_cache_hit_with_zero_ifindex_falls_back_to_pick_wan() {
    load_skel!("tc-lan6-cache-zero-if", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        0,
        false,
        0x0305,
    );
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(mark, 0x0200_0305);
    assert_eq!(forwarded, 0, "cache-hit pick_wan bypasses the tc wrapper");

    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .expect("cache entry must survive");
    assert_eq!(cache.ifindex, 0, "cache-hit fast path must not touch the ifindex");
    assert_eq!(
        cache.mark_value, 0x0305,
        "entry untouched: set_cache only runs after fresh pick_wan"
    );
}

#[test]
fn lan6_ingress_lan_cache_same_ifindex_entry_hands_to_stack() {
    load_skel!("tc-lan6-cache-sameif", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        LOOPBACK_IFINDEX,
        false,
        0x0305,
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "cached target on the incoming device must pass");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan6_ingress_lan_cache_has_mac_entry_rewrites_from_gate_ip_mac() {
    load_skel!("tc-lan6-cache-gwmac", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    let entry_mac = [0x02, 0x44, 0x55, 0x66, 0x77, 0x88];
    put_rt6_cache_full(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        true,
        0x0305,
        false,
        gateway_addr(),
        entry_mac,
    );
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, gateway_addr(), gw_mac, gw_dev, TARGET_IFINDEX);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &gw_mac.octets(), "dst = ip_mac[gate_addr].mac");
    assert_eq!(&out[6..12], &entry_mac, "src = cached entry mac");
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan6_ingress_lan_cache_has_mac_entry_without_ip_mac_falls_to_neigh() {
    load_skel!("tc-lan6-cache-gwmiss", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_full(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        true,
        0x0305,
        false,
        gateway_addr(),
        [0x02, 0x44, 0x55, 0x66, 0x77, 0x88],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
}

#[test]
fn lan6_ingress_lan_cache_docker_entry_pushes_vlan_and_redirects() {
    load_skel!("tc-lan6-cache-docker", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_full(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        false,
        0x0305,
        true,
        Ipv6Addr::UNSPECIFIED,
        [0; 6],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan6_ingress_lan_cache_zero_ifindex_same_device_slot_passes() {
    load_skel!("tc-lan6-cache-sameslot", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        0,
        false,
        0x0305,
    );
    seed_wan_slots(&skel, 5, LOOPBACK_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "slot on the incoming device must pass");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan6_ingress_lan_cache_zero_ifindex_without_slot_drops() {
    load_skel!("tc-lan6-cache-noslot", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        0,
        false,
        0x0305,
    );
    // rt6_slot_map intentionally left empty for flow 5

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "non-zero cached flow without slots must drop");
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan6_ingress_lan_cache_zero_ifindex_default_flow_passes() {
    // Legacy pick_wan twin (route6_pick_wan_and_send_by_flow_id) reached via
    // a cache entry with ifindex == 0 and a DEFAULT-flow mark: a flow id 0
    // slot-miss passes (TC_ACT_UNSPEC) — unlike the TC first-packet wrapper
    // which drops the default flow.
    load_skel!("tc-lan6-cache-default-pass", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        0,
        false,
        0, // mark_value 0 → resolved flow id 0 (default flow)
    );
    // rt6_slot_map intentionally left empty for flow 0

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "legacy pick_wan passes default-flow traffic");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0000, "wrapper stamps the LAN source on the search-cache return");
}

#[test]
fn lan6_ingress_set_cache_skipped_when_wan_cache_has_entry() {
    // route6_set_cache_in_lan checks the WAN cache first: a stale entry there
    // (inert during the search, no binding) suppresses the LAN cache write
    // even after a fresh redirect.
    load_skel!("tc-lan6-setcache-wanexist", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        true,
        0,
    );
    // no wan binding → the WAN-cache entry is inert during the search
    seed_flow_rule_under(&skel, 0, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .is_none(),
        "a WAN-cache entry must suppress the LAN cache write"
    );
}

// ---------------------------------------------------------------------------
// WAN-cache hit (reply-learned reverse fast path)
// ---------------------------------------------------------------------------

fn seed_wan_cache(skel: &TcLanIngressIntroSkel<'_>) {
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        true,
        0,
    );
    seed_wan_binding(skel);
}

#[test]
fn lan6_ingress_wan_cache_hit_rewrites_header_from_remote_ip_mac() {
    load_skel!("tc-lan6-wan-cache", skel);
    seed_wan_cache(&skel);

    let next_hop = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, remote_addr(), next_hop, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &next_hop.octets());
    assert_eq!(&out[6..12], &dev_mac.octets());
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
    assert_eq!(mark, 0x0200_0000, "WAN-cache hit keeps the original mark value (0)");
    assert_eq!(forwarded, 0);
}

#[test]
fn lan6_ingress_wan_cache_hit_falls_back_to_gateway_mac() {
    load_skel!("tc-lan6-wan-cache-gw", skel);
    seed_wan_cache(&skel);

    let gateway_mac = MacAddr::from_str("02:66:77:88:99:aa").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ef").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, gateway_addr(), gateway_mac, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &gateway_mac.octets(), "must fall back to the wan gateway mac");
    assert_eq!(&out[6..12], &dev_mac.octets());
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
}

#[test]
fn lan6_ingress_wan_cache_hit_without_any_ip_mac_falls_to_neigh() {
    load_skel!("tc-lan6-wan-cache-neigh", skel);
    seed_wan_cache(&skel);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
}

#[test]
fn lan6_ingress_wan_cache_no_mac_entry_redirects_directly() {
    // route6_search_cache_in_lan !target_has_mac row: a mac-less WAN-cache
    // entry redirects immediately, without touching ip_mac_v6 or the packet.
    load_skel!("tc-lan6-wan-cache-nomac", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        false, // !has_mac
        0,
    );
    seed_wan_binding(&skel);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "mac-less WAN-cache entry redirects directly");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0000, "WAN-cache hit keeps the original mark value (0)");
    assert_eq!(forwarded, 0);
}

#[test]
fn lan6_ingress_wan_cache_hit_without_wan_binding_is_inert() {
    load_skel!("tc-lan6-wan-cache-nobind", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        true,
        0,
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "no binding → WAN-cache entry is inert → default drop");
    assert_eq!(mark, 0x0200_0000);
    assert!(lookup_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr()
    )
    .is_none());
}
