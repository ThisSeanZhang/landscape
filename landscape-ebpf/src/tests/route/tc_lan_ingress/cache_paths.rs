//! Cache fast-path matrix of the v4 LAN-ingress worker
//! (`route4_search_cache_in_lan`): LAN-cache hits (including the
//! zero-ifindex legacy pick_wan handoff) and reply-learned WAN-cache hits.

use super::*;

// ---------------------------------------------------------------------------
// LAN-cache hit (the "second request" fast path)
// ---------------------------------------------------------------------------

#[test]
fn lan_ingress_lan_cache_hit_short_circuits_without_learning() {
    load_skel!("tc-lan-flow-cache-hit", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        TARGET_IFINDEX,
        false,
        0x0305,
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "cache hit must redirect straight away");
    assert_eq!(mark, 0x0200_0305, "mark must come from the cache mark value");
    assert_eq!(forwarded, 0, "cache-hit redirect bypasses pick_wan (no cb flag)");
    assert!(
        lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_none(),
        "learning must not run on the cache fast path"
    );
}

#[test]
fn lan_ingress_lan_cache_hit_with_zero_ifindex_falls_back_to_pick_wan() {
    load_skel!("tc-lan-flow-cache-zero-if", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        0,
        false,
        0x0305,
    );
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(mark, 0x0200_0305);
    assert_eq!(forwarded, 0, "cache-hit pick_wan bypasses the tc wrapper, so no cb flag is set");

    let cache = lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
    )
    .expect("cache entry must survive");
    assert_eq!(cache.ifindex, 0, "cache-hit fast path must not touch the ifindex");
    assert_eq!(
        cache.mark_value, 0x0305,
        "set_cache_in_lan only runs after a fresh pick_wan, so the entry is untouched"
    );
}

#[test]
fn lan_ingress_lan_cache_same_ifindex_entry_hands_to_stack() {
    // route4_redirect_by_cached_target: ifindex == skb->ifindex → UNSPEC, but
    // the early-return wrapper still stamps the mark.
    load_skel!("tc-lan-flow-cache-sameif", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        LOOPBACK_IFINDEX,
        false,
        0x0305,
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "cached target on the incoming device must pass");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan_ingress_lan_cache_has_mac_entry_rewrites_from_gate_ip_mac() {
    // route4_redirect_by_cached_target has_mac branch: dst mac comes from
    // ip_mac_v4[gate_addr], src mac from the cached entry.
    load_skel!("tc-lan-flow-cache-gwmac", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    let entry_mac = [0x02, 0x44, 0x55, 0x66, 0x77, 0x88];
    put_rt4_cache_full(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        TARGET_IFINDEX,
        true,
        0x0305,
        false,
        wan_gateway(),
        entry_mac,
    );
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, wan_gateway(), gw_mac, gw_dev, TARGET_IFINDEX);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &gw_mac.octets(), "dst = ip_mac[gate_addr].mac");
    assert_eq!(&out[6..12], &entry_mac, "src = cached entry mac");
    assert_eq!(&out[12..14], &[0x08, 0x00]);
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan_ingress_lan_cache_has_mac_entry_without_ip_mac_falls_to_neigh() {
    load_skel!("tc-lan-flow-cache-gwmiss", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_full(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        TARGET_IFINDEX,
        true,
        0x0305,
        false,
        wan_gateway(),
        [0x02, 0x44, 0x55, 0x66, 0x77, 0x88],
    );
    // no ip_mac_v4 entries at all → bpf_redirect_neigh(gate_addr) fallback

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened: the neigh lookup resolves later");
}

#[test]
fn lan_ingress_lan_cache_docker_entry_pushes_vlan_and_redirects() {
    load_skel!("tc-lan-flow-cache-docker", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_full(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        TARGET_IFINDEX,
        false,
        0x0305,
        true,
        Ipv4Addr::UNSPECIFIED,
        [0; 6],
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // bpf_skb_vlan_push only sets the hwaccel tag under PROG_TEST_RUN.
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan_ingress_lan_cache_zero_ifindex_same_device_slot_passes() {
    // pick_wan resolved through the cached flow id, but the slot target is the
    // incoming device itself: no redirect needed → UNSPEC.
    load_skel!("tc-lan-flow-cache-sameslot", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        0,
        false,
        0x0305,
    );
    seed_wan_slots(&skel, 5, LOOPBACK_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "slot on the incoming device must pass");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan_ingress_lan_cache_zero_ifindex_without_slot_drops() {
    // pick_wan slot-miss with flow_id != 0 → SHOT (the cached flow's slots
    // were never provisioned).
    load_skel!("tc-lan-flow-cache-noslot", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        0,
        false,
        0x0305,
    );
    // rt4_slot_map intentionally left empty for flow 5

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "non-zero cached flow without slots must drop");
    assert_eq!(mark, 0x0200_0305);
}

#[test]
fn lan_ingress_lan_cache_zero_ifindex_default_flow_passes() {
    // Legacy pick_wan twin (route4_pick_wan_and_send_by_flow_id) reached via
    // a cache entry with ifindex == 0 and a DEFAULT-flow mark: a flow id 0
    // slot-miss passes (TC_ACT_UNSPEC) — unlike the TC first-packet wrapper
    // which drops the default flow.
    load_skel!("tc-lan-flow-cache-default-pass", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        0,
        false,
        0, // mark_value 0 → resolved flow id 0 (default flow)
    );
    // rt4_slot_map intentionally left empty for flow 0

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_UNSPEC, "legacy pick_wan passes default-flow traffic");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0000, "wrapper stamps the LAN source on the search-cache return");
}

#[test]
fn lan_ingress_set_cache_skipped_when_wan_cache_has_entry() {
    // route4_set_cache_in_lan checks the WAN cache first: a stale entry there
    // (inert during the search, no binding) suppresses the LAN cache write
    // even after a fresh redirect.
    load_skel!("tc-lan-flow-setcache-wanexist", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_ifindex(
        &skel.maps.rt4_cache_map,
        WAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        TARGET_IFINDEX,
        true,
    );
    // no wan binding → the WAN-cache entry is inert during the search
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert!(
        lookup_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            LAN_CACHE,
            client_addr(),
            remote_wan_addr()
        )
        .is_none(),
        "a WAN-cache entry must suppress the LAN cache write"
    );
}

// ---------------------------------------------------------------------------
// WAN-cache hit (reply-learned reverse fast path)
// ---------------------------------------------------------------------------

fn seed_wan_cache(skel: &TcLanIngressIntroSkel<'_>) {
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    put_rt4_cache_ifindex(
        &skel.maps.rt4_cache_map,
        WAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        TARGET_IFINDEX,
        true,
    );
    seed_wan_binding(skel);
}

#[test]
fn lan_ingress_wan_cache_hit_rewrites_header_from_remote_ip_mac() {
    load_skel!("tc-lan-flow-wan-cache", skel);
    seed_wan_cache(&skel);

    let next_hop = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, remote_wan_addr(), next_hop, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // The WAN-cache path stores the full 14-byte ip_mac value: dst mac, dev
    // mac, then the proto field as ethertype.
    assert_eq!(&out[0..6], &next_hop.octets());
    assert_eq!(&out[6..12], &dev_mac.octets());
    assert_eq!(&out[12..14], &[0x08, 0x00]);
    assert_eq!(mark, 0x0200_0000, "WAN-cache hit keeps the original mark value (0)");
    assert_eq!(forwarded, 0);
}

#[test]
fn lan_ingress_wan_cache_hit_falls_back_to_gateway_mac() {
    load_skel!("tc-lan-flow-wan-cache-gw", skel);
    seed_wan_cache(&skel);

    let gateway_mac = MacAddr::from_str("02:66:77:88:99:aa").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ef").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, wan_gateway(), gateway_mac, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &gateway_mac.octets(), "must fall back to the wan gateway mac");
    assert_eq!(&out[6..12], &dev_mac.octets());
    assert_eq!(&out[12..14], &[0x08, 0x00]);
}

#[test]
fn lan_ingress_wan_cache_hit_without_any_ip_mac_falls_to_neigh() {
    // has_mac WAN-cache entry with neither the remote nor the gateway in
    // ip_mac_v4 → bpf_redirect_neigh(gateway) fallback, no rewrite.
    load_skel!("tc-lan-flow-wan-cache-neigh", skel);
    seed_wan_cache(&skel);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened: the neigh lookup resolves later");
}

#[test]
fn lan_ingress_wan_cache_no_mac_entry_redirects_directly() {
    // route4_search_cache_in_lan !target_has_mac row: a mac-less WAN-cache
    // entry redirects immediately, without touching ip_mac_v4 or the packet.
    load_skel!("tc-lan-flow-wan-cache-nomac", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    put_rt4_cache_ifindex(
        &skel.maps.rt4_cache_map,
        WAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        TARGET_IFINDEX,
        false, // !has_mac
    );
    seed_wan_binding(&skel);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "mac-less WAN-cache entry redirects directly");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0200_0000, "WAN-cache hit keeps the original mark value (0)");
    assert_eq!(forwarded, 0);
}

#[test]
fn lan_ingress_wan_cache_hit_without_wan_binding_is_inert() {
    // The WAN-cache fast path requires wan_ip_binding[target->ifindex]; a
    // stale cache entry without a binding must not redirect.
    load_skel!("tc-lan-flow-wan-cache-nobind", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_ifindex(
        &skel.maps.rt4_cache_map,
        WAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        TARGET_IFINDEX,
        true,
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "no binding → WAN-cache entry is inert → default drop");
    assert_eq!(mark, 0x0200_0000);
    assert!(lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr()
    )
    .is_none());
}
