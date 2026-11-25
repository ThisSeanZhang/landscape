//! Cache fast-path matrix of the v6 LAN-ingress worker
//! (`route6_search_cache_in_lan`): LAN-cache hits, zero-ifindex true-miss
//! fallback/rebuild, and reply-learned WAN-cache hits.

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
    assert_eq!(
        mark,
        normal_mark(FlowMarkAction::Redirect, 5, false),
        "mark must come from the cache mark value"
    );
    assert_eq!(forwarded, 1, "route6_redirect_by_cached_target stamps the cb forwarded flag");
    assert!(
        lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).is_none(),
        "learning must not run on the cache fast path"
    );
}

#[test]
fn lan6_ingress_lan_cache_zero_ifindex_misses_and_rebuilds_like_empty_cache() {
    // Both flows have usable slots. With no overriding rule, only the packet's
    // own mark A should determine the redirect and the rebuilt cache entry.
    const MARK_A: u32 = FLOW_REDIRECT_MARK; // flow 5
    const MARK_B: u32 = 0x0306; // action REDIRECT, flow 6
    const IFINDEX_A: u32 = TARGET_IFINDEX;
    const IFINDEX_B: u32 = TARGET_IFINDEX + 1;

    let run_case = |pin: &str, seed_zero_ifindex: bool| {
        load_skel!(pin, skel);
        create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
        if seed_zero_ifindex {
            put_rt6_cache_value(
                &skel.maps.rt6_cache_map,
                LAN_CACHE,
                local_addr(),
                remote_addr(),
                0,
                false,
                MARK_B,
            );
        }
        seed_wan_slots(&skel, 5, IFINDEX_A, false, None);
        seed_wan_slots(&skel, 6, IFINDEX_B, false, None);

        let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
        let mut ctx = TestSkb { mark: MARK_A, ..lan_ctx() };
        let (ret, _out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut ctx);
        let cache = lookup_rt6_cache_value(
            &skel.maps.rt6_cache_map,
            LAN_CACHE,
            local_addr(),
            remote_addr(),
        )
        .expect("slow-path redirect must populate/rebuild the LAN cache entry");
        let learned = lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).is_some();
        (ret, mark, forwarded, cache.ifindex, cache.mark_value, learned)
    };

    let empty = run_case("tc-lan6-cache-empty-ref", false);
    let zero_if = run_case("tc-lan6-cache-zero-if", true);

    assert_eq!(zero_if, empty, "zero-ifindex entry must match empty-cache slow path");
    assert_eq!(zero_if.0, RET_REDIRECT);
    assert_eq!(zero_if.1, normal_mark(FlowMarkAction::Redirect, 5, false));
    assert_eq!(zero_if.2, 1);
    assert_eq!(zero_if.3, IFINDEX_A, "cache entry must be rebuilt to target A's ifindex");
    assert_eq!(zero_if.4, MARK_A, "cache entry must be rebuilt to mark A, not stale mark B");
    assert!(zero_if.5, "true cache miss must run slow-path neighbour learning");
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
    assert_eq!(mark, normal_mark(FlowMarkAction::Redirect, 5, false));
}

#[test]
fn lan6_ingress_lan_cache_has_mac_preserves_frame_with_or_without_gate_ip_mac() {
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());

    for (pin, seed_gw_neighbor) in [("tc-lan6-cache-gwmac", true), ("tc-lan6-cache-gwmiss", false)]
    {
        load_skel!(pin, skel);
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
        );
        if seed_gw_neighbor {
            insert_ip_mac_v6(&skel.maps.ip_mac_v6, gateway_addr(), gw_mac, gw_dev, TARGET_IFINDEX);
        }

        let (ret, out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

        assert_eq!(ret, RET_REDIRECT);
        assert_eq!(out, pkt, "LAN-cache hit must preserve the original Ethernet frame");
        assert_eq!(mark, normal_mark(FlowMarkAction::Redirect, 5, false));
        assert_eq!(forwarded, 1, "LAN-cache redirect must stamp the cb forwarded flag");
    }
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
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt);
    assert_eq!(mark, normal_mark(FlowMarkAction::Redirect, 5, false));
}

#[test]
fn lan6_ingress_lan_cache_zero_ifindex_default_flow_without_slot_drops() {
    // A zero-ifindex LAN-cache entry with a stale non-zero mark B (whose slot
    // B is provisioned) must still miss to the TC slow path: with no matching
    // rule and no default-flow (flow 0) slot, the packet drops with mark 0
    // rather than redirecting via stale mark B or passing via a legacy path.
    const MARK_B: u32 = 0x0306; // action REDIRECT, flow 6
    const IFINDEX_B: u32 = TARGET_IFINDEX + 1;

    load_skel!("tc-lan6-cache-zero-if-drop", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr(),
        0,
        false,
        MARK_B,
    );
    seed_wan_slots(&skel, 6, IFINDEX_B, false, None);
    // rt6_slot_map intentionally left empty for default flow 0

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "zero-ifindex miss with empty default-flow slots must drop");
    assert_eq!(
        mark,
        normal_mark(FlowMarkAction::KeepGoing, 0, false),
        "stale cached mark B must not leak onto the packet"
    );
    assert!(
        lookup_ip_mac_v6(&skel.maps.ip_mac_v6, local_addr()).is_some(),
        "true cache miss must run slow-path neighbour learning"
    );
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

fn seed_wan_cache(skel: &TcLanIngressRouteSkel<'_>) {
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
fn lan6_ingress_wan_cache_hit_ignores_remote_ip_mac() {
    load_skel!("tc-lan6-wan-cache", skel);
    seed_wan_cache(&skel);

    let next_hop = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, remote_addr(), next_hop, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "the WAN egress root owns the Ethernet rewrite");
    assert_eq!(
        mark,
        normal_mark(FlowMarkAction::KeepGoing, 0, false),
        "WAN-cache hit keeps the original mark value (0)"
    );
    assert_eq!(forwarded, 1, "the WAN-cache branch stamps the cb forwarded flag");
}

#[test]
fn lan6_ingress_wan_cache_hit_ignores_gateway_mac() {
    load_skel!("tc-lan6-wan-cache-gw", skel);
    seed_wan_cache(&skel);

    let gateway_mac = MacAddr::from_str("02:66:77:88:99:aa").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ef").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, gateway_addr(), gateway_mac, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "the WAN egress root resolves the gateway, not this stage");
}

#[test]
fn lan6_ingress_wan_cache_hit_without_ip_mac_redirects() {
    load_skel!("tc-lan6-wan-cache-neigh", skel);
    seed_wan_cache(&skel);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_lan6_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "no rewrite happened");
}

#[test]
fn lan6_ingress_wan_cache_no_mac_entry_redirects_directly() {
    // A WAN-cache hit redirects without touching ip_mac_v6 or the packet,
    // regardless of the cached has_mac flag.
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
    assert_eq!(
        mark,
        normal_mark(FlowMarkAction::KeepGoing, 0, false),
        "WAN-cache hit keeps the original mark value (0)"
    );
    assert_eq!(forwarded, 1, "the WAN-cache branch stamps the cb forwarded flag");
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
    assert_eq!(mark, normal_mark(FlowMarkAction::KeepGoing, 0, false));
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, LAN_CACHE, local_addr(), remote_addr())
            .is_none()
    );
}
