//! Cache fast-path matrix of the v4 LAN-ingress worker
//! (`route4_search_cache_in_lan`): LAN-cache hits, zero-ifindex true-miss
//! fallback/rebuild, and reply-learned WAN-cache hits.

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
    assert_eq!(
        mark,
        normal_mark(FlowMarkAction::Redirect, 5, false),
        "mark must come from the cache mark value"
    );
    assert_eq!(forwarded, 1, "route4_redirect_by_cached_target stamps the cb forwarded flag");
    assert!(
        lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_none(),
        "learning must not run on the cache fast path"
    );
}

#[test]
fn lan_ingress_lan_cache_zero_ifindex_misses_and_rebuilds_like_empty_cache() {
    // Both flows have usable slots. With no overriding rule, only the packet's
    // own mark A should determine the redirect and the rebuilt cache entry.
    const MARK_A: u32 = FLOW_REDIRECT_MARK; // flow 5
    const MARK_B: u32 = 0x0306; // action REDIRECT, flow 6
    const IFINDEX_A: u32 = TARGET_IFINDEX;
    const IFINDEX_B: u32 = TARGET_IFINDEX + 1;

    let run_case = |pin: &str, seed_zero_ifindex: bool| {
        load_skel!(pin, skel);
        create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
        if seed_zero_ifindex {
            put_rt4_cache_value(
                &skel.maps.rt4_cache_map,
                LAN_CACHE,
                client_addr(),
                remote_wan_addr(),
                0,
                false,
                MARK_B,
            );
        }
        seed_wan_slots(&skel, 5, IFINDEX_A, false, None);
        seed_wan_slots(&skel, 6, IFINDEX_B, false, None);

        let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
        let mut ctx = TestSkb { mark: MARK_A, ..lan_ctx() };
        let (ret, _out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut ctx);
        let cache = lookup_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            LAN_CACHE,
            client_addr(),
            remote_wan_addr(),
        )
        .expect("slow-path redirect must populate/rebuild the LAN cache entry");
        let learned = lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_some();
        (ret, mark, forwarded, cache.ifindex, cache.mark_value, learned)
    };

    let empty = run_case("tc-lan-flow-cache-empty-ref", false);
    let zero_if = run_case("tc-lan-flow-cache-zero-if", true);

    assert_eq!(zero_if, empty, "zero-ifindex entry must match empty-cache slow path");
    assert_eq!(zero_if.0, RET_REDIRECT);
    assert_eq!(zero_if.1, normal_mark(FlowMarkAction::Redirect, 5, false));
    assert_eq!(zero_if.2, 1);
    assert_eq!(zero_if.3, IFINDEX_A, "cache entry must be rebuilt to target A's ifindex");
    assert_eq!(zero_if.4, MARK_A, "cache entry must be rebuilt to mark A, not stale mark B");
    assert!(zero_if.5, "true cache miss must run slow-path neighbour learning");
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
    assert_eq!(mark, normal_mark(FlowMarkAction::Redirect, 5, false));
}

#[test]
fn lan_ingress_lan_cache_has_mac_entry_defers_rewrite_to_root() {
    // The cached target is a WAN link.  Even with has_mac set on the cached
    // target and a resolvable ip_mac_v4 entry, LAN ingress must only hand the
    // packet to that link's root, which owns the single Ethernet rewrite.
    load_skel!("tc-lan-flow-cache-gwmac", skel);
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
    );
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, wan_gateway(), gw_mac, gw_dev, TARGET_IFINDEX);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "LAN ingress must not rewrite Ethernet on a WAN cache hit");
    assert_eq!(forwarded, 1, "the target link root owns the rewrite");
    assert_eq!(mark, normal_mark(FlowMarkAction::Redirect, 5, false));
}

#[test]
fn lan_ingress_lan_cache_has_mac_entry_without_ip_mac_defers_to_root() {
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
    );
    // Leave the neighbour map empty to exercise the handoff on a miss.

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "cross-link handoff still redirects");
    assert_eq!(out, pkt, "no rewrite happens at LAN ingress");
    assert_eq!(forwarded, 1, "the target link root owns lookup and fallback");
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
    );

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // bpf_skb_vlan_push only sets the hwaccel tag under PROG_TEST_RUN.
    assert_eq!(out, pkt);
    assert_eq!(mark, normal_mark(FlowMarkAction::Redirect, 5, false));
}

#[test]
fn lan_ingress_lan_cache_zero_ifindex_default_flow_without_slot_drops() {
    // A zero-ifindex LAN-cache entry with a stale non-zero mark B (whose slot
    // B is provisioned) must still miss to the TC slow path: with no matching
    // rule and no default-flow (flow 0) slot, the packet drops with mark 0
    // rather than redirecting via stale mark B or passing via a legacy path.
    const MARK_B: u32 = 0x0306; // action REDIRECT, flow 6
    const IFINDEX_B: u32 = TARGET_IFINDEX + 1;

    load_skel!("tc-lan-flow-cache-zero-if-drop", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        0,
        false,
        MARK_B,
    );
    seed_wan_slots(&skel, 6, IFINDEX_B, false, None);
    // rt4_slot_map intentionally left empty for default flow 0

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "zero-ifindex miss with empty default-flow slots must drop");
    assert_eq!(
        mark,
        normal_mark(FlowMarkAction::KeepGoing, 0, false),
        "stale cached mark B must not leak onto the packet"
    );
    assert!(
        lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_some(),
        "true cache miss must run slow-path neighbour learning"
    );
}

fn put_wan_cache_with_chain(
    skel: &TcLanIngressRouteSkel<'_>,
    ifindex: u32,
    has_mac: bool,
    link_chain_id: u16,
) {
    let val = skel
        .maps
        .rt4_cache_map
        .lookup(&WAN_CACHE.to_ne_bytes(), MapFlags::ANY)
        .unwrap()
        .expect("WAN_CACHE inner map missing");
    let map_id = u32::from_ne_bytes(val[..4].try_into().unwrap());
    let inner = libbpf_rs::MapHandle::from_map_id(map_id).expect("open WAN_CACHE inner map");
    let key = crate::maps::Route4CacheKey {
        local_addr: client_addr().to_bits().to_be(),
        remote_addr: remote_wan_addr().to_bits().to_be(),
    };
    let entry = crate::maps::Route4CacheValue {
        ifindex,
        has_mac: u8::from(has_mac),
        link_chain_id,
        ..Default::default()
    };
    inner.update(as_bytes(&key), as_bytes(&entry), MapFlags::ANY).unwrap();
}

#[test]
fn lan_ingress_wan_cache_hit_short_circuits_without_writing_lan_cache() {
    // A WAN-cache hit pins return traffic to the original WAN link and
    // short-circuits before slow-path learning, flow verdict, pick_wan, and
    // LAN-cache population — even when a competing flow rule and alternative
    // WAN slot are available.
    const ORIG_CHAIN: u16 = 7;
    const ALT_IFINDEX: u32 = TARGET_IFINDEX + 1;

    load_skel!("tc-lan-flow-setcache-wanexist", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_wan_cache_with_chain(&skel, TARGET_IFINDEX, true, ORIG_CHAIN);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, ALT_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, cb) = run_lan_ingress_with_cb(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(cb[0], 1, "WAN-cache hit stamps the cb forwarded flag");
    assert_eq!(cb[1] >> 16, u32::from(ORIG_CHAIN), "WAN-cache hit must keep the original chain");
    assert_eq!(
        mark,
        normal_mark(FlowMarkAction::KeepGoing, 0, false),
        "WAN-cache hit must not run flow verdict"
    );
    assert!(
        lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_none(),
        "WAN-cache hit must skip slow-path neighbour learning"
    );
    assert!(
        lookup_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            LAN_CACHE,
            client_addr(),
            remote_wan_addr()
        )
        .is_none(),
        "a WAN-cache hit must not populate the LAN cache"
    );
}

// ---------------------------------------------------------------------------
// WAN-cache hit (reply-learned reverse fast path)
// ---------------------------------------------------------------------------

fn seed_wan_cache(skel: &TcLanIngressRouteSkel<'_>) {
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    put_rt4_cache_ifindex(
        &skel.maps.rt4_cache_map,
        WAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        TARGET_IFINDEX,
        true,
    );
}

#[test]
fn wan_cache_raw_ipv4_prepends_a_unicast_header_for_neighbour_fallback() {
    load_skel!("tc-lan-cache-raw4", skel, 0);
    seed_wan_cache(&skel);
    let frame = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let ip = &frame[14..];
    let mut ctx = lan_ctx();
    let mut out = vec![0; frame.len()];
    let result = skel
        .progs
        .tc_route4_lan_ingress
        .test_run(ProgramInput {
            data_in: Some(ip),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(result.return_value as i32, RET_REDIRECT);
    let packet = result.data.unwrap();
    assert_eq!(packet[0] & 1, 0);
    assert_eq!(packet[12..14], [8, 0]);
    assert_eq!(&packet[14..], ip);
}

#[test]
fn lan_ingress_wan_cache_hit_defers_header_rewrite_to_link_root() {
    load_skel!("tc-lan-flow-wan-cache", skel);
    seed_wan_cache(&skel);

    let next_hop = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, remote_wan_addr(), next_hop, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // LAN ingress only selects the target link.  The target link's from-LAN
    // root owns the Ethernet rewrite using its own source MAC.
    assert_eq!(out, pkt, "LAN ingress must not rewrite the Ethernet header");
    assert_eq!(
        mark,
        normal_mark(FlowMarkAction::KeepGoing, 0, false),
        "WAN-cache hit keeps the original mark value (0)"
    );
    assert_eq!(forwarded, 1, "the WAN-cache branch stamps the cb forwarded flag");
}

#[test]
fn lan_ingress_wan_cache_hit_does_not_resolve_gateway_mac() {
    load_skel!("tc-lan-flow-wan-cache-gw", skel);
    seed_wan_cache(&skel);

    let gateway_mac = MacAddr::from_str("02:66:77:88:99:aa").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ef").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, wan_gateway(), gateway_mac, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "gateway MAC resolution belongs to the target link root");
}

#[test]
fn lan_ingress_wan_cache_hit_without_any_ip_mac_defers_to_root() {
    // The reverse cache still selects a WAN when its neighbour is unknown.
    load_skel!("tc-lan-flow-wan-cache-neigh", skel);
    seed_wan_cache(&skel);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_REDIRECT, "cross-link handoff still redirects");
    assert_eq!(out, pkt, "no rewrite happened at LAN ingress");
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

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

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
fn lan_ingress_wan_cache_zero_ifindex_drops_without_rerouting_to_alternative() {
    const ALT_IFINDEX: u32 = TARGET_IFINDEX + 1;

    load_skel!("tc-lan-flow-wan-cache-zeroif", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_wan_cache_with_chain(&skel, 0, true, 7);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        client_addr(),
        remote_wan_addr(),
        ALT_IFINDEX,
        true,
        FLOW_REDIRECT_MARK,
    );
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 0, ALT_IFINDEX, false, None);
    seed_wan_slots(&skel, 5, ALT_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(client_addr(), remote_wan_addr());
    let (ret, _out, mark, forwarded) = run_lan_ingress(&skel, &pkt, &mut lan_ctx());

    assert_eq!(ret, RET_SHOT, "zero-ifindex WAN-cache hit must drop without rerouting");
    assert_eq!(forwarded, 0);
    assert_eq!(mark, normal_mark(FlowMarkAction::KeepGoing, 0, false));
    assert!(lookup_ip_mac_v4(&skel.maps.ip_mac_v4, client_addr()).is_none());
}
