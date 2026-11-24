use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use landscape_common::{
    config::FlowId,
    ddns::IpFamily,
    flow::{FlowTarget, WeightedFlowTarget, config::FlowConfig},
    sys_service::route_service::{
        LanIPv6RouteKey, LanRouteInfo, LanRouteMode, RouteOwner, RouteTargetInfo, WanRouteTarget,
    },
    wan_link::{WanLinkHealthInfo, WanLinkHealthState},
};
use uuid::Uuid;

use super::flow_target::collect_target_refresh_result;
use super::lan::{Ipv4LanBucketUpdate, Ipv6LanRouteUpdate, reconcile_ipv4_lan_bucket};
use super::wan::{WanRouteEvent, WanRouteEventKind};
use super::*;

fn ipv4_wan_route(iface_name: &str, iface_ip: Ipv4Addr) -> WanRouteTarget {
    WanRouteTarget::link(
        0,
        RouteTargetInfo::new_gateway_v4(
            1,
            iface_name,
            None,
            iface_ip,
            Ipv4Addr::new(192, 0, 2, 1),
            true,
        ),
    )
}

fn ipv6_wan_default_route(iface_name: &str) -> WanRouteTarget {
    WanRouteTarget::link(
        0,
        RouteTargetInfo::new_gateway_v6(
            2,
            iface_name,
            None,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            true,
        ),
    )
}

fn ipv6_wan_route(iface_name: &str, gateway: Ipv6Addr) -> WanRouteTarget {
    WanRouteTarget::link(
        0,
        RouteTargetInfo::new_gateway_v6(2, iface_name, None, Ipv6Addr::LOCALHOST, gateway, true),
    )
}

fn ipv4_lan_route(
    ifindex: u32,
    iface_name: &str,
    iface_ip: Ipv4Addr,
    prefix: u8,
    mode: LanRouteMode,
) -> LanRouteInfo {
    LanRouteInfo {
        ifindex,
        iface_name: iface_name.to_string(),
        iface_ip: IpAddr::V4(iface_ip),
        mac: None,
        prefix,
        mode,
    }
}

fn ipv6_lan_route(
    ifindex: u32,
    iface_name: &str,
    iface_ip: Ipv6Addr,
    prefix: u8,
    mode: LanRouteMode,
) -> LanRouteInfo {
    LanRouteInfo {
        ifindex,
        iface_name: iface_name.to_string(),
        iface_ip: IpAddr::V6(iface_ip),
        mac: None,
        prefix,
        mode,
    }
}

fn run_async_test(test: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test);
}

#[test]
fn wan_route_events_only_fire_on_real_changes() {
    run_async_test(async {
        let service = test_used_ip_route();
        let mut events = service.subscribe_wan_route_events();
        let route = ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 10));
        let owner = RouteOwner::Link(Uuid::nil());

        service.insert_ipv4_wan_route(&owner, route.clone()).await;
        assert_eq!(
            events.recv().await.unwrap(),
            WanRouteEvent {
                owner: owner.clone(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        );

        service.insert_ipv4_wan_route(&owner, route).await;
        assert!(tokio::time::timeout(Duration::from_millis(50), events.recv()).await.is_err());

        service.remove_ipv4_wan_route(&owner).await;
        assert_eq!(
            events.recv().await.unwrap(),
            WanRouteEvent {
                owner,
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Removed,
            }
        );
    });
}

#[test]
fn wan_route_events_fire_on_chain_change() {
    run_async_test(async {
        let service = test_used_ip_route();
        let mut events = service.subscribe_wan_route_events();
        let owner = RouteOwner::Link(Uuid::nil());

        service
            .insert_ipv4_wan_route(&owner, ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 10)))
            .await;
        let _ = events.recv().await; // initial upsert

        // Same route info but a different chain: the stored entry changed,
        // so subscribers (the flow-target join) must re-run and rewrite the
        // eBPF slot values with the new chain.
        let mut reanchored = ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 10));
        reanchored.link_chain_id = 3;
        service.insert_ipv4_wan_route(&owner, reanchored.clone()).await;
        assert_eq!(
            events.recv().await.unwrap(),
            WanRouteEvent {
                owner: owner.clone(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        );

        // And an identical re-registration stays quiet.
        service.insert_ipv4_wan_route(&owner, reanchored).await;
        assert!(tokio::time::timeout(Duration::from_millis(50), events.recv()).await.is_err());
    });
}

#[test]
fn remove_all_wan_docker_notifies_and_refreshes_default_router() {
    run_async_test(async {
        let service = test_used_ip_route();
        let mut events = service.subscribe_wan_route_events();

        let docker_owner = RouteOwner::Netns("docker0".to_string());
        let wan_owner = RouteOwner::Link(Uuid::nil());
        let mut docker_route = ipv4_wan_route("docker0", Ipv4Addr::new(172, 17, 0, 1));
        docker_route.info.is_docker = true;
        docker_route.info.default_route = false;
        service.insert_ipv4_wan_route(&docker_owner, docker_route).await;
        service
            .insert_ipv4_wan_route(
                &wan_owner,
                ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)),
            )
            .await;
        let _ = events.recv().await; // docker0 upserted
        let _ = events.recv().await; // wan0 upserted

        service.remove_all_wan_docker().await;

        assert_eq!(
            events.recv().await.unwrap(),
            WanRouteEvent {
                owner: docker_owner.clone(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Removed,
            }
        );
        assert!(tokio::time::timeout(Duration::from_millis(50), events.recv()).await.is_err());
        assert!(service.get_ipv4_wan_route(&docker_owner).await.is_none());
        assert!(service.get_ipv4_wan_route(&wan_owner).await.is_some());
    });
}

#[test]
fn reachable_local_ipv4_addrs_filter_invalid_entries_and_next_hop() {
    run_async_test(async {
        let service = test_used_ip_route();
        let mut routes = service.ipv4_lan_ifaces.write().await;
        routes.insert(
            "wan0".to_string(),
            vec![ipv4_lan_route(
                1,
                "wan0",
                Ipv4Addr::new(192, 168, 2, 1),
                24,
                LanRouteMode::Reachable,
            )],
        );
        routes.insert(
            "lan0".to_string(),
            vec![ipv4_lan_route(
                2,
                "lan0",
                Ipv4Addr::new(192, 168, 1, 1),
                24,
                LanRouteMode::Reachable,
            )],
        );
        routes.insert(
            "lan0-nexthop".to_string(),
            vec![ipv4_lan_route(
                2,
                "lan0",
                Ipv4Addr::new(192, 168, 1, 254),
                24,
                LanRouteMode::NextHop {
                    next_hop_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                },
            )],
        );
        routes.insert(
            "loopback".to_string(),
            vec![ipv4_lan_route(3, "lo", Ipv4Addr::LOCALHOST, 8, LanRouteMode::Reachable)],
        );
        routes.insert(
            "lan1".to_string(),
            vec![ipv4_lan_route(
                4,
                "lan1",
                Ipv4Addr::new(192, 168, 1, 1),
                24,
                LanRouteMode::Reachable,
            )],
        );
        service.refresh_reachable_local_ipv4_addrs(&routes);
        drop(routes);

        assert_eq!(
            service.local_addr_view().load_ipv4_addrs().as_ref(),
            &vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))
            ]
        );
    });
}

#[test]
fn reachable_local_ipv6_addrs_keep_link_local_and_deduplicate() {
    run_async_test(async {
        let service = test_used_ip_route();
        let mut routes = service.ipv6_lan_ifaces.write().await;
        routes.insert(
            LanIPv6RouteKey {
                iface_name: "lan0".to_string(),
                subnet: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                prefix_len: 64,
            },
            LanRouteInfo {
                ifindex: 1,
                iface_name: "lan0".to_string(),
                iface_ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                mac: None,
                prefix: 64,
                mode: LanRouteMode::Reachable,
            },
        );
        routes.insert(
            LanIPv6RouteKey {
                iface_name: "lan1".to_string(),
                subnet: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                prefix_len: 64,
            },
            LanRouteInfo {
                ifindex: 2,
                iface_name: "lan1".to_string(),
                iface_ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                mac: None,
                prefix: 64,
                mode: LanRouteMode::Reachable,
            },
        );
        routes.insert(
            LanIPv6RouteKey {
                iface_name: "lan2".to_string(),
                subnet: Ipv6Addr::UNSPECIFIED,
                prefix_len: 64,
            },
            LanRouteInfo {
                ifindex: 3,
                iface_name: "lan2".to_string(),
                iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                mac: None,
                prefix: 64,
                mode: LanRouteMode::Reachable,
            },
        );
        routes.insert(
            LanIPv6RouteKey {
                iface_name: "lan3".to_string(),
                subnet: Ipv6Addr::LOCALHOST,
                prefix_len: 128,
            },
            LanRouteInfo {
                ifindex: 4,
                iface_name: "lan3".to_string(),
                iface_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                mac: None,
                prefix: 128,
                mode: LanRouteMode::Reachable,
            },
        );
        routes.insert(
            LanIPv6RouteKey {
                iface_name: "lan4".to_string(),
                subnet: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                prefix_len: 64,
            },
            LanRouteInfo {
                ifindex: 5,
                iface_name: "lan4".to_string(),
                iface_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                mac: None,
                prefix: 64,
                mode: LanRouteMode::NextHop {
                    next_hop_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                },
            },
        );
        service.refresh_reachable_local_ipv6_addrs(&routes);
        drop(routes);

        assert_eq!(
            service.local_addr_view().load_ipv6_addrs().as_ref(),
            &vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))]
        );
    });
}

#[test]
fn remove_ipv6_lan_route_by_key_state_update_keeps_other_routes_for_same_iface() {
    run_async_test(async {
        let service = test_used_ip_route();
        let key_a = LanIPv6RouteKey {
            iface_name: "lan0".to_string(),
            subnet: Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0),
            prefix_len: 64,
        };
        let key_b = LanIPv6RouteKey {
            iface_name: "lan0".to_string(),
            subnet: Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0),
            prefix_len: 64,
        };
        let route_a = ipv6_lan_route(
            1,
            "lan0",
            Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1),
            64,
            LanRouteMode::Reachable,
        );
        let route_b = ipv6_lan_route(
            1,
            "lan0",
            Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1),
            64,
            LanRouteMode::Reachable,
        );

        {
            let mut routes = service.ipv6_lan_ifaces.write().await;
            let update_a =
                service.upsert_ipv6_lan_route_by_key(&mut routes, key_a.clone(), route_a.clone());
            let update_b =
                service.upsert_ipv6_lan_route_by_key(&mut routes, key_b.clone(), route_b.clone());

            assert!(matches!(update_a, Ipv6LanRouteUpdate::Changed { removed: None, .. }));
            assert!(matches!(update_b, Ipv6LanRouteUpdate::Changed { removed: None, .. }));

            let removed = service.remove_ipv6_lan_route_by_key_inner(&mut routes, &key_a);

            assert_eq!(removed, Some(route_a));
            assert!(!routes.contains_key(&key_a));
            assert_eq!(routes.get(&key_b), Some(&route_b));
        }
        assert_eq!(
            service.local_addr_view().load_ipv6_addrs().as_ref(),
            &vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1))]
        );
    });
}

#[test]
fn upsert_and_remove_ipv4_lan_routes_for_same_owner_refresh_reachable_local_snapshots() {
    run_async_test(async {
        let service = test_used_ip_route();
        let owner = "lan0-static";
        let route_a =
            ipv4_lan_route(2, "lan0", Ipv4Addr::new(192, 168, 1, 1), 24, LanRouteMode::Reachable);
        let route_b =
            ipv4_lan_route(2, "lan0", Ipv4Addr::new(10, 0, 0, 1), 24, LanRouteMode::Reachable);

        {
            let mut routes = service.ipv4_lan_ifaces.write().await;
            let update_a =
                service.upsert_ipv4_lan_routes_for_owner(&mut routes, owner, route_a.clone());
            let update_b =
                service.upsert_ipv4_lan_routes_for_owner(&mut routes, owner, route_b.clone());

            assert!(
                matches!(update_a, Ipv4LanBucketUpdate::Changed { ref removed, .. } if removed.is_empty())
            );
            assert!(
                matches!(update_b, Ipv4LanBucketUpdate::Changed { ref removed, .. } if removed.is_empty())
            );
            assert_eq!(routes.get(owner), Some(&vec![route_a.clone(), route_b.clone()]));
        }
        assert_eq!(
            service.local_addr_view().load_ipv4_addrs().as_ref(),
            &vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            ]
        );

        {
            let mut routes = service.ipv4_lan_ifaces.write().await;
            let removed = service.remove_ipv4_lan_routes_for_owner(&mut routes, owner);

            assert_eq!(removed, Some(vec![route_a, route_b]));
            assert!(!routes.contains_key(owner));
        }
        assert!(service.local_addr_view().load_ipv4_addrs().is_empty());
    });
}

#[test]
fn reconcile_ipv4_lan_bucket_replaces_same_subnet_and_keeps_other_routes() {
    let mut bucket = vec![
        ipv4_lan_route(1, "lan0", Ipv4Addr::new(192, 168, 1, 1), 24, LanRouteMode::Reachable),
        ipv4_lan_route(1, "lan0", Ipv4Addr::new(10, 0, 0, 1), 24, LanRouteMode::Reachable),
    ];
    let replacement =
        ipv4_lan_route(2, "lan0", Ipv4Addr::new(192, 168, 1, 254), 24, LanRouteMode::Reachable);

    let update = reconcile_ipv4_lan_bucket(&mut bucket, replacement.clone());

    assert!(matches!(
        update,
        Ipv4LanBucketUpdate::Changed { ref removed, ref added }
            if removed
                == &vec![ipv4_lan_route(
                    1,
                    "lan0",
                    Ipv4Addr::new(192, 168, 1, 1),
                    24,
                    LanRouteMode::Reachable
                )]
                && added == &replacement
    ));
    assert_eq!(
        bucket,
        vec![
            ipv4_lan_route(1, "lan0", Ipv4Addr::new(10, 0, 0, 1), 24, LanRouteMode::Reachable),
            replacement,
        ]
    );
}

#[test]
fn reconcile_ipv4_lan_bucket_returns_noop_for_identical_entry() {
    let existing =
        ipv4_lan_route(1, "lan0", Ipv4Addr::new(192, 168, 1, 1), 24, LanRouteMode::Reachable);
    let mut bucket = vec![existing.clone()];

    let update = reconcile_ipv4_lan_bucket(&mut bucket, existing.clone());

    assert!(matches!(update, Ipv4LanBucketUpdate::Noop));
    assert_eq!(bucket, vec![existing]);
}

#[test]
fn refresh_reachable_local_ipv4_addrs_flattens_owner_buckets() {
    run_async_test(async {
        let service = test_used_ip_route();
        let mut routes = service.ipv4_lan_ifaces.write().await;
        routes.insert(
            "docker-network".to_string(),
            vec![
                ipv4_lan_route(
                    10,
                    "br0",
                    Ipv4Addr::new(172, 18, 0, 1),
                    16,
                    LanRouteMode::Reachable,
                ),
                ipv4_lan_route(
                    10,
                    "br0",
                    Ipv4Addr::new(172, 19, 0, 1),
                    16,
                    LanRouteMode::Reachable,
                ),
            ],
        );
        routes.insert(
            "iface".to_string(),
            vec![ipv4_lan_route(
                2,
                "lan0",
                Ipv4Addr::new(192, 168, 1, 1),
                24,
                LanRouteMode::Reachable,
            )],
        );

        service.refresh_reachable_local_ipv4_addrs(&routes);
        drop(routes);

        assert_eq!(
            service.local_addr_view().load_ipv4_addrs().as_ref(),
            &vec![
                IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            ]
        );
    });
}

#[test]
fn local_addr_view_loads_snapshots_directly() {
    run_async_test(async {
        let service = test_used_ip_route();
        let mut routes = service.ipv4_lan_ifaces.write().await;
        routes.insert(
            "lan0".to_string(),
            vec![ipv4_lan_route(
                2,
                "lan0",
                Ipv4Addr::new(192, 168, 1, 1),
                24,
                LanRouteMode::Reachable,
            )],
        );
        service.refresh_reachable_local_ipv4_addrs(&routes);
        drop(routes);

        assert_eq!(
            service.local_addr_view().load_ipv4_addrs().as_ref(),
            &vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]
        );
    });
}

#[test]
fn local_addr_view_loads_ifindex_specific_snapshot() {
    run_async_test(async {
        let service = test_used_ip_route();
        let mut routes = service.ipv4_lan_ifaces.write().await;
        routes.insert(
            "lan0".to_string(),
            vec![
                ipv4_lan_route(
                    2,
                    "lan0",
                    Ipv4Addr::new(192, 168, 1, 1),
                    24,
                    LanRouteMode::Reachable,
                ),
                ipv4_lan_route(
                    7,
                    "lan1",
                    Ipv4Addr::new(192, 168, 2, 1),
                    24,
                    LanRouteMode::Reachable,
                ),
            ],
        );
        service.refresh_reachable_local_ipv4_addrs(&routes);
        drop(routes);

        let view = service.local_addr_view();
        assert_eq!(
            view.load_ipv4_addrs_for_ifindex(7).as_ref(),
            &vec![IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))]
        );
        assert!(view.load_ipv4_addrs_for_ifindex(99).is_empty());
    });
}

// ── collect_target_refresh_result ──────────────────────────────

fn flow_config(flow_id: u32, enable: bool, targets: Vec<WeightedFlowTarget>) -> FlowConfig {
    FlowConfig {
        id: Uuid::nil(),
        enable,
        flow_id,
        flow_match_rules: vec![],
        flow_targets: targets,
        name: String::new(),
        remark: String::new(),
        update_at: 0.0,
    }
}

fn named_uuid(name: &str) -> Uuid {
    let (mut h1, mut h2): (u64, u64) = (0xcbf29ce484222325, 0x9e3779b97f4a7c15);
    for b in name.as_bytes() {
        h1 ^= *b as u64;
        h1 = h1.wrapping_mul(0x100000001b3);
        h2 = h2.rotate_left(5) ^ (*b as u64);
    }
    Uuid::from_u64_pair(h1, h2)
}

fn iface_target(name: &str, weight: u32) -> WeightedFlowTarget {
    WeightedFlowTarget::new(
        FlowTarget::Interface { name: name.to_string(), link_id: named_uuid(name) },
        weight,
    )
}

fn link_owner(name: &str) -> RouteOwner {
    RouteOwner::Link(named_uuid(name))
}

fn netns_target(container_name: &str, weight: u32) -> WeightedFlowTarget {
    WeightedFlowTarget::new(
        FlowTarget::Netns { container_name: container_name.to_string() },
        weight,
    )
}

fn health_info(link_id: Uuid, state: WanLinkHealthState) -> WanLinkHealthInfo {
    WanLinkHealthInfo {
        link_id,
        state,
        consecutive_failures: if state == WanLinkHealthState::Unhealthy { 3 } else { 0 },
        targets: Vec::new(),
        rtt_ewma_ms: None,
        loss_ewma: None,
        last_success_at: None,
        last_failure_at: None,
        updated_at: 0.0,
    }
}

#[test]
fn collect_refresh_enabled_flow_with_matching_targets() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert(link_owner("wan0"), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));
    wan_infos.insert(link_owner("wan1"), ipv4_wan_route("wan1", Ipv4Addr::new(203, 0, 113, 1)));

    let configs =
        vec![flow_config(5, true, vec![iface_target("wan0", 3), iface_target("wan1", 1)])];

    let result = collect_target_refresh_result(&configs, &wan_infos, &LinkHealths::new());

    let targets = result.get(&5).expect("flow_id 5 should be present");
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].1, 3); // weight preserved
    assert_eq!(targets[1].1, 1);
    assert_eq!(targets[0].0.info.iface_name, "wan0");
    assert_eq!(targets[1].0.info.iface_name, "wan1");
}

#[test]
fn collect_refresh_carries_chain_id() {
    let mut wan_infos = WanRoutesByOwner::new();
    let mut anchored = ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1));
    anchored.link_chain_id = 7;
    wan_infos.insert(link_owner("wan0"), anchored);

    let configs = vec![flow_config(5, true, vec![iface_target("wan0", 1)])];

    let result = collect_target_refresh_result(&configs, &wan_infos, &LinkHealths::new());

    let targets = result.get(&5).expect("flow_id 5 should be present");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0.link_chain_id, 7, "the join must pass the chain into the slot targets");
}

#[test]
fn collect_refresh_disabled_flow_yields_empty() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert(link_owner("wan0"), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

    let configs = vec![flow_config(5, false, vec![iface_target("wan0", 1)])];

    let result = collect_target_refresh_result(&configs, &wan_infos, &LinkHealths::new());

    let targets = result.get(&5).expect("flow_id 5 should be present");
    assert!(targets.is_empty());
}

#[test]
fn collect_refresh_enabled_flow_with_unresolved_targets_yields_empty() {
    let wan_infos = WanRoutesByOwner::new(); // no routes registered

    let configs = vec![flow_config(5, true, vec![iface_target("missing_wan", 2)])];

    let result = collect_target_refresh_result(&configs, &wan_infos, &LinkHealths::new());

    let targets = result.get(&5).expect("flow_id 5 should be present");
    assert!(targets.is_empty());
}

#[test]
fn collect_refresh_partial_match_keeps_only_resolved() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert(link_owner("wan0"), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

    let configs =
        vec![flow_config(5, true, vec![iface_target("wan0", 3), iface_target("missing_wan", 1)])];

    let result = collect_target_refresh_result(&configs, &wan_infos, &LinkHealths::new());

    let targets = result.get(&5).expect("flow_id 5 should be present");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0.info.iface_name, "wan0");
    assert_eq!(targets[0].1, 3);
}

#[test]
fn collect_refresh_resolves_by_link_id_with_stale_name() {
    let mut wan_infos = WanRoutesByOwner::new();
    let uuid = named_uuid("wan0");
    wan_infos
        .insert(RouteOwner::Link(uuid), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

    let stale_target = WeightedFlowTarget::new(
        FlowTarget::Interface {
            name: "stale-renamed-iface".to_string(),
            link_id: uuid,
        },
        2,
    );
    let configs = vec![flow_config(7, true, vec![stale_target])];

    let result = collect_target_refresh_result(&configs, &wan_infos, &LinkHealths::new());

    let targets = result.get(&7).expect("flow_id 7 should be present");
    assert_eq!(targets.len(), 1, "a correct link_id must resolve regardless of its stale name");
    assert_eq!(
        targets[0].0.info.iface_name, "wan0",
        "the resolved iface comes from the registered route"
    );
}

#[test]
fn collect_refresh_netns_owner_does_not_satisfy_interface_target() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert(
        RouteOwner::Netns("wan0".to_string()),
        ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)),
    );

    let configs = vec![flow_config(9, true, vec![iface_target("wan0", 1)])];

    let result = collect_target_refresh_result(&configs, &wan_infos, &LinkHealths::new());

    let targets = result.get(&9).expect("flow_id 9 should be present");
    assert!(
        targets.is_empty(),
        "an Interface target must not resolve through a Netns owner with the same display name"
    );
}

#[test]
fn collect_refresh_netns_target_resolves_by_container_name() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert(
        RouteOwner::Netns("ns0".to_string()),
        ipv4_wan_route("ns0", Ipv4Addr::new(10, 0, 0, 1)),
    );

    let configs = vec![flow_config(3, true, vec![netns_target("ns0", 5)])];

    let result = collect_target_refresh_result(&configs, &wan_infos, &LinkHealths::new());

    let targets = result.get(&3).expect("flow_id 3 should be present");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0.info.iface_name, "ns0");
    assert_eq!(targets[0].1, 5);
}

#[test]
fn collect_refresh_multiple_flows_independent() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert(link_owner("wan0"), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

    let configs = vec![
        flow_config(1, true, vec![iface_target("wan0", 2)]),
        flow_config(2, false, vec![iface_target("wan0", 1)]),
        flow_config(3, true, vec![iface_target("missing", 1)]),
    ];

    let result = collect_target_refresh_result(&configs, &wan_infos, &LinkHealths::new());

    assert_eq!(result.get(&1).unwrap().len(), 1);
    assert!(result.get(&2).unwrap().is_empty());
    assert!(result.get(&3).unwrap().is_empty());
}

#[test]
fn collect_refresh_health_filters_multi_target_and_fails_open() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert(link_owner("wan1"), ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 1)));
    wan_infos.insert(link_owner("wan2"), ipv4_wan_route("wan2", Ipv4Addr::new(203, 0, 113, 1)));

    let configs = vec![
        flow_config(4, true, vec![iface_target("wan2", 1)]),
        flow_config(5, true, vec![iface_target("wan1", 2), iface_target("wan2", 3)]),
    ];

    // Unknown health (or missing health_check) keeps both targets.
    let mut healths = LinkHealths::new();
    healths
        .insert(named_uuid("wan1"), health_info(named_uuid("wan1"), WanLinkHealthState::Unknown));
    let res = collect_target_refresh_result(&configs, &wan_infos, &healths);
    assert_eq!(res.get(&5).unwrap().len(), 2);

    // WAN1 Unhealthy, WAN2 Healthy: Flow 5 converges to WAN2 only; Flow 4 stays WAN2.
    healths
        .insert(named_uuid("wan1"), health_info(named_uuid("wan1"), WanLinkHealthState::Unhealthy));
    healths
        .insert(named_uuid("wan2"), health_info(named_uuid("wan2"), WanLinkHealthState::Healthy));
    let res = collect_target_refresh_result(&configs, &wan_infos, &healths);
    let flow5 = res.get(&5).unwrap();
    assert_eq!(flow5.len(), 1);
    assert_eq!(flow5[0].0.info.iface_name, "wan2");
    assert_eq!(flow5[0].1, 3);
    assert_eq!(res.get(&4).unwrap().len(), 1);

    // WAN1 Unhealthy, WAN2 Unknown: Unknown is treated as available, so Flow 5 converges to WAN2.
    healths
        .insert(named_uuid("wan2"), health_info(named_uuid("wan2"), WanLinkHealthState::Unknown));
    let res = collect_target_refresh_result(&configs, &wan_infos, &healths);
    assert_eq!(res.get(&5).unwrap().len(), 1);
    assert_eq!(res.get(&5).unwrap()[0].0.info.iface_name, "wan2");

    // Both Unhealthy: Flow 5 fails open (keeps both), and single-target Flow 4 keeps WAN2.
    healths
        .insert(named_uuid("wan2"), health_info(named_uuid("wan2"), WanLinkHealthState::Unhealthy));
    let res = collect_target_refresh_result(&configs, &wan_infos, &healths);
    assert_eq!(
        res.get(&5).unwrap().len(),
        2,
        "multi-target flow must fail open when all unhealthy"
    );
    let flow4 = res.get(&4).unwrap();
    assert_eq!(flow4.len(), 1, "single-target isolated flow must fail open and stay pinned");
    assert_eq!(flow4[0].0.info.iface_name, "wan2");

    // WAN1 Healthy, WAN2 Unhealthy: Flow 5 converges to WAN1, Flow 4 STILL stays pinned to WAN2.
    healths
        .insert(named_uuid("wan1"), health_info(named_uuid("wan1"), WanLinkHealthState::Healthy));
    let res = collect_target_refresh_result(&configs, &wan_infos, &healths);
    assert_eq!(res.get(&5).unwrap().len(), 1);
    assert_eq!(res.get(&5).unwrap()[0].0.info.iface_name, "wan1");
    assert_eq!(res.get(&4).unwrap().len(), 1);
    assert_eq!(
        res.get(&4).unwrap()[0].0.info.iface_name,
        "wan2",
        "single-target isolated flow must never leak to another WAN"
    );
}

#[test]
fn collect_refresh_zero_weight_healthy_target_fails_open() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert(link_owner("wan1"), ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 1)));
    wan_infos.insert(link_owner("wan2"), ipv4_wan_route("wan2", Ipv4Addr::new(203, 0, 113, 1)));

    let configs =
        vec![flow_config(5, true, vec![iface_target("wan1", 2), iface_target("wan2", 0)])];
    let mut healths = LinkHealths::new();
    healths
        .insert(named_uuid("wan1"), health_info(named_uuid("wan1"), WanLinkHealthState::Unhealthy));
    healths
        .insert(named_uuid("wan2"), health_info(named_uuid("wan2"), WanLinkHealthState::Healthy));

    let res = collect_target_refresh_result(&configs, &wan_infos, &healths);
    assert_eq!(
        res.get(&5).unwrap().len(),
        2,
        "must not filter down to only zero-weight targets and blackhole the flow"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Kernel default-route sync
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum LanRouteOp {
    Add(LanRouteInfo),
    Del(LanRouteInfo),
}

/// No-op dataplane recording every `sync_kernel_default_ipv4` /
/// `sync_kernel_default_ipv6` payload and `add_lan_route`/`del_lan_route`
/// call; `set_fail_next*` makes the next matching kernel-default sync report
/// failure.
#[derive(Default)]
struct RecordingRouteDataplane {
    calls: std::sync::Mutex<Vec<Vec<RouteTargetInfo>>>,
    v6_calls: std::sync::Mutex<Vec<Vec<RouteTargetInfo>>>,
    lan_ops: std::sync::Mutex<Vec<LanRouteOp>>,
    fail_next: std::sync::atomic::AtomicBool,
    fail_next_v6: std::sync::atomic::AtomicBool,
    policy_calls: std::sync::Mutex<Vec<Vec<WanRouteTarget>>>,
    fail_next_policy: std::sync::atomic::AtomicBool,
    wan_slots_v4: std::sync::Mutex<HashMap<FlowId, Vec<(WanRouteTarget, u32)>>>,
    wan_slots_v6: std::sync::Mutex<HashMap<FlowId, Vec<(WanRouteTarget, u32)>>>,
    lan_cache_invalidations: std::sync::atomic::AtomicUsize,
}

impl RecordingRouteDataplane {
    fn calls(&self) -> Vec<Vec<RouteTargetInfo>> {
        self.calls.lock().unwrap().clone()
    }

    fn v6_calls(&self) -> Vec<Vec<RouteTargetInfo>> {
        self.v6_calls.lock().unwrap().clone()
    }

    fn take_lan_ops(&self) -> Vec<LanRouteOp> {
        std::mem::take(&mut *self.lan_ops.lock().unwrap())
    }

    fn set_fail_next(&self) {
        self.fail_next.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn set_fail_next_v6(&self) {
        self.fail_next_v6.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn policy_calls(&self) -> Vec<Vec<WanRouteTarget>> {
        self.policy_calls.lock().unwrap().clone()
    }

    fn set_fail_next_policy(&self) {
        self.fail_next_policy.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn slots_v4(&self, flow_id: FlowId) -> Option<Vec<(WanRouteTarget, u32)>> {
        self.wan_slots_v4.lock().unwrap().get(&flow_id).cloned()
    }

    fn slots_v6(&self, flow_id: FlowId) -> Option<Vec<(WanRouteTarget, u32)>> {
        self.wan_slots_v6.lock().unwrap().get(&flow_id).cloned()
    }

    fn lan_cache_invalidations(&self) -> usize {
        self.lan_cache_invalidations.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl landscape_common::sys_service::route_service::dataplane::RouteTableDataplane
    for RecordingRouteDataplane
{
    fn add_lan_route(&self, info: LanRouteInfo) {
        self.lan_ops.lock().unwrap().push(LanRouteOp::Add(info));
    }

    fn del_lan_route(&self, info: LanRouteInfo) {
        self.lan_ops.lock().unwrap().push(LanRouteOp::Del(info));
    }

    fn replace_wan_slots_v4(&self, flow_id: FlowId, targets: &[(WanRouteTarget, u32)]) {
        self.wan_slots_v4.lock().unwrap().insert(flow_id, targets.to_vec());
    }

    fn replace_wan_slots_v6(&self, flow_id: FlowId, targets: &[(WanRouteTarget, u32)]) {
        self.wan_slots_v6.lock().unwrap().insert(flow_id, targets.to_vec());
    }

    fn del_wan_slots_v4(&self, flow_id: FlowId) {
        self.wan_slots_v4.lock().unwrap().remove(&flow_id);
    }

    fn del_wan_slots_v6(&self, flow_id: FlowId) {
        self.wan_slots_v6.lock().unwrap().remove(&flow_id);
    }

    async fn sync_kernel_default_ipv4(&self, nexthops: &[RouteTargetInfo]) -> bool {
        self.calls.lock().unwrap().push(nexthops.to_vec());
        !self.fail_next.swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    async fn sync_kernel_default_ipv6(&self, nexthops: &[RouteTargetInfo]) -> bool {
        self.v6_calls.lock().unwrap().push(nexthops.to_vec());
        !self.fail_next_v6.swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    async fn sync_kernel_wan_policy_ipv4(&self, targets: &[WanRouteTarget]) -> bool {
        self.policy_calls.lock().unwrap().push(targets.to_vec());
        !self.fail_next_policy.swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    fn invalidate_lan_cache(&self) {
        self.lan_cache_invalidations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn kernel_default_nexthops_filters_dedups_and_sorts() {
    let mut routes = WanRoutesByOwner::new();
    routes.insert(link_owner("wan0"), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

    // Duplicate nexthop registered by another owner collapses into one.
    routes.insert(
        RouteOwner::Netns("dup".to_string()),
        ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 2)),
    );

    // Non-default routes never contribute.
    let mut non_default = ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 3));
    non_default.info.default_route = false;
    routes.insert(link_owner("wan1"), non_default);

    // A default route behind an IPv6 gateway is skipped (v4 route table).
    let mut v6_gateway = ipv4_wan_route("wan2", Ipv4Addr::new(198, 51, 100, 4));
    v6_gateway.info.gateway_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
    routes.insert(link_owner("wan2"), v6_gateway);

    let nexthops = super::wan::kernel_default_nexthops(&routes, &LinkHealths::new(), false);

    assert_eq!(nexthops.len(), 1);
    assert_eq!(nexthops[0].iface_name, "wan0");
    assert_eq!(nexthops[0].gateway_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
}

#[test]
fn kernel_default_skips_unspecified_gateway() {
    let mut routes = WanRoutesByOwner::new();

    // `via 0.0.0.0` is not a valid nexthop; such a route must be skipped.
    let mut unspecified = ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1));
    unspecified.info.gateway_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    routes.insert(link_owner("wan0"), unspecified);

    routes.insert(link_owner("wan1"), ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 2)));

    let nexthops = super::wan::kernel_default_nexthops(&routes, &LinkHealths::new(), false);

    assert_eq!(nexthops.len(), 1);
    assert_eq!(nexthops[0].iface_name, "wan1");
}

#[test]
fn kernel_default_clamps_zero_weight_and_normalizes() {
    let mut routes = WanRoutesByOwner::new();

    // The kernel rejects `weight 0`; it must be clamped to 1.
    let mut zero_weight = ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1));
    zero_weight.info.weight = 0;
    routes.insert(link_owner("wan0"), zero_weight);

    let nexthops = super::wan::kernel_default_nexthops(&routes, &LinkHealths::new(), false);

    assert_eq!(nexthops.len(), 1);
    assert_eq!(nexthops[0].weight, 1);
    assert_eq!(nexthops[0].ifindex, 0);
    assert_eq!(nexthops[0].mac, None);
    assert_eq!(nexthops[0].iface_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
}

#[test]
fn kernel_default_route_syncs_on_change_only() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        let owner_a = link_owner("wan0");
        let owner_b = link_owner("wan1");
        service
            .insert_ipv4_wan_route(&owner_a, ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)))
            .await;
        service.reconcile_kernel_default_ipv4().await;
        assert_eq!(dataplane.calls().len(), 1);
        assert_eq!(dataplane.calls()[0].len(), 1);

        // Second default link joins the ECMP set.
        service
            .insert_ipv4_wan_route(&owner_b, ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 2)))
            .await;
        service.reconcile_kernel_default_ipv4().await;
        assert_eq!(dataplane.calls().len(), 2);
        assert_eq!(dataplane.calls()[1].len(), 2);

        // An IPv6-only default change must not rewrite the v4 kernel route.
        service.insert_ipv6_wan_route(&owner_a, ipv6_wan_default_route("wan0")).await;
        service.reconcile_kernel_default_ipv4().await;
        assert_eq!(dataplane.calls().len(), 2);

        // Removing one default link regenerates the set without it.
        service.remove_ipv4_wan_route(&owner_a).await;
        service.reconcile_kernel_default_ipv4().await;
        assert_eq!(dataplane.calls().len(), 3);
        assert_eq!(dataplane.calls()[2].len(), 1);
        assert_eq!(dataplane.calls()[2][0].iface_name, "wan1");

        // Removing the last default link propagates an empty target set;
        // the dataplane leaves whatever kernel default route exists alone.
        service.remove_ipv4_wan_route(&owner_b).await;
        service.reconcile_kernel_default_ipv4().await;
        assert_eq!(dataplane.calls().len(), 4);
        assert!(dataplane.calls()[3].is_empty());
    });
}

#[test]
fn kernel_default_retries_after_failed_sync() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        service
            .insert_ipv4_wan_route(
                &link_owner("wan0"),
                ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)),
            )
            .await;

        // First sync attempt fails: the cache must stay `None` so the next
        // reconcile retries instead of skipping.
        dataplane.set_fail_next();
        service.reconcile_kernel_default_ipv4().await;
        assert_eq!(dataplane.calls().len(), 1);

        service.reconcile_kernel_default_ipv4().await;
        assert_eq!(dataplane.calls().len(), 2);
        assert_eq!(dataplane.calls()[1].len(), 1);

        // Success converged the cache; no further calls.
        service.reconcile_kernel_default_ipv4().await;
        assert_eq!(dataplane.calls().len(), 2);
    });
}

#[test]
fn kernel_default_burst_converges_in_single_reconcile() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        // Two WAN links come up back to back: both doorbells ring before
        // the (single-writer) reconcile pass runs, so one snapshot-based
        // reconcile covers both — no stale intermediate state can be
        // committed.
        service
            .insert_ipv4_wan_route(
                &link_owner("wan0"),
                ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)),
            )
            .await;
        service
            .insert_ipv4_wan_route(
                &link_owner("wan1"),
                ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 2)),
            )
            .await;

        service.reconcile_kernel_default_ipv4().await;

        assert_eq!(dataplane.calls().len(), 1);
        assert_eq!(dataplane.calls()[0].len(), 2);
    });
}

#[test]
fn kernel_default_v6_nexthops_filters_dedups_and_sorts() {
    let mut routes = WanRoutesByOwner::new();
    routes.insert(link_owner("wan0"), ipv6_wan_route("wan0", "2001:db8::1".parse().unwrap()));

    // Duplicate nexthop registered by another owner collapses into one.
    routes.insert(
        RouteOwner::Netns("dup".to_string()),
        ipv6_wan_route("wan0", "2001:db8::1".parse().unwrap()),
    );

    // Non-default routes never contribute.
    let mut non_default = ipv6_wan_route("wan1", "2001:db8::2".parse().unwrap());
    non_default.info.default_route = false;
    routes.insert(link_owner("wan1"), non_default);

    // A default route behind an IPv4 gateway is skipped (v6 route table).
    let mut v4_gateway = ipv6_wan_route("wan2", "2001:db8::3".parse().unwrap());
    v4_gateway.info.gateway_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    routes.insert(link_owner("wan2"), v4_gateway);

    let nexthops = super::wan::kernel_default_nexthops_v6(&routes, &LinkHealths::new(), false);

    assert_eq!(nexthops.len(), 1);
    assert_eq!(nexthops[0].iface_name, "wan0");
    assert_eq!(nexthops[0].gateway_ip, IpAddr::V6("2001:db8::1".parse().unwrap()));
}

#[test]
fn kernel_default_v6_skips_unspecified_gateway() {
    let mut routes = WanRoutesByOwner::new();

    // `via ::` is not a valid nexthop; such a route must be skipped.
    routes.insert(link_owner("wan0"), ipv6_wan_route("wan0", Ipv6Addr::UNSPECIFIED));
    routes.insert(link_owner("wan1"), ipv6_wan_route("wan1", "2001:db8::2".parse().unwrap()));

    let nexthops = super::wan::kernel_default_nexthops_v6(&routes, &LinkHealths::new(), false);

    assert_eq!(nexthops.len(), 1);
    assert_eq!(nexthops[0].iface_name, "wan1");
}

#[test]
fn kernel_default_v6_clamps_zero_weight_and_normalizes() {
    let mut routes = WanRoutesByOwner::new();

    // The kernel rejects `weight 0`; it must be clamped to 1.
    let mut zero_weight = ipv6_wan_route("wan0", "2001:db8::1".parse().unwrap());
    zero_weight.info.weight = 0;
    routes.insert(link_owner("wan0"), zero_weight);

    let nexthops = super::wan::kernel_default_nexthops_v6(&routes, &LinkHealths::new(), false);

    assert_eq!(nexthops.len(), 1);
    assert_eq!(nexthops[0].weight, 1);
    assert_eq!(nexthops[0].ifindex, 0);
    assert_eq!(nexthops[0].mac, None);
    assert_eq!(nexthops[0].iface_ip, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
}

#[test]
fn kernel_default_v6_route_syncs_on_change_only() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        let owner_a = link_owner("wan0");
        let owner_b = link_owner("wan1");
        service
            .insert_ipv6_wan_route(&owner_a, ipv6_wan_route("wan0", "2001:db8::1".parse().unwrap()))
            .await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.v6_calls().len(), 1);
        assert_eq!(dataplane.v6_calls()[0].len(), 1);

        // An IPv4-only default change must not rewrite the v6 kernel route.
        service
            .insert_ipv4_wan_route(&owner_a, ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)))
            .await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.v6_calls().len(), 1);

        // Second default link joins the ECMP set.
        service
            .insert_ipv6_wan_route(&owner_b, ipv6_wan_route("wan1", "2001:db8::2".parse().unwrap()))
            .await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.v6_calls().len(), 2);
        assert_eq!(dataplane.v6_calls()[1].len(), 2);

        // Removing one default link regenerates the set without it.
        service.remove_ipv6_wan_route(&owner_a).await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.v6_calls().len(), 3);
        assert_eq!(dataplane.v6_calls()[2].len(), 1);
        assert_eq!(dataplane.v6_calls()[2][0].iface_name, "wan1");

        // Removing the last default link propagates an empty target set;
        // the dataplane leaves whatever kernel default route exists alone.
        service.remove_ipv6_wan_route(&owner_b).await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.v6_calls().len(), 4);
        assert!(dataplane.v6_calls()[3].is_empty());
    });
}

#[test]
fn kernel_default_v6_retries_after_failed_sync() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        service
            .insert_ipv6_wan_route(
                &link_owner("wan0"),
                ipv6_wan_route("wan0", "2001:db8::1".parse().unwrap()),
            )
            .await;

        // First sync attempt fails: the cache must stay `None` so the next
        // reconcile retries instead of skipping.
        dataplane.set_fail_next_v6();
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.v6_calls().len(), 1);

        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.v6_calls().len(), 2);
        assert_eq!(dataplane.v6_calls()[1].len(), 1);

        // Success converged the cache; no further calls.
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.v6_calls().len(), 2);
    });
}

// ─────────────────────────────────────────────────────────────────────────
// IPv4 WanReachable host /32 publication, ownership and withdrawal
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn ipv4_wan_reachable_subnet_publishes_and_withdraws_host_32_preserving_api_and_local_addrs() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());
        let wan_subnet =
            ipv4_lan_route(2, "wan0", Ipv4Addr::new(192, 0, 2, 10), 24, LanRouteMode::WanReachable);
        let wan_host = LanRouteInfo { prefix: 32, ..wan_subnet.clone() };

        service.insert_ipv4_lan_route("wan0", wan_subnet.clone()).await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![LanRouteOp::Add(wan_subnet.clone()), LanRouteOp::Add(wan_host.clone())]
        );

        // Stored API state preserves the single subnet record without duplicating /32,
        // and Reachable-only local address snapshots remain unaffected.
        let stored = service.get_all_ipv4_lan_routes().await;
        assert_eq!(stored.get("wan0"), Some(&vec![wan_subnet.clone()]));
        assert!(service.local_addr_view().load_ipv4_addrs().is_empty());

        // Identical re-publish is a no-op.
        service.insert_ipv4_lan_route("wan0", wan_subnet.clone()).await;
        assert!(dataplane.take_lan_ops().is_empty());

        service.remove_ipv4_lan_route("wan0").await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![LanRouteOp::Del(wan_subnet), LanRouteOp::Del(wan_host)]
        );
    });
}

#[test]
fn ipv6_later_lan_host_route_cannot_shadow_owned_wan_host() {
    run_async_test(async {
        let dp = std::sync::Arc::new(RecordingRouteDataplane::default());
        let routes = IpRouteService::new(dp.clone());
        let addr = "2001:db8::10".parse().unwrap();
        let key = |iface: &str| LanIPv6RouteKey {
            iface_name: iface.into(),
            subnet: addr,
            prefix_len: 128,
        };
        let wan = ipv6_lan_route(6, "wan", addr, 128, LanRouteMode::WanReachable);
        let lan = ipv6_lan_route(
            7,
            "lan",
            addr,
            128,
            LanRouteMode::NextHop { next_hop_ip: "2001:db8::1".parse().unwrap() },
        );
        routes.insert_ipv6_lan_route(key("wan"), wan.clone()).await;
        routes.insert_ipv6_lan_route(key("lan"), lan.clone()).await;
        assert_eq!(dp.take_lan_ops().last(), Some(&LanRouteOp::Add(wan)));
        routes.remove_ipv6_lan_route_by_key(&key("wan")).await;
        assert_eq!(dp.take_lan_ops(), vec![LanRouteOp::Add(lan)]);
    });
}

#[test]
fn ipv4_wan_reachable_32_does_not_duplicate_dataplane_ops() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());
        let ppp_host = ipv4_lan_route(
            7,
            "ppp0",
            Ipv4Addr::new(203, 0, 113, 5),
            32,
            LanRouteMode::WanReachable,
        );

        service.insert_ipv4_lan_route("ppp0", ppp_host.clone()).await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Add(ppp_host.clone())]);

        service.remove_ipv4_lan_route("ppp0").await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Del(ppp_host)]);
    });
}

#[test]
fn ipv4_wan_reachable_updates_withdraw_old_host_32_and_preserve_unrelated_bucket_routes() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        let unrelated =
            ipv4_lan_route(2, "eth0", Ipv4Addr::new(10, 0, 0, 1), 24, LanRouteMode::Reachable);
        let wan_a =
            ipv4_lan_route(2, "eth0", Ipv4Addr::new(192, 0, 2, 10), 24, LanRouteMode::WanReachable);
        let wan_a_host = LanRouteInfo { prefix: 32, ..wan_a.clone() };
        let wan_a2 =
            ipv4_lan_route(2, "eth0", Ipv4Addr::new(192, 0, 2, 20), 24, LanRouteMode::WanReachable);
        let wan_a2_host = LanRouteInfo { prefix: 32, ..wan_a2.clone() };
        let wan_b = ipv4_lan_route(
            2,
            "eth0",
            Ipv4Addr::new(198, 51, 100, 30),
            24,
            LanRouteMode::WanReachable,
        );
        let wan_b_host = LanRouteInfo { prefix: 32, ..wan_b.clone() };

        service.insert_ipv4_lan_route("eth0", unrelated.clone()).await;
        service.insert_ipv4_lan_route("eth0", wan_a.clone()).await;
        let _ = dataplane.take_lan_ops();

        // Same-subnet IP change: withdraws old /32, overwrites /24, publishes new /32.
        service.insert_ipv4_lan_route("eth0", wan_a2.clone()).await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![
                LanRouteOp::Del(wan_a_host),
                LanRouteOp::Add(wan_a2.clone()),
                LanRouteOp::Add(wan_a2_host.clone()),
            ]
        );
        assert_eq!(
            service.get_all_ipv4_lan_routes().await.get("eth0"),
            Some(&vec![unrelated.clone(), wan_a2.clone()])
        );

        // Cross-subnet change: withdraws old /24 and old /32, publishes new /24 and /32,
        // while keeping unrelated routes in the same owner bucket.
        service.insert_ipv4_lan_route("eth0", wan_b.clone()).await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![
                LanRouteOp::Del(wan_a2),
                LanRouteOp::Del(wan_a2_host),
                LanRouteOp::Add(wan_b.clone()),
                LanRouteOp::Add(wan_b_host.clone()),
            ]
        );
        assert_eq!(
            service.get_all_ipv4_lan_routes().await.get("eth0"),
            Some(&vec![unrelated.clone(), wan_b.clone()])
        );

        // Prefix change /24 -> /32 on same IP: withdraws /24 without deleting /32.
        service.insert_ipv4_lan_route("eth0", wan_b_host.clone()).await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![LanRouteOp::Del(wan_b), LanRouteOp::Add(wan_b_host.clone())]
        );
        assert_eq!(
            service.get_all_ipv4_lan_routes().await.get("eth0"),
            Some(&vec![unrelated, wan_b_host])
        );
    });
}

#[test]
fn ipv4_wan_reachable_two_owners_same_host_ip_survivor_handoff() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());
        let ip = Ipv4Addr::new(192, 0, 2, 10);

        let wan0 = ipv4_lan_route(2, "wan0", ip, 24, LanRouteMode::WanReachable);
        let wan0_host = LanRouteInfo { prefix: 32, ..wan0.clone() };
        let wan1_host = ipv4_lan_route(5, "wan1", ip, 32, LanRouteMode::WanReachable);

        service.insert_ipv4_lan_route("wan0", wan0.clone()).await;
        let _ = dataplane.take_lan_ops();

        // Higher-ifindex owner does not replace lower-ifindex winner on /32.
        service.insert_ipv4_lan_route("wan1", wan1_host.clone()).await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Add(wan0_host)]);

        // Removing wan0 withdraws its /24 and hands /32 over to surviving wan1 without deleting /32.
        service.remove_ipv4_lan_route("wan0").await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![LanRouteOp::Del(wan0), LanRouteOp::Add(wan1_host.clone())]
        );

        // Removing the last owner deletes /32.
        service.remove_ipv4_lan_route("wan1").await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Del(wan1_host)]);
    });
}

#[test]
fn ipv4_wan_reachable_overlapping_lpm_and_colliding_host_32_precedence() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        // Overlapping more-specific LAN /25 + WAN /24.
        let lan25 =
            ipv4_lan_route(1, "lan0", Ipv4Addr::new(192, 0, 2, 1), 25, LanRouteMode::Reachable);
        let wan24 =
            ipv4_lan_route(2, "wan0", Ipv4Addr::new(192, 0, 2, 10), 24, LanRouteMode::WanReachable);
        let wan_host = LanRouteInfo { prefix: 32, ..wan24.clone() };

        service.insert_ipv4_lan_route("lan0", lan25.clone()).await;
        let _ = dataplane.take_lan_ops();

        service.insert_ipv4_lan_route("wan0", wan24.clone()).await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![LanRouteOp::Add(wan24.clone()), LanRouteOp::Add(wan_host.clone())]
        );

        service.remove_ipv4_lan_route("wan0").await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![LanRouteOp::Del(wan24.clone()), LanRouteOp::Del(wan_host.clone())]
        );
        assert_eq!(service.get_all_ipv4_lan_routes().await.get("lan0"), Some(&vec![lan25]));

        // Same-subnet LAN /24 + WAN /24: normal last-publish on insert, restore LAN on withdraw.
        let lan24 =
            ipv4_lan_route(3, "lan1", Ipv4Addr::new(192, 0, 2, 1), 24, LanRouteMode::Reachable);
        service.insert_ipv4_lan_route("lan1", lan24.clone()).await;
        let _ = dataplane.take_lan_ops();

        service.insert_ipv4_lan_route("wan0", wan24.clone()).await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![LanRouteOp::Add(wan24.clone()), LanRouteOp::Add(wan_host.clone())]
        );

        service.remove_ipv4_lan_route("wan0").await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![LanRouteOp::Add(lan24), LanRouteOp::Del(wan_host.clone())]
        );

        // Colliding /32 host route: WanReachable takes precedence and withdrawal restores Reachable.
        let lan32 =
            ipv4_lan_route(1, "lan32", Ipv4Addr::new(192, 0, 2, 10), 32, LanRouteMode::Reachable);
        service.insert_ipv4_lan_route("lan32", lan32.clone()).await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Add(lan32.clone())]);

        service.insert_ipv4_lan_route("wan0", wan24.clone()).await;
        assert_eq!(
            dataplane.take_lan_ops(),
            vec![LanRouteOp::Add(wan24.clone()), LanRouteOp::Add(wan_host.clone())]
        );

        // A later Reachable /32 on the same IP must not clobber the active WanReachable /32.
        let lan32_b =
            ipv4_lan_route(4, "lan32-b", Ipv4Addr::new(192, 0, 2, 10), 32, LanRouteMode::Reachable);
        service.insert_ipv4_lan_route("lan32-b", lan32_b).await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Add(wan_host)]);

        service.remove_ipv4_lan_route("wan0").await;
        let ops = dataplane.take_lan_ops();
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0],
            LanRouteOp::Add(ipv4_lan_route(
                3,
                "lan1",
                Ipv4Addr::new(192, 0, 2, 1),
                24,
                LanRouteMode::Reachable,
            ))
        );
        assert_eq!(ops[1], LanRouteOp::Add(lan32));
    });
}

#[test]
fn ipv4_reachable_and_nexthop_do_not_synthesize_host_32() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());
        let reachable =
            ipv4_lan_route(1, "lan0", Ipv4Addr::new(192, 168, 1, 1), 24, LanRouteMode::Reachable);
        let nexthop = ipv4_lan_route(
            1,
            "lan0",
            Ipv4Addr::new(10, 10, 0, 0),
            24,
            LanRouteMode::NextHop {
                next_hop_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            },
        );

        service.insert_ipv4_lan_route("lan0", reachable.clone()).await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Add(reachable.clone())]);

        service.insert_ipv4_lan_route("lan0-static", nexthop.clone()).await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Add(nexthop.clone())]);

        service.remove_ipv4_lan_route("lan0").await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Del(reachable)]);

        service.remove_ipv4_lan_route("lan0-static").await;
        assert_eq!(dataplane.take_lan_ops(), vec![LanRouteOp::Del(nexthop)]);
    });
}

#[test]
fn dual_wan_ipv6_default_selects_primary_only_while_secondary_serves_custom_flows() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        let wan1_owner = link_owner("enp1s0.105");
        let wan2_owner = link_owner("enp1s0.101");

        let mut wan1_v6 = WanRouteTarget::link(
            2,
            RouteTargetInfo::new_gateway_v6(
                10,
                "enp1s0.105",
                None,
                Ipv6Addr::new(0x240e, 0x1, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                true,
            ),
        );
        let wan2_v6 = WanRouteTarget::link(
            3,
            RouteTargetInfo::new_gateway_v6(
                11,
                "enp1s0.101",
                None,
                Ipv6Addr::new(0x2409, 0x2, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                false,
            ),
        );

        // Even if WAN2 ("enp1s0.101", lexicographically smaller) registers first,
        // it must not become Flow 0 default because default_route == false.
        service.insert_ipv6_wan_route(&wan2_owner, wan2_v6.clone()).await;
        assert!(dataplane.slots_v6(0).is_none());

        service.insert_ipv6_wan_route(&wan1_owner, wan1_v6.clone()).await;
        let flow0_v6 = dataplane.slots_v6(0).expect("flow 0 v6 default must be populated");
        assert_eq!(flow0_v6.len(), 1);
        assert_eq!(flow0_v6[0].0.info.iface_name, "enp1s0.105");

        // Re-updating WAN2 keeps WAN1 pinned on Flow 0.
        wan1_v6.info.gateway_ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        service.insert_ipv6_wan_route(&wan2_owner, wan2_v6.clone()).await;
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "enp1s0.105");

        // Meanwhile WAN2 participates in Flow 4 (single) and Flow 5 (ECMP).
        let flows = vec![
            flow_config(4, true, vec![iface_target("enp1s0.101", 1)]),
            flow_config(
                5,
                true,
                vec![iface_target("enp1s0.105", 2), iface_target("enp1s0.101", 3)],
            ),
        ];
        service.sync_flow_wan_targets(&flows).await;

        let flow4_v6 = dataplane.slots_v6(4).expect("flow 4 v6 targets");
        assert_eq!(flow4_v6.len(), 1);
        assert_eq!(flow4_v6[0].0.info.iface_name, "enp1s0.101");

        let flow5_v6 = dataplane.slots_v6(5).expect("flow 5 v6 targets");
        assert_eq!(flow5_v6.len(), 2);
        assert_eq!(flow5_v6[0].0.info.iface_name, "enp1s0.105");
        assert_eq!(flow5_v6[0].1, 2);
        assert_eq!(flow5_v6[1].0.info.iface_name, "enp1s0.101");
        assert_eq!(flow5_v6[1].1, 3);
    });
}

#[test]
fn default_router_selection_is_deterministic_across_multiple_default_wans() {
    for _ in 0..32 {
        let mut routes_v4 = WanRoutesByOwner::new();
        routes_v4.insert(
            link_owner("wan-b"),
            WanRouteTarget::link(2, ipv4_wan_route("wan-b", Ipv4Addr::new(198, 51, 100, 2)).info),
        );
        routes_v4.insert(
            link_owner("wan-a"),
            WanRouteTarget::link(5, ipv4_wan_route("wan-a", Ipv4Addr::new(198, 51, 100, 1)).info),
        );
        routes_v4.insert(
            link_owner("wan-c"),
            WanRouteTarget::link(1, ipv4_wan_route("wan-c", Ipv4Addr::new(198, 51, 100, 3)).info),
        );
        let picked_v4 =
            super::wan::select_default_wan_route(&routes_v4, &LinkHealths::new(), false).unwrap();
        assert_eq!(picked_v4.info.iface_name, "wan-a");

        let mut routes_v6 = WanRoutesByOwner::new();
        routes_v6.insert(link_owner("wan-z"), ipv6_wan_default_route("wan-z"));
        routes_v6.insert(link_owner("wan-m"), ipv6_wan_default_route("wan-m"));
        routes_v6.insert(link_owner("wan-a"), ipv6_wan_default_route("wan-a"));
        let picked_v6 =
            super::wan::select_default_wan_route(&routes_v6, &LinkHealths::new(), false).unwrap();
        assert_eq!(picked_v6.info.iface_name, "wan-a");
    }
}

#[test]
fn default_router_dual_stack_failover_recovery_and_fail_open() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        let wan1_id = named_uuid("enp1s0.105");
        let wan2_id = named_uuid("enp1s0.101");

        let wan1_v4 = WanRouteTarget::link(
            2,
            RouteTargetInfo::new_gateway_v4(
                10,
                "enp1s0.105",
                None,
                Ipv4Addr::new(198, 51, 100, 10),
                Ipv4Addr::new(198, 51, 100, 1),
                true,
            ),
        );
        let wan2_v4 = WanRouteTarget::link(
            3,
            RouteTargetInfo::new_gateway_v4(
                11,
                "enp1s0.101",
                None,
                Ipv4Addr::new(203, 0, 113, 10),
                Ipv4Addr::new(203, 0, 113, 1),
                false,
            ),
        );
        let wan1_v6 = WanRouteTarget::link(
            2,
            RouteTargetInfo::new_gateway_v6(
                10,
                "enp1s0.105",
                None,
                Ipv6Addr::new(0x240e, 0x1, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                true,
            ),
        );
        let wan2_v6 = WanRouteTarget::link(
            3,
            RouteTargetInfo::new_gateway_v6(
                11,
                "enp1s0.101",
                None,
                Ipv6Addr::new(0x2409, 0x2, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                false,
            ),
        );
        let (docker_v4, docker_v6) = RouteTargetInfo::new_docker(99, "sing-box-flow1");

        service.insert_ipv4_link_route(wan1_id, wan1_v4).await;
        service.insert_ipv6_link_route(wan1_id, wan1_v6).await;
        service.insert_ipv4_link_route(wan2_id, wan2_v4).await;
        service.insert_ipv6_link_route(wan2_id, wan2_v6).await;
        service
            .insert_ipv4_wan_route(
                &RouteOwner::Netns("sing-box-flow1".to_string()),
                WanRouteTarget::netns(docker_v4),
            )
            .await;
        service
            .insert_ipv6_wan_route(
                &RouteOwner::Netns("sing-box-flow1".to_string()),
                WanRouteTarget::netns(docker_v6),
            )
            .await;

        service.reconcile_kernel_default_ipv4().await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "enp1s0.105");
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "enp1s0.105");
        assert_eq!(dataplane.calls().last().unwrap()[0].iface_name, "enp1s0.105");
        assert_eq!(dataplane.v6_calls().last().unwrap()[0].iface_name, "enp1s0.105");

        // Unknown -> Healthy transitions do not disturb Flow 0 or flush LAN cache unnecessarily.
        let invalidations_before = dataplane.lan_cache_invalidations();
        service.update_link_health(health_info(wan1_id, WanLinkHealthState::Healthy)).await;
        service.update_link_health(health_info(wan2_id, WanLinkHealthState::Healthy)).await;
        assert_eq!(dataplane.lan_cache_invalidations(), invalidations_before);

        // Primary flips Unhealthy: 0s dual-stack hot failover to WAN2 (eBPF v4/v6 + kernel v4/v6).
        service.update_link_health(health_info(wan1_id, WanLinkHealthState::Unhealthy)).await;
        service.reconcile_kernel_default_ipv4().await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "enp1s0.101");
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "enp1s0.101");
        assert_eq!(dataplane.calls().last().unwrap()[0].iface_name, "enp1s0.101");
        assert_eq!(dataplane.v6_calls().last().unwrap()[0].iface_name, "enp1s0.101");
        assert!(dataplane.lan_cache_invalidations() > invalidations_before);

        // Both WAN1 and WAN2 Unhealthy: fail-open stays on original primary WAN1, never Docker.
        service.update_link_health(health_info(wan2_id, WanLinkHealthState::Unhealthy)).await;
        service.reconcile_kernel_default_ipv4().await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "enp1s0.105");
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "enp1s0.105");
        assert_eq!(dataplane.calls().last().unwrap()[0].iface_name, "enp1s0.105");
        assert_eq!(dataplane.v6_calls().last().unwrap()[0].iface_name, "enp1s0.105");

        // WAN2 recovers while WAN1 remains Unhealthy: switches back to WAN2.
        service.update_link_health(health_info(wan2_id, WanLinkHealthState::Healthy)).await;
        service.reconcile_kernel_default_ipv4().await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "enp1s0.101");
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "enp1s0.101");
        assert_eq!(dataplane.calls().last().unwrap()[0].iface_name, "enp1s0.101");
        assert_eq!(dataplane.v6_calls().last().unwrap()[0].iface_name, "enp1s0.101");

        // Primary recovers Healthy: smoothly switches back to WAN1.
        service.update_link_health(health_info(wan1_id, WanLinkHealthState::Healthy)).await;
        service.reconcile_kernel_default_ipv4().await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "enp1s0.105");
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "enp1s0.105");
        assert_eq!(dataplane.calls().last().unwrap()[0].iface_name, "enp1s0.105");
        assert_eq!(dataplane.v6_calls().last().unwrap()[0].iface_name, "enp1s0.105");
    });
}

#[test]
fn default_router_treats_unknown_backup_as_available_and_prefers_verified_healthy_backup() {
    let mut routes = WanRoutesByOwner::new();
    let wan1_id = named_uuid("wan1");
    let wan2_id = named_uuid("wan2");
    let wan3_id = named_uuid("wan3");

    routes
        .insert(RouteOwner::Link(wan1_id), ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 1)));
    let mut wan2 = ipv4_wan_route("wan2", Ipv4Addr::new(203, 0, 113, 2));
    wan2.info.default_route = false;
    routes.insert(RouteOwner::Link(wan2_id), wan2);

    // WAN1 Unhealthy, WAN2 has no health entry (Unknown): WAN2 must be selected as backup.
    let mut healths = LinkHealths::new();
    healths.insert(wan1_id, health_info(wan1_id, WanLinkHealthState::Unhealthy));
    let picked = super::wan::select_default_wan_route(&routes, &healths, false).unwrap();
    assert_eq!(picked.info.iface_name, "wan2");

    // Add a third backup WAN3 verified Healthy: verified Healthy takes precedence over Unknown.
    let mut wan3 = ipv4_wan_route("wan3", Ipv4Addr::new(203, 0, 113, 3));
    wan3.info.default_route = false;
    routes.insert(RouteOwner::Link(wan3_id), wan3);
    healths.insert(wan3_id, health_info(wan3_id, WanLinkHealthState::Healthy));
    let picked = super::wan::select_default_wan_route(&routes, &healths, false).unwrap();
    assert_eq!(picked.info.iface_name, "wan3");
}

#[test]
fn default_router_fails_over_when_primary_route_drops_with_active_intent_and_respects_no_default() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        let wan1_id = named_uuid("wan1");
        let wan2_id = named_uuid("wan2");

        let mut wan2_v4 = ipv4_wan_route("wan2", Ipv4Addr::new(203, 0, 113, 2));
        wan2_v4.info.default_route = false;
        let mut wan2_v6 = ipv6_wan_route("wan2", "2001:db8::2".parse().unwrap());
        wan2_v6.info.default_route = false;

        // With no default intent (--no-wan-default-route), non-default WAN2 stays off Flow 0.
        service.insert_ipv4_link_route(wan2_id, wan2_v4).await;
        service.insert_ipv6_link_route(wan2_id, wan2_v6).await;
        service.reconcile_kernel_default_ipv4().await;
        service.reconcile_kernel_default_ipv6().await;
        assert!(dataplane.slots_v4(0).is_none());
        assert!(dataplane.slots_v6(0).is_none());
        assert!(dataplane.calls().last().unwrap().is_empty());
        assert!(dataplane.v6_calls().last().unwrap().is_empty());

        // Primary WAN1 is configured as default (active link) and currently up.
        service.set_link_default_intent(wan1_id, true, true).await;
        service
            .insert_ipv4_link_route(wan1_id, ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 1)))
            .await;
        service
            .insert_ipv6_link_route(wan1_id, ipv6_wan_route("wan1", "2001:db8::1".parse().unwrap()))
            .await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "wan1");
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "wan1");

        // Primary PPPoE session drops (routes removed while redialing): Flow 0 & kernel routes fail over to WAN2.
        service.remove_ipv4_link_route(wan1_id).await;
        service.remove_ipv6_link_route(wan1_id).await;
        service.reconcile_kernel_default_ipv4().await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "wan2");
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "wan2");
        assert_eq!(dataplane.calls().last().unwrap()[0].iface_name, "wan2");
        assert_eq!(dataplane.v6_calls().last().unwrap()[0].iface_name, "wan2");

        // Primary comes back online: Flow 0 & kernel routes switch back to WAN1.
        service
            .insert_ipv4_link_route(wan1_id, ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 1)))
            .await;
        service
            .insert_ipv6_link_route(wan1_id, ipv6_wan_route("wan1", "2001:db8::1".parse().unwrap()))
            .await;
        service.reconcile_kernel_default_ipv4().await;
        service.reconcile_kernel_default_ipv6().await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "wan1");
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "wan1");
        assert_eq!(dataplane.calls().last().unwrap()[0].iface_name, "wan1");
        assert_eq!(dataplane.v6_calls().last().unwrap()[0].iface_name, "wan1");

        // Removing primary link completely (clear intent + remove routes): non-default WAN2 is not forced.
        service.clear_link_default_intent(wan1_id).await;
        service.remove_ipv4_link_route(wan1_id).await;
        service.remove_ipv6_link_route(wan1_id).await;
        assert!(dataplane.slots_v4(0).is_none());
        assert!(dataplane.slots_v6(0).is_none());
    });
}

#[test]
fn default_router_never_fails_over_to_docker_netns() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());
        let wan1_id = named_uuid("wan1");
        let (docker_v4, docker_v6) = RouteTargetInfo::new_docker(99, "sing-box-flow1");

        service
            .insert_ipv4_link_route(wan1_id, ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 1)))
            .await;
        service.insert_ipv6_link_route(wan1_id, ipv6_wan_default_route("wan1")).await;
        service
            .insert_ipv4_wan_route(
                &RouteOwner::Netns("sing-box-flow1".to_string()),
                WanRouteTarget::netns(docker_v4),
            )
            .await;
        service
            .insert_ipv6_wan_route(
                &RouteOwner::Netns("sing-box-flow1".to_string()),
                WanRouteTarget::netns(docker_v6),
            )
            .await;

        service.update_link_health(health_info(wan1_id, WanLinkHealthState::Unhealthy)).await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "wan1");
        assert_eq!(dataplane.slots_v6(0).unwrap()[0].0.info.iface_name, "wan1");
    });
}

#[test]
fn concurrent_route_and_health_updates_converge_without_deadlock() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());

        let wan1_id = named_uuid("wan1");
        let wan2_id = named_uuid("wan2");
        let mut wan2_v4 = ipv4_wan_route("wan2", Ipv4Addr::new(203, 0, 113, 2));
        wan2_v4.info.default_route = false;

        service
            .insert_ipv4_link_route(wan1_id, ipv4_wan_route("wan1", Ipv4Addr::new(198, 51, 100, 1)))
            .await;
        service.insert_ipv4_link_route(wan2_id, wan2_v4.clone()).await;

        let flows =
            vec![flow_config(5, true, vec![iface_target("wan1", 2), iface_target("wan2", 3)])];

        let s1 = service.clone();
        let s2 = service.clone();
        let s3 = service.clone();
        let flows_clone = flows.clone();
        tokio::join!(
            async move {
                for i in 0..30 {
                    let state = if i % 2 == 0 {
                        WanLinkHealthState::Unhealthy
                    } else {
                        WanLinkHealthState::Healthy
                    };
                    s1.update_link_health(health_info(wan1_id, state)).await;
                }
                s1.update_link_health(health_info(wan1_id, WanLinkHealthState::Unhealthy)).await;
            },
            async move {
                for i in 0..30 {
                    let mut route = wan2_v4.clone();
                    route.info.iface_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, (10 + i) as u8));
                    s2.insert_ipv4_link_route(wan2_id, route).await;
                }
            },
            async move {
                for _ in 0..30 {
                    s3.sync_flow_wan_targets(&flows_clone).await;
                }
            }
        );

        // Final settle sync confirms exact convergence to healthy WAN2.
        service.sync_flow_wan_targets(&flows).await;
        assert_eq!(dataplane.slots_v4(0).unwrap()[0].0.info.iface_name, "wan2");
        let flow5 = dataplane.slots_v4(5).unwrap();
        assert_eq!(flow5.len(), 1);
        assert_eq!(flow5[0].0.info.iface_name, "wan2");
    });
}

#[test]
fn kernel_wan_policy_targets_includes_all_active_v4_links_and_excludes_invalid() {
    let mut routes = WanRoutesByOwner::new();

    let wan1 = WanRouteTarget::link(
        2,
        RouteTargetInfo::new_gateway_v4(
            5,
            "enp1s0.105",
            None,
            Ipv4Addr::new(100, 65, 89, 96),
            Ipv4Addr::new(100, 65, 0, 1),
            true,
        ),
    );
    let wan2 = WanRouteTarget::link(
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
    // Excluded: unassigned chain_id == 0
    let chain_zero = WanRouteTarget::link(
        0,
        RouteTargetInfo::new_gateway_v4(
            6,
            "eth1",
            None,
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            false,
        ),
    );
    // Excluded: ifindex == 0
    let ifindex_zero = WanRouteTarget::link(
        5,
        RouteTargetInfo::new_gateway_v4(
            0,
            "eth2",
            None,
            Ipv4Addr::new(192, 0, 2, 11),
            Ipv4Addr::new(192, 0, 2, 1),
            false,
        ),
    );
    // Excluded: unspecified gateway (non-p2p)
    let bad_gw = WanRouteTarget::link(
        6,
        RouteTargetInfo::new_gateway_v4(
            7,
            "eth3",
            None,
            Ipv4Addr::new(192, 0, 2, 12),
            Ipv4Addr::UNSPECIFIED,
            false,
        ),
    );
    let (docker_v4, _) = RouteTargetInfo::new_docker(99, "sing-box-flow1");

    routes.insert(link_owner("wan2"), wan2);
    routes.insert(link_owner("pppd"), pppd);
    routes.insert(link_owner("wan1"), wan1);
    routes.insert(link_owner("chain_zero"), chain_zero);
    routes.insert(link_owner("ifindex_zero"), ifindex_zero);
    routes.insert(link_owner("bad_gw"), bad_gw);
    routes
        .insert(RouteOwner::Netns("sing-box-flow1".to_string()), WanRouteTarget::netns(docker_v4));

    let targets = super::wan::kernel_wan_policy_targets(&routes);
    let summary: Vec<(u16, &str, u32, bool)> = targets
        .iter()
        .map(|t| {
            (t.link_chain_id, t.info.iface_name.as_str(), t.info.ifindex, t.info.dev_only_nexthop)
        })
        .collect();
    assert_eq!(
        summary,
        vec![(2, "enp1s0.105", 5, false), (3, "enp1s0.101", 37, false), (4, "ppp0", 40, true),]
    );
    assert_eq!(targets[1].info.iface_ip, IpAddr::V4(Ipv4Addr::new(100, 65, 247, 59)));
    assert_eq!(targets[1].info.gateway_ip, IpAddr::V4(Ipv4Addr::new(100, 65, 0, 1)));
}

#[test]
fn reconcile_kernel_wan_policy_caches_retries_and_cleans_up_empty() {
    run_async_test(async {
        let dataplane = std::sync::Arc::new(RecordingRouteDataplane::default());
        let service = IpRouteService::new(dataplane.clone());
        let wan1_id = named_uuid("enp1s0.105");
        let wan2_id = named_uuid("enp1s0.101");

        // Startup reconcile with empty routes still invokes dataplane once to purge stale rules.
        service.reconcile_kernel_wan_policy_ipv4().await;
        assert_eq!(dataplane.policy_calls().len(), 1);
        assert!(dataplane.policy_calls()[0].is_empty());

        // Second identical empty pass is deduplicated by the cache.
        service.reconcile_kernel_wan_policy_ipv4().await;
        assert_eq!(dataplane.policy_calls().len(), 1);

        let wan1 = WanRouteTarget::link(
            2,
            RouteTargetInfo::new_gateway_v4(
                5,
                "enp1s0.105",
                None,
                Ipv4Addr::new(100, 65, 89, 96),
                Ipv4Addr::new(100, 65, 0, 1),
                true,
            ),
        );
        let wan2 = WanRouteTarget::link(
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

        service.insert_ipv4_link_route(wan1_id, wan1.clone()).await;
        service.insert_ipv4_link_route(wan2_id, wan2.clone()).await;

        // Failed sync leaves cache dirty so the next pass retries.
        dataplane.set_fail_next_policy();
        service.reconcile_kernel_wan_policy_ipv4().await;
        assert_eq!(dataplane.policy_calls().len(), 2);

        service.reconcile_kernel_wan_policy_ipv4().await;
        assert_eq!(dataplane.policy_calls().len(), 3);
        assert_eq!(dataplane.policy_calls()[2].len(), 2);

        // Health failover changes Flow 0 default route but must not churn per-link policy routes.
        service.update_link_health(health_info(wan1_id, WanLinkHealthState::Unhealthy)).await;
        service.reconcile_kernel_wan_policy_ipv4().await;
        assert_eq!(dataplane.policy_calls().len(), 3);

        // Removing both links pushes an empty target slice to clean up rules and tables.
        service.remove_ipv4_link_route(wan2_id).await;
        service.reconcile_kernel_wan_policy_ipv4().await;
        assert_eq!(dataplane.policy_calls().len(), 4);
        assert_eq!(dataplane.policy_calls()[3].len(), 1);
        assert_eq!(dataplane.policy_calls()[3][0].link_chain_id, 2);

        service.remove_ipv4_link_route(wan1_id).await;
        service.reconcile_kernel_wan_policy_ipv4().await;
        assert_eq!(dataplane.policy_calls().len(), 5);
        assert!(dataplane.policy_calls()[4].is_empty());
    });
}
