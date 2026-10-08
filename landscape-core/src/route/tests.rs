use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use landscape_common::{
    ddns::IpFamily,
    flow::{FlowTarget, WeightedFlowTarget, config::FlowConfig},
    sys_service::route_service::{LanIPv6RouteKey, LanRouteInfo, LanRouteMode, RouteTargetInfo},
};
use uuid::Uuid;

use super::flow_target::collect_target_refresh_result;
use super::lan::{Ipv4LanBucketUpdate, Ipv6LanRouteUpdate, reconcile_ipv4_lan_bucket};
use super::wan::{WanRouteEvent, WanRouteEventKind};
use super::*;

fn ipv4_wan_route(iface_name: &str, iface_ip: Ipv4Addr) -> RouteTargetInfo {
    RouteTargetInfo {
        weight: 1,
        ifindex: 1,
        mac: None,
        default_route: true,
        is_docker: false,
        iface_name: iface_name.to_string(),
        iface_ip: IpAddr::V4(iface_ip),
        gateway_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    }
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

        service.insert_ipv4_wan_route("wan0", route.clone()).await;
        assert_eq!(
            events.recv().await.unwrap(),
            WanRouteEvent {
                owner: "wan0".to_string(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        );

        service.insert_ipv4_wan_route("wan0", route).await;
        assert!(tokio::time::timeout(Duration::from_millis(50), events.recv()).await.is_err());

        service.remove_ipv4_wan_route("wan0").await;
        assert_eq!(
            events.recv().await.unwrap(),
            WanRouteEvent {
                owner: "wan0".to_string(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Removed,
            }
        );
    });
}

#[test]
fn remove_all_wan_docker_notifies_and_refreshes_default_router() {
    run_async_test(async {
        let service = test_used_ip_route();
        let mut events = service.subscribe_wan_route_events();

        let mut docker_route = ipv4_wan_route("docker0", Ipv4Addr::new(172, 17, 0, 1));
        docker_route.is_docker = true;
        docker_route.default_route = false;
        service.insert_ipv4_wan_route("docker0", docker_route).await;
        service
            .insert_ipv4_wan_route("wan0", ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)))
            .await;
        let _ = events.recv().await; // docker0 upserted
        let _ = events.recv().await; // wan0 upserted

        service.remove_all_wan_docker().await;

        assert_eq!(
            events.recv().await.unwrap(),
            WanRouteEvent {
                owner: "docker0".to_string(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Removed,
            }
        );
        assert!(tokio::time::timeout(Duration::from_millis(50), events.recv()).await.is_err());
        assert!(service.get_ipv4_wan_route("docker0").await.is_none());
        assert!(service.get_ipv4_wan_route("wan0").await.is_some());
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

fn iface_target(name: &str, weight: u32) -> WeightedFlowTarget {
    WeightedFlowTarget::new(
        FlowTarget::Interface { link_id: uuid::Uuid::nil(), name: name.to_string() },
        weight,
    )
}

fn netns_target(container_name: &str, weight: u32) -> WeightedFlowTarget {
    WeightedFlowTarget::new(
        FlowTarget::Netns { container_name: container_name.to_string() },
        weight,
    )
}

#[test]
fn collect_refresh_enabled_flow_with_matching_targets() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert("wan0".to_string(), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));
    wan_infos.insert("wan1".to_string(), ipv4_wan_route("wan1", Ipv4Addr::new(203, 0, 113, 1)));

    let configs =
        vec![flow_config(5, true, vec![iface_target("wan0", 3), iface_target("wan1", 1)])];

    let result = collect_target_refresh_result(&configs, &wan_infos);

    let targets = result.get(&5).expect("flow_id 5 should be present");
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].1, 3); // weight preserved
    assert_eq!(targets[1].1, 1);
    assert_eq!(targets[0].0.iface_name, "wan0");
    assert_eq!(targets[1].0.iface_name, "wan1");
}

#[test]
fn collect_refresh_disabled_flow_yields_empty() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert("wan0".to_string(), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

    let configs = vec![flow_config(5, false, vec![iface_target("wan0", 1)])];

    let result = collect_target_refresh_result(&configs, &wan_infos);

    let targets = result.get(&5).expect("flow_id 5 should be present");
    assert!(targets.is_empty());
}

#[test]
fn collect_refresh_enabled_flow_with_unresolved_targets_yields_empty() {
    let wan_infos = WanRoutesByOwner::new(); // no routes registered

    let configs = vec![flow_config(5, true, vec![iface_target("missing_wan", 2)])];

    let result = collect_target_refresh_result(&configs, &wan_infos);

    let targets = result.get(&5).expect("flow_id 5 should be present");
    assert!(targets.is_empty());
}

#[test]
fn collect_refresh_partial_match_keeps_only_resolved() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert("wan0".to_string(), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

    let configs =
        vec![flow_config(5, true, vec![iface_target("wan0", 3), iface_target("missing_wan", 1)])];

    let result = collect_target_refresh_result(&configs, &wan_infos);

    let targets = result.get(&5).expect("flow_id 5 should be present");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0.iface_name, "wan0");
    assert_eq!(targets[0].1, 3);
}

#[test]
fn collect_refresh_netns_target_resolves_by_container_name() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert("ns0".to_string(), ipv4_wan_route("ns0", Ipv4Addr::new(10, 0, 0, 1)));

    let configs = vec![flow_config(3, true, vec![netns_target("ns0", 5)])];

    let result = collect_target_refresh_result(&configs, &wan_infos);

    let targets = result.get(&3).expect("flow_id 3 should be present");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0.iface_name, "ns0");
    assert_eq!(targets[0].1, 5);
}

#[test]
fn collect_refresh_multiple_flows_independent() {
    let mut wan_infos = WanRoutesByOwner::new();
    wan_infos.insert("wan0".to_string(), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

    let configs = vec![
        flow_config(1, true, vec![iface_target("wan0", 2)]),
        flow_config(2, false, vec![iface_target("wan0", 1)]),
        flow_config(3, true, vec![iface_target("missing", 1)]),
    ];

    let result = collect_target_refresh_result(&configs, &wan_infos);

    assert_eq!(result.get(&1).unwrap().len(), 1);
    assert!(result.get(&2).unwrap().is_empty());
    assert!(result.get(&3).unwrap().is_empty());
}
