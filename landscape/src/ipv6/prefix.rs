use arc_swap::ArcSwap;
use landscape_common::event::hub::{IAPrefixEvent, IAPrefixEventReader};
pub use landscape_common::ipv6::allocate_subnet;
use landscape_common::ipv6::checked_allocate_subnet;
use landscape_common::ipv6::lan::{
    LanPrefixGroupConfig, NaPrefixConfig, PdPrefixRangeConfig, PrefixParentSource, RaPrefixConfig,
};
use landscape_common::ipv6_pd::{IAPrefixMap, LDIAPrefix};
use landscape_common::route::{LanIPv6RouteKey, LanRouteInfo};
use std::net::{IpAddr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::route::IpRouteService;

/// Parent prefix block available for IA_PD delegation.
#[derive(Clone)]
pub struct PdDelegationParent {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
}

/// Per-subnet prefix info used by RA (with lifetimes) and DHCPv6 NA.
#[derive(Clone)]
pub struct ICMPv6ConfigInfo {
    pub rt_prefix: Ipv6Addr,
    pub rt_prefix_len: u8,

    pub sub_router: Ipv6Addr,
    pub sub_prefix: Ipv6Addr,
    pub sub_prefix_len: u8,

    pub ra_preferred_lifetime: u32,
    pub ra_valid_lifetime: u32,
}

/// Prefix data for a single consumer (RA, DHCPv6 NA, or DHCPv6 PD).
///
/// `notify` is an assignment-level change signal. Watchers must send it after
/// writing a dynamic `ArcSwap` entry, so consumers can read the updated view
/// without subscribing to raw upstream IA prefix events.
#[derive(Clone)]
pub struct Assignment<T> {
    pub statics: Vec<T>,
    pub dynamics: Vec<Arc<ArcSwap<Option<T>>>>,
    pub token: CancellationToken,
    pub notify: watch::Receiver<()>,
    pub boot_time: Instant,
}

/// Complete LAN prefix setup: one Assignment per consumer.
pub struct LanPrefixSetup {
    pub ra: Assignment<ICMPv6ConfigInfo>,
    pub na: Assignment<ICMPv6ConfigInfo>,
    pub pd: Assignment<PdDelegationParent>,
    pub cleanup_ips: Vec<(Ipv6Addr, u8, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DynamicPrefixState {
    route_key: LanIPv6RouteKey,
    sub_prefix: Ipv6Addr,
    sub_prefix_len: u8,
    sub_router: Ipv6Addr,
}

// ── Static prefix helpers ─────────────────────────────────────────────────

async fn add_static_prefix(
    target: &mut Vec<ICMPv6ConfigInfo>,
    cleanup_ips: &mut Vec<(Ipv6Addr, u8, String)>,
    iface_name: &str,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
    base_prefix: Ipv6Addr,
    parent_prefix_len: u8,
    pool_index: u32,
    preferred_lifetime: u32,
    valid_lifetime: u32,
) {
    let sub_prefix_len = 64u8;
    let Some((sub_prefix, sub_router)) =
        checked_allocate_subnet(base_prefix, parent_prefix_len, sub_prefix_len, pool_index as u128)
    else {
        tracing::error!(
            pool_index = pool_index,
            base_prefix = %base_prefix,
            parent_prefix_len = parent_prefix_len,
            "add_static_prefix: invalid subnet allocation"
        );
        return;
    };
    set_iface_ip(sub_router, sub_prefix_len, iface_name, None, None);
    cleanup_ips.push((sub_router, sub_prefix_len, iface_name.to_string()));
    let mut li = lan_info.clone();
    li.iface_ip = IpAddr::V6(sub_router);
    li.prefix = sub_prefix_len;
    let lan_info_key = LanIPv6RouteKey {
        iface_name: iface_name.to_string(),
        subnet_index: pool_index,
    };
    route_service.insert_ipv6_lan_route(lan_info_key, li).await;
    target.push(ICMPv6ConfigInfo {
        rt_prefix: base_prefix,
        rt_prefix_len: parent_prefix_len,
        sub_router,
        sub_prefix,
        sub_prefix_len,
        ra_preferred_lifetime: preferred_lifetime,
        ra_valid_lifetime: valid_lifetime,
    });
}

async fn add_static_pd(
    target: &mut Vec<PdDelegationParent>,
    base_prefix: Ipv6Addr,
    parent_prefix_len: u8,
    pd: &PdPrefixRangeConfig,
) {
    for pool_index in pd.start_index..=pd.end_index {
        let Some((sub_block, _)) = checked_allocate_subnet(
            base_prefix,
            parent_prefix_len,
            pd.pool_len,
            pool_index as u128,
        ) else {
            tracing::error!(
                pool_index = pool_index,
                base_prefix = %base_prefix,
                parent_prefix_len = parent_prefix_len,
                pool_len = pd.pool_len,
                "add_static_pd: invalid subnet allocation"
            );
            continue;
        };
        target.push(PdDelegationParent { prefix: sub_block, prefix_len: pd.pool_len });
    }
}

// ── Dynamic prefix / PD watchers ──────────────────────────────────────────

struct PdSourceConfig {
    lan_slot: u32,
    sub_prefix_len: u8,
    preferred_lifetime: u32,
    valid_lifetime: u32,
}

/// Spawn a PD watcher that updates a RA/NA prefix entry (ICMPv6ConfigInfo).
// TODO: Accept IAPrefixEventReader instead of broadcast::Sender (see
// EventHubHandle::ipv6_prefix_broadcast_tx).
fn spawn_prefix_watcher(
    depend_iface: String,
    prefix_map: IAPrefixMap,
    prefix_broadcast_tx: broadcast::Sender<IAPrefixEvent>,
    target: Arc<ArcSwap<Option<ICMPv6ConfigInfo>>>,
    notify_tx: Arc<watch::Sender<()>>,
    token: CancellationToken,
    iface_name: String,
    lan_info: LanRouteInfo,
    route_service: IpRouteService,
    pd_config: PdSourceConfig,
    planned_parent_prefix_len: u8,
) {
    tokio::spawn(async move {
        let mut prefix_reader = IAPrefixEventReader::new(prefix_broadcast_tx.subscribe());
        let mut expire_time = Box::pin(tokio::time::sleep(Duration::from_secs(0)));
        let mut applied_state: Option<DynamicPrefixState> = None;

        // Initial load
        let ia_prefix = prefix_map.load(&depend_iface);
        if let Some(ia_prefix) = ia_prefix {
            if source_prefix_matches_max_len(ia_prefix.prefix_len, planned_parent_prefix_len)
                && can_delegate_from_pd(ia_prefix.prefix_len, pd_config.sub_prefix_len)
            {
                let (new_info, new_state) = update_current_info(
                    &iface_name,
                    ia_prefix,
                    &pd_config,
                    expire_time.as_mut(),
                    &lan_info,
                    &route_service,
                )
                .await;
                applied_state = replace_dynamic_prefix_state(
                    &route_service,
                    &iface_name,
                    applied_state,
                    new_state,
                )
                .await;
                target.store(Arc::new(new_info));
            }
        }

        loop {
            tokio::select! {
                change_result = prefix_reader.recv() => {
                    let matched = match &change_result {
                        Ok(IAPrefixEvent::Updated { iface_name })
                        | Ok(IAPrefixEvent::Expired { iface_name })
                            if *iface_name == depend_iface => true,
                        Ok(_) => false,
                        Err(_) => break,
                    };
                    if !matched {
                        continue;
                    }
                    let ia_prefix = prefix_map.load(&depend_iface);
                    if let Some(ia_prefix) = ia_prefix {
                        if source_prefix_matches_max_len(ia_prefix.prefix_len, planned_parent_prefix_len)
                            && can_delegate_from_pd(ia_prefix.prefix_len, pd_config.sub_prefix_len)
                        {
                            let (new_info, new_state) = update_current_info(
                                &iface_name,
                                ia_prefix,
                                &pd_config,
                                expire_time.as_mut(),
                                &lan_info,
                                &route_service,
                            ).await;
                            applied_state = replace_dynamic_prefix_state(
                                &route_service,
                                &iface_name,
                                applied_state,
                                new_state,
                            ).await;
                            target.store(Arc::new(new_info));
                        } else {
                            applied_state = replace_dynamic_prefix_state(
                                &route_service, &iface_name, applied_state, None,
                            ).await;
                            target.store(Arc::new(None));
                        }
                    } else {
                        applied_state = replace_dynamic_prefix_state(
                            &route_service, &iface_name, applied_state, None,
                        ).await;
                        target.store(Arc::new(None));
                    }
                    let _ = notify_tx.send(());
                },
                _ = token.cancelled() => break,
                _ = expire_time.as_mut() => {
                    applied_state = replace_dynamic_prefix_state(
                        &route_service, &iface_name, applied_state, None,
                    ).await;
                    target.store(Arc::new(None));
                    let _ = notify_tx.send(());
                    expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(u64::MAX)));
                }
            }
        }
        clear_dynamic_prefix_state(&route_service, applied_state).await;
        tracing::info!("prefix watcher for {} is down", depend_iface);
    });
}

/// Spawn a PD watcher that updates a PD delegation entry (PdDelegationParent).
// TODO: Accept IAPrefixEventReader instead of broadcast::Sender (see
// EventHubHandle::ipv6_prefix_broadcast_tx).
fn spawn_pd_watcher(
    depend_iface: String,
    prefix_map: IAPrefixMap,
    prefix_broadcast_tx: broadcast::Sender<IAPrefixEvent>,
    target: Arc<ArcSwap<Option<PdDelegationParent>>>,
    notify_tx: Arc<watch::Sender<()>>,
    token: CancellationToken,
    planned_parent_prefix_len: u8,
    pool_index: u32,
    pool_len: u8,
) {
    tokio::spawn(async move {
        let mut prefix_reader = IAPrefixEventReader::new(prefix_broadcast_tx.subscribe());
        let mut expire_time = Box::pin(tokio::time::sleep(Duration::from_secs(0)));

        // Initial load
        let ia_prefix = prefix_map.load(&depend_iface);
        if let Some(ia_prefix) = ia_prefix {
            if source_prefix_matches_max_len(ia_prefix.prefix_len, planned_parent_prefix_len)
                && can_delegate_from_pd(ia_prefix.prefix_len, pool_len)
            {
                let Some((sub_block, _)) = checked_allocate_subnet(
                    ia_prefix.prefix_ip,
                    ia_prefix.prefix_len,
                    pool_len,
                    lan_slot_to_subnet_index(pool_index, pool_len),
                ) else {
                    return;
                };
                target.store(Arc::new(Some(PdDelegationParent {
                    prefix: sub_block,
                    prefix_len: pool_len,
                })));
                expire_time
                    .as_mut()
                    .set(tokio::time::sleep(Duration::from_secs(ia_prefix.valid_lifetime as u64)));
            }
        }
        loop {
            tokio::select! {
                change_result = prefix_reader.recv() => {
                    let matched = match &change_result {
                        Ok(IAPrefixEvent::Updated { iface_name })
                        | Ok(IAPrefixEvent::Expired { iface_name })
                            if *iface_name == depend_iface => true,
                        Ok(_) => false,
                        Err(_) => break,
                    };
                    if !matched {
                        continue;
                    }
                    let ia_prefix = prefix_map.load(&depend_iface);
                    if let Some(ia_prefix) = ia_prefix {
                        if source_prefix_matches_max_len(
                            ia_prefix.prefix_len,
                            planned_parent_prefix_len,
                        ) && can_delegate_from_pd(ia_prefix.prefix_len, pool_len)
                        {
                            let Some((sub_block, _)) = checked_allocate_subnet(
                                ia_prefix.prefix_ip,
                                ia_prefix.prefix_len,
                                pool_len,
                                lan_slot_to_subnet_index(pool_index, pool_len),
                            ) else {
                                continue;
                            };
                            target.store(Arc::new(Some(PdDelegationParent {
                                prefix: sub_block,
                                prefix_len: pool_len,
                            })));
                            expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(
                                ia_prefix.valid_lifetime as u64,
                            )));
                        } else {
                            target.store(Arc::new(None));
                        }
                    } else {
                        target.store(Arc::new(None));
                    }
                    let _ = notify_tx.send(());
                },
                _ = token.cancelled() => break,
                _ = expire_time.as_mut() => {
                    target.store(Arc::new(None));
                    let _ = notify_tx.send(());
                    expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(u64::MAX)));
                }
            }
        }
        tracing::info!("pd delegation watcher for {} is down", depend_iface);
    });
}

// ── Main setup function ───────────────────────────────────────────────────

/// Process all prefix groups once and return per-consumer assignments.
///
/// Each group's `ra` field → `ra` assignment, `na` → `na` assignment, `pd` → `pd` assignment.
/// Static sources are materialized immediately; Pd sources spawn watchers that
/// update `ArcSwap` entries and notify via the assignment's `notify` channel.
// TODO: Accept IAPrefixEventReader instead of broadcast::Sender (see
// EventHubHandle::ipv6_prefix_broadcast_tx).
pub async fn setup_lan_prefixes(
    groups: &[LanPrefixGroupConfig],
    iface_name: &str,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
    prefix_map: &IAPrefixMap,
    prefix_broadcast_tx: &broadcast::Sender<IAPrefixEvent>,
) -> LanPrefixSetup {
    let mut ra_statics = vec![];
    let mut ra_dynamics = vec![];
    let mut na_statics = vec![];
    let mut na_dynamics = vec![];
    let mut pd_statics = vec![];
    let mut pd_dynamics = vec![];
    let mut cleanup_ips = vec![];

    let ra_token = CancellationToken::new();
    let na_token = CancellationToken::new();
    let pd_token = CancellationToken::new();
    let (ra_tx, ra_rx) = watch::channel(());
    let (na_tx, na_rx) = watch::channel(());
    let (pd_tx, pd_rx) = watch::channel(());
    let ra_notify_tx = Arc::new(ra_tx);
    let na_notify_tx = Arc::new(na_tx);
    let pd_notify_tx = Arc::new(pd_tx);

    let boot_time = Instant::now();

    for group in groups {
        match &group.parent {
            PrefixParentSource::Static { base_prefix, parent_prefix_len } => {
                if let Some(RaPrefixConfig { pool_index, preferred_lifetime, valid_lifetime }) =
                    &group.ra
                {
                    add_static_prefix(
                        &mut ra_statics,
                        &mut cleanup_ips,
                        iface_name,
                        lan_info,
                        route_service,
                        *base_prefix,
                        *parent_prefix_len,
                        *pool_index,
                        *preferred_lifetime,
                        *valid_lifetime,
                    )
                    .await;
                }
                if let Some(NaPrefixConfig { pool_index }) = &group.na {
                    add_static_prefix(
                        &mut na_statics,
                        &mut cleanup_ips,
                        iface_name,
                        lan_info,
                        route_service,
                        *base_prefix,
                        *parent_prefix_len,
                        *pool_index,
                        0,
                        0,
                    )
                    .await;
                }
                if let Some(pd) = &group.pd {
                    add_static_pd(&mut pd_statics, *base_prefix, *parent_prefix_len, pd).await;
                }
            }
            PrefixParentSource::Pd { depend_iface, planned_parent_prefix_len } => {
                if let Some(RaPrefixConfig { pool_index, preferred_lifetime, valid_lifetime }) =
                    &group.ra
                {
                    let target: Arc<ArcSwap<Option<ICMPv6ConfigInfo>>> =
                        Arc::new(ArcSwap::from_pointee(None));
                    ra_dynamics.push(target.clone());
                    spawn_prefix_watcher(
                        depend_iface.clone(),
                        prefix_map.clone(),
                        prefix_broadcast_tx.clone(),
                        target,
                        ra_notify_tx.clone(),
                        ra_token.clone(),
                        iface_name.to_string(),
                        lan_info.clone(),
                        route_service.clone(),
                        PdSourceConfig {
                            lan_slot: *pool_index,
                            sub_prefix_len: 64,
                            preferred_lifetime: *preferred_lifetime,
                            valid_lifetime: *valid_lifetime,
                        },
                        *planned_parent_prefix_len,
                    );
                }
                if let Some(NaPrefixConfig { pool_index }) = &group.na {
                    let target: Arc<ArcSwap<Option<ICMPv6ConfigInfo>>> =
                        Arc::new(ArcSwap::from_pointee(None));
                    na_dynamics.push(target.clone());
                    spawn_prefix_watcher(
                        depend_iface.clone(),
                        prefix_map.clone(),
                        prefix_broadcast_tx.clone(),
                        target,
                        na_notify_tx.clone(),
                        na_token.clone(),
                        iface_name.to_string(),
                        lan_info.clone(),
                        route_service.clone(),
                        PdSourceConfig {
                            lan_slot: *pool_index,
                            sub_prefix_len: 64,
                            preferred_lifetime: 0,
                            valid_lifetime: 0,
                        },
                        *planned_parent_prefix_len,
                    );
                }
                if let Some(pd) = &group.pd {
                    for pool_index in pd.start_index..=pd.end_index {
                        let target: Arc<ArcSwap<Option<PdDelegationParent>>> =
                            Arc::new(ArcSwap::from_pointee(None));
                        pd_dynamics.push(target.clone());
                        spawn_pd_watcher(
                            depend_iface.clone(),
                            prefix_map.clone(),
                            prefix_broadcast_tx.clone(),
                            target,
                            pd_notify_tx.clone(),
                            pd_token.clone(),
                            *planned_parent_prefix_len,
                            pool_index,
                            pd.pool_len,
                        );
                    }
                }
            }
        }
    }

    // Keep-alive: hold sender until token is cancelled, then drop → receiver gets Err
    {
        let ra_tx = ra_notify_tx.clone();
        let ra_ct = ra_token.clone();
        tokio::spawn(async move {
            let _keep = ra_tx;
            ra_ct.cancelled().await;
        });
    }
    {
        let na_tx = na_notify_tx.clone();
        let na_ct = na_token.clone();
        tokio::spawn(async move {
            let _keep = na_tx;
            na_ct.cancelled().await;
        });
    }
    {
        let pd_tx = pd_notify_tx.clone();
        let pd_ct = pd_token.clone();
        tokio::spawn(async move {
            let _keep = pd_tx;
            pd_ct.cancelled().await;
        });
    }

    // Deduplicate cleanup_ips (same subnet may be added for both ra and na)
    cleanup_ips.sort();
    cleanup_ips.dedup();

    LanPrefixSetup {
        ra: Assignment {
            statics: ra_statics,
            dynamics: ra_dynamics,
            token: ra_token,
            notify: ra_rx,
            boot_time,
        },
        na: Assignment {
            statics: na_statics,
            dynamics: na_dynamics,
            token: na_token,
            notify: na_rx,
            boot_time,
        },
        pd: Assignment {
            statics: pd_statics,
            dynamics: pd_dynamics,
            token: pd_token,
            notify: pd_rx,
            boot_time,
        },
        cleanup_ips,
    }
}

// ── Cleanup ────────────────────────────────────────────────────────────────

/// Clean up prefix resources: remove routes and delete static IPs
pub async fn cleanup_prefix_sources(
    static_ip_infos: Vec<(Ipv6Addr, u8, String)>,
    iface_name: &str,
    route_service: &IpRouteService,
) {
    route_service.remove_ipv6_lan_route(iface_name).await;
    for (ip, prefix, iface_name) in static_ip_infos {
        del_iface_ip(ip, prefix, &iface_name);
    }
}

// ── Dynamic prefix update helpers (used by watchers) ─────────────────────

async fn update_current_info(
    iface_name: &str,
    ia_prefix: LDIAPrefix,
    pd_config: &PdSourceConfig,
    mut expire_time: Pin<&mut tokio::time::Sleep>,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
) -> (Option<ICMPv6ConfigInfo>, Option<DynamicPrefixState>) {
    let Some((sub_prefix, sub_router)) = checked_allocate_subnet(
        ia_prefix.prefix_ip,
        ia_prefix.prefix_len,
        pd_config.sub_prefix_len,
        lan_slot_to_subnet_index(pd_config.lan_slot, pd_config.sub_prefix_len),
    ) else {
        return (None, None);
    };
    expire_time.set(tokio::time::sleep(Duration::from_secs(ia_prefix.valid_lifetime as u64)));

    let mut lan_info = lan_info.clone();
    lan_info.iface_ip = IpAddr::V6(sub_router);
    lan_info.prefix = pd_config.sub_prefix_len;
    let lan_info_key = LanIPv6RouteKey {
        iface_name: iface_name.to_string(),
        subnet_index: pd_config.lan_slot,
    };
    route_service.insert_ipv6_lan_route(lan_info_key, lan_info).await;

    add_route(sub_prefix, pd_config.sub_prefix_len, iface_name, Some(ia_prefix.valid_lifetime));
    set_iface_ip(
        sub_router,
        pd_config.sub_prefix_len,
        iface_name,
        Some(ia_prefix.valid_lifetime),
        Some(ia_prefix.preferred_lifetime),
    );

    (
        Some(ICMPv6ConfigInfo {
            rt_prefix: ia_prefix.prefix_ip,
            rt_prefix_len: ia_prefix.prefix_len,
            sub_prefix,
            sub_prefix_len: pd_config.sub_prefix_len,
            sub_router,
            ra_preferred_lifetime: pd_config.preferred_lifetime,
            ra_valid_lifetime: pd_config.valid_lifetime,
        }),
        Some(DynamicPrefixState {
            route_key: LanIPv6RouteKey {
                iface_name: iface_name.to_string(),
                subnet_index: pd_config.lan_slot,
            },
            sub_prefix,
            sub_prefix_len: pd_config.sub_prefix_len,
            sub_router,
        }),
    )
}

async fn replace_dynamic_prefix_state(
    route_service: &IpRouteService,
    iface_name: &str,
    current_state: Option<DynamicPrefixState>,
    next_state: Option<DynamicPrefixState>,
) -> Option<DynamicPrefixState> {
    if current_state.as_ref() == next_state.as_ref() {
        return current_state;
    }

    if let Some(state) = current_state {
        clear_dynamic_prefix_runtime(iface_name, &state);
        if next_state.is_none() {
            route_service.remove_ipv6_lan_route_by_key(&state.route_key).await;
        }
    }

    next_state
}

async fn clear_dynamic_prefix_state(
    route_service: &IpRouteService,
    state: Option<DynamicPrefixState>,
) {
    let Some(state) = state else {
        return;
    };

    clear_dynamic_prefix_runtime(&state.route_key.iface_name, &state);
    route_service.remove_ipv6_lan_route_by_key(&state.route_key).await;
}

fn clear_dynamic_prefix_runtime(iface_name: &str, state: &DynamicPrefixState) {
    del_iface_ip(state.sub_router, state.sub_prefix_len, iface_name);
    del_route(state.sub_prefix, state.sub_prefix_len, iface_name);
}

// ── Subnet / route helpers ─────────────────────────────────────────────────

fn reserved_wan_slots(target_prefix_len: u8) -> u128 {
    if target_prefix_len <= 64 {
        1
    } else {
        1u128 << (target_prefix_len - 64)
    }
}

fn lan_slot_to_subnet_index(lan_slot: u32, target_prefix_len: u8) -> u128 {
    u128::from(lan_slot) + reserved_wan_slots(target_prefix_len)
}

fn can_delegate_from_pd(source_prefix_len: u8, target_prefix_len: u8) -> bool {
    source_prefix_len < 64 && source_prefix_len < target_prefix_len
}

fn source_prefix_matches_max_len(source_prefix_len: u8, max_source_prefix_len: u8) -> bool {
    source_prefix_len <= max_source_prefix_len
}

// ── Shell command helpers (ip route / ip addr) ────────────────────────────

pub fn add_route(ip: Ipv6Addr, prefix: u8, iface_name: &str, valid_lifetime: Option<u32>) {
    let mut args = vec![
        "-6".to_string(),
        "route".to_string(),
        "replace".to_string(),
        format!("{}/{}", ip, prefix),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    if let Some(lifetime) = valid_lifetime {
        args.push("expires".to_string());
        args.push(lifetime.to_string());
    }

    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("{e:?}");
    }
}

pub fn add_route_via(
    prefix: Ipv6Addr,
    prefix_len: u8,
    via: Ipv6Addr,
    iface_name: &str,
    valid_lifetime: Option<u32>,
) {
    let mut args = vec![
        "-6".to_string(),
        "route".to_string(),
        "replace".to_string(),
        format!("{}/{}", prefix, prefix_len),
        "via".to_string(),
        via.to_string(),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    if let Some(lifetime) = valid_lifetime {
        args.push("expires".to_string());
        args.push(lifetime.to_string());
    }

    tracing::info!("Adding PD route: ip {}", args.join(" "));
    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("add_route_via error: {e:?}");
    }
}

pub fn del_route(prefix: Ipv6Addr, prefix_len: u8, iface_name: &str) {
    let args = vec![
        "-6".to_string(),
        "route".to_string(),
        "del".to_string(),
        format!("{}/{}", prefix, prefix_len),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    tracing::debug!("Deleting PD route: ip {}", args.join(" "));
    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("del_route error: {e:?}");
    }
}

pub fn del_iface_ip(ip: Ipv6Addr, prefix: u8, iface_name: &str) {
    let args = vec![
        "-6".to_string(),
        "addr".to_string(),
        "del".to_string(),
        format!("{}/{}", ip, prefix),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("{e:?}");
    }
}

pub fn set_iface_ip(
    ip: Ipv6Addr,
    prefix: u8,
    iface_name: &str,
    valid_lifetime: Option<u32>,
    preferred_lft: Option<u32>,
) {
    let mut args = vec![
        "-6".to_string(),
        "addr".to_string(),
        "replace".to_string(),
        format!("{}/{}", ip, prefix),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    if let Some(valid) = valid_lifetime {
        args.push("valid_lft".to_string());
        args.push(valid.to_string());
    }

    if let Some(preferred) = preferred_lft {
        args.push("preferred_lft".to_string());
        args.push(preferred.to_string());
    }

    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("{e:?}");
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        allocate_subnet, source_prefix_matches_max_len, spawn_pd_watcher, PdDelegationParent,
    };
    use arc_swap::ArcSwap;
    use landscape_common::event::hub::IAPrefixEvent;
    use landscape_common::ipv6_pd::{IAPrefixMap, LDIAPrefix};
    use std::net::Ipv6Addr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{broadcast, watch};
    use tokio_util::sync::CancellationToken;

    #[test]
    fn test() {
        let ldia_prefix = LDIAPrefix {
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            prefix_len: 48,
            prefix_ip: "2001:db8::".parse().unwrap(),
            last_update_time: 0.0,
        };
        let sub_prefix_len = 64;
        let subnet_index = 2;
        let (subnet_network, router_addr) = allocate_subnet(
            ldia_prefix.prefix_ip,
            ldia_prefix.prefix_len,
            sub_prefix_len,
            subnet_index,
        );
        println!("子网网络地址: {}/{}", subnet_network, sub_prefix_len);
        println!("路由器地址: {}", router_addr);
    }

    #[test]
    fn test_static_setting() {
        let (subnet_network, router_addr) =
            allocate_subnet("2001:db8::3".parse().unwrap(), 60, 64, 2);
        println!("子网网络地址: {}/{}", subnet_network, 64);
        println!("路由器地址: {}", router_addr);
    }

    #[test]
    fn test_source_prefix_matches_max_len() {
        assert!(source_prefix_matches_max_len(56, 60));
        assert!(source_prefix_matches_max_len(60, 60));
        assert!(!source_prefix_matches_max_len(64, 60));
    }

    #[tokio::test]
    async fn test_change_channel_stays_alive_without_pd_sources() {
        let (change_tx, mut change_rx) = watch::channel(());
        let change_tx = Arc::new(change_tx);
        let ra_token = CancellationToken::new();
        let dhcpv6_token = CancellationToken::new();

        {
            let ra_clone = ra_token.clone();
            let dhcpv6_clone = dhcpv6_token.clone();
            tokio::spawn(async move {
                let _keep_alive = change_tx;
                tokio::join!(ra_clone.cancelled(), dhcpv6_clone.cancelled());
            });
        }

        change_rx.borrow_and_update();

        let result = tokio::time::timeout(Duration::from_millis(100), change_rx.changed()).await;
        assert!(result.is_err(), "should timeout, not get channel Err");

        ra_token.cancel();
        dhcpv6_token.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let result = change_rx.changed().await;
        assert!(result.is_err(), "sender dropped, should get Err");
    }

    #[tokio::test]
    async fn test_change_channel_receives_pd_notifications() {
        let (change_tx, mut change_rx) = watch::channel(());
        let change_tx = Arc::new(change_tx);
        let tx_clone = change_tx.clone();

        change_rx.borrow_and_update();

        tx_clone.send(()).unwrap();

        let result = tokio::time::timeout(Duration::from_millis(100), change_rx.changed()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_pd_watcher_notifies_after_assignment_update_and_expire() {
        let prefix_map = IAPrefixMap::new();
        let (prefix_tx, _) = broadcast::channel(8);
        let target: Arc<ArcSwap<Option<PdDelegationParent>>> =
            Arc::new(ArcSwap::from_pointee(None));
        let token = CancellationToken::new();
        let (notify_tx, mut notify_rx) = watch::channel(());

        spawn_pd_watcher(
            "wan0".to_string(),
            prefix_map.clone(),
            prefix_tx.clone(),
            target.clone(),
            Arc::new(notify_tx),
            token.clone(),
            56,
            0,
            60,
        );

        tokio::time::sleep(Duration::from_millis(20)).await;
        notify_rx.borrow_and_update();

        prefix_map.store(
            "wan0",
            LDIAPrefix {
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
                prefix_len: 56,
                prefix_ip: Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
                last_update_time: 0.0,
            },
        );
        prefix_tx.send(IAPrefixEvent::Updated { iface_name: "wan0".to_string() }).unwrap();

        let result = tokio::time::timeout(Duration::from_millis(200), notify_rx.changed()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
        assert!(target.load_full().is_some());

        prefix_map.remove("wan0");
        prefix_tx.send(IAPrefixEvent::Expired { iface_name: "wan0".to_string() }).unwrap();

        let result = tokio::time::timeout(Duration::from_millis(200), notify_rx.changed()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
        assert!(target.load_full().is_none());

        token.cancel();
    }
}
