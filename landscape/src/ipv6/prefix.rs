use arc_swap::ArcSwap;
use landscape_common::event::hub::{IAPrefixEvent, IAPrefixEventReader};
pub use landscape_common::ipv6::allocate_subnet;
use landscape_common::ipv6::checked_allocate_subnet;
use landscape_common::ipv6::lan::{
    LanIPv6SourceConfig, LanPrefixGroupConfig, NaPrefixConfig, PdPrefixRangeConfig,
    PrefixGroupServiceKind, PrefixParentSource, RaPrefixConfig, SourceServiceKind,
};
use landscape_common::ipv6_pd::{IAPrefixMap, LDIAPrefix};
use landscape_common::route::{LanIPv6RouteKey, LanRouteInfo};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::route::IpRouteService;

/// Parent prefix block available for IA_PD delegation.
/// Derived from PdStatic (static) or PdPd (upstream PD watch).
/// Completely independent from NA prefix info.
#[derive(Clone)]
pub struct PdDelegationParent {
    pub prefix: Ipv6Addr, // sub-block network address (computed from pool_index/pool_len)
    pub prefix_len: u8,   // = pool_len, the parent block length for delegation
}

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

/// Pure data: prefix runtime information shared by RA and DHCPv6
pub struct IPv6PrefixRuntime {
    pub static_info: Vec<ICMPv6ConfigInfo>,
    pub pd_info: HashMap<String, Arc<ArcSwap<Option<ICMPv6ConfigInfo>>>>,
    // PD delegation sources (independent from NA path)
    pub pd_delegation_static: Vec<PdDelegationParent>,
    pub pd_delegation_dynamic: Vec<Arc<ArcSwap<Option<PdDelegationParent>>>>,
    pub relative_boot_time: Instant,
}

/// Return value of `setup_prefix_sources()`
pub struct PrefixSetupResult {
    pub runtime: IPv6PrefixRuntime,
    pub ra_token: CancellationToken,
    pub dhcpv6_token: CancellationToken,
    pub change_notify: watch::Receiver<()>,
    pub cleanup_ips: Vec<(Ipv6Addr, u8, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DynamicPrefixState {
    route_key: LanIPv6RouteKey,
    sub_prefix: Ipv6Addr,
    sub_prefix_len: u8,
    sub_router: Ipv6Addr,
}

fn can_delegate_group(
    kind: PrefixGroupServiceKind,
    filter_kinds: &[PrefixGroupServiceKind],
) -> bool {
    filter_kinds.contains(&kind)
}

async fn add_static_runtime_info(
    runtime: &mut IPv6PrefixRuntime,
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
            "add_static_runtime_info: invalid subnet allocation"
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
    runtime.static_info.push(ICMPv6ConfigInfo {
        rt_prefix: base_prefix,
        rt_prefix_len: parent_prefix_len,
        sub_router,
        sub_prefix,
        sub_prefix_len,
        ra_preferred_lifetime: preferred_lifetime,
        ra_valid_lifetime: valid_lifetime,
    });
}

async fn add_dynamic_runtime_info(
    runtime: &mut IPv6PrefixRuntime,
    change_tx: Arc<watch::Sender<()>>,
    ra_token: &CancellationToken,
    dhcpv6_token: &CancellationToken,
    iface_name: &str,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
    prefix_map: &IAPrefixMap,
    prefix_broadcast_tx: &broadcast::Sender<IAPrefixEvent>,
    depend_iface: &str,
    planned_parent_prefix_len: u8,
    pool_index: u32,
    preferred_lifetime: u32,
    valid_lifetime: u32,
) {
    let pd_config = PdSourceConfig {
        depend_iface: depend_iface.to_string(),
        lan_slot: pool_index,
        sub_prefix_len: 64,
        preferred_lifetime,
        valid_lifetime,
    };

    let pd_prefix_info: Option<ICMPv6ConfigInfo> = None;
    let pd_prefix_info = Arc::new(ArcSwap::from_pointee(pd_prefix_info));
    runtime.pd_info.insert(depend_iface.to_string(), pd_prefix_info.clone());

    let change_tx_clone = change_tx.clone();
    let ra_token_clone = ra_token.clone();
    let dhcpv6_token_clone = dhcpv6_token.clone();
    let iface_name_owned = iface_name.to_string();
    let lan_info_clone = lan_info.clone();
    let route_service_clone = route_service.clone();
    let depend_iface_owned = depend_iface.to_string();
    let prefix_map_clone = prefix_map.clone();
    let prefix_broadcast_tx_clone = prefix_broadcast_tx.clone();
    tokio::spawn(async move {
        let mut prefix_reader = IAPrefixEventReader::new(prefix_broadcast_tx_clone.subscribe());
        let mut expire_time = Box::pin(tokio::time::sleep(Duration::from_secs(0)));
        let mut applied_state: Option<DynamicPrefixState> = None;

        let ia_prefix = prefix_map_clone.load(&depend_iface_owned);
        if let Some(ia_prefix) = ia_prefix {
            if source_prefix_matches_max_len(ia_prefix.prefix_len, planned_parent_prefix_len)
                && can_delegate_from_pd(ia_prefix.prefix_len, pd_config.sub_prefix_len)
            {
                let (new_info, new_state) = update_current_info(
                    &iface_name_owned,
                    ia_prefix,
                    &pd_config,
                    expire_time.as_mut(),
                    &lan_info_clone,
                    &route_service_clone,
                )
                .await;
                applied_state = replace_dynamic_prefix_state(
                    &route_service_clone,
                    &iface_name_owned,
                    applied_state,
                    new_state,
                )
                .await;
                pd_prefix_info.store(Arc::new(new_info));
            }
        }

        let both_done = async {
            tokio::join!(ra_token_clone.cancelled(), dhcpv6_token_clone.cancelled());
        };
        tokio::pin!(both_done);

        loop {
            tokio::select! {
            change_result = prefix_reader.recv() => {
                let matched = match &change_result {
                    Ok(IAPrefixEvent::Updated { iface_name }) | Ok(IAPrefixEvent::Expired { iface_name })
                        if *iface_name == depend_iface_owned => true,
                    Ok(_) => false,
                    Err(_) => break,
                };
                if !matched {
                    continue;
                }
                    let ia_prefix = prefix_map_clone.load(&depend_iface_owned);
                    if let Some(ia_prefix) = ia_prefix {
                        if source_prefix_matches_max_len(
                            ia_prefix.prefix_len,
                            planned_parent_prefix_len,
                        )
                            && can_delegate_from_pd(ia_prefix.prefix_len, pd_config.sub_prefix_len)
                        {
                            let (new_info, new_state) = update_current_info(
                                &iface_name_owned,
                                ia_prefix,
                                &pd_config,
                                expire_time.as_mut(),
                                &lan_info_clone,
                                &route_service_clone,
                            )
                            .await;
                            applied_state = replace_dynamic_prefix_state(
                                &route_service_clone,
                                &iface_name_owned,
                                applied_state,
                                new_state,
                            )
                            .await;
                            pd_prefix_info.store(Arc::new(new_info));
                        } else {
                            applied_state = replace_dynamic_prefix_state(
                                &route_service_clone,
                                &iface_name_owned,
                                applied_state,
                                None,
                            )
                            .await;
                            pd_prefix_info.store(Arc::new(None));
                        }
                    } else {
                        applied_state = replace_dynamic_prefix_state(
                            &route_service_clone,
                            &iface_name_owned,
                            applied_state,
                            None,
                        )
                        .await;
                        pd_prefix_info.store(Arc::new(None));
                    }
                    let _ = change_tx_clone.send(());
                },
                _ = &mut both_done => break,
                _ = expire_time.as_mut() => {
                    applied_state = replace_dynamic_prefix_state(
                        &route_service_clone,
                        &iface_name_owned,
                        applied_state,
                        None,
                    )
                    .await;
                    pd_prefix_info.store(Arc::new(None));
                    let _ = change_tx_clone.send(());
                    expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(u64::MAX)));
                }
            }
        }
        clear_dynamic_prefix_state(&route_service_clone, applied_state).await;
        tracing::info!("iface: {} prefix listen is down", depend_iface_owned);
    });
}

async fn add_static_pd_range(
    runtime: &mut IPv6PrefixRuntime,
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
                "add_static_pd_range: invalid subnet allocation"
            );
            continue;
        };
        runtime
            .pd_delegation_static
            .push(PdDelegationParent { prefix: sub_block, prefix_len: pd.pool_len });
    }
}

async fn add_dynamic_pd_range(
    runtime: &mut IPv6PrefixRuntime,
    dhcpv6_token: &CancellationToken,
    prefix_map: &IAPrefixMap,
    prefix_broadcast_tx: &broadcast::Sender<IAPrefixEvent>,
    depend_iface: &str,
    planned_parent_prefix_len: u8,
    pd: &PdPrefixRangeConfig,
) {
    for pool_index in pd.start_index..=pd.end_index {
        let pd_prefix_info: Option<PdDelegationParent> = None;
        let pd_prefix_info = Arc::new(ArcSwap::from_pointee(pd_prefix_info));
        runtime.pd_delegation_dynamic.push(pd_prefix_info.clone());

        let dhcpv6_token_clone = dhcpv6_token.clone();
        let pool_len = pd.pool_len;
        let depend_iface_owned = depend_iface.to_string();
        let prefix_map_clone = prefix_map.clone();
        let prefix_broadcast_tx_clone = prefix_broadcast_tx.clone();
        tokio::spawn(async move {
            let mut prefix_reader = IAPrefixEventReader::new(prefix_broadcast_tx_clone.subscribe());
            let mut expire_time = Box::pin(tokio::time::sleep(Duration::from_secs(0)));

            let ia_prefix = prefix_map_clone.load(&depend_iface_owned);
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
                        tracing::error!(
                            pool_index = pool_index,
                            pool_len = pool_len,
                            prefix = %ia_prefix.prefix_ip,
                            prefix_len = ia_prefix.prefix_len,
                            "add_dynamic_pd_range: invalid subnet allocation at init"
                        );
                        return;
                    };
                    pd_prefix_info.store(Arc::new(Some(PdDelegationParent {
                        prefix: sub_block,
                        prefix_len: pool_len,
                    })));
                    expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(
                        ia_prefix.valid_lifetime as u64,
                    )));
                }
            }
            loop {
                tokio::select! {
                    change_result = prefix_reader.recv() => {
                        let matched = match &change_result {
                            Ok(IAPrefixEvent::Updated { iface_name }) | Ok(IAPrefixEvent::Expired { iface_name })
                                if *iface_name == depend_iface_owned => true,
                            Ok(_) => false,
                            Err(_) => break,
                        };
                        if !matched {
                            continue;
                        }
                        let ia_prefix = prefix_map_clone.load(&depend_iface_owned);
                        if let Some(ia_prefix) = ia_prefix {
                            if source_prefix_matches_max_len(
                                ia_prefix.prefix_len,
                                planned_parent_prefix_len,
                            )
                                && can_delegate_from_pd(ia_prefix.prefix_len, pool_len)
                            {
                                let Some((sub_block, _)) = checked_allocate_subnet(
                                    ia_prefix.prefix_ip,
                                    ia_prefix.prefix_len,
                                    pool_len,
                                    lan_slot_to_subnet_index(pool_index, pool_len),
                                ) else {
                                    tracing::error!(
                                        pool_index = pool_index,
                                        pool_len = pool_len,
                                        prefix = %ia_prefix.prefix_ip,
                                        prefix_len = ia_prefix.prefix_len,
                                        "add_dynamic_pd_range: invalid subnet allocation in loop"
                                    );
                                    continue;
                                };
                                pd_prefix_info.store(Arc::new(Some(PdDelegationParent {
                                    prefix: sub_block,
                                    prefix_len: pool_len,
                                })));
                                expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(ia_prefix.valid_lifetime as u64)));
                            } else {
                                pd_prefix_info.store(Arc::new(None));
                            }
                        } else {
                            pd_prefix_info.store(Arc::new(None));
                        }
                    },
                    _ = dhcpv6_token_clone.cancelled() => break,
                    _ = expire_time.as_mut() => {
                        pd_prefix_info.store(Arc::new(None));
                        expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(u64::MAX)));
                    }
                }
            }
            tracing::info!("Pd range listen for {} is down", depend_iface_owned);
        });
    }
}

pub async fn setup_prefix_groups(
    groups: &[LanPrefixGroupConfig],
    filter_kinds: &[PrefixGroupServiceKind],
    iface_name: &str,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
    prefix_map: &IAPrefixMap,
    prefix_broadcast_tx: &broadcast::Sender<IAPrefixEvent>,
) -> PrefixSetupResult {
    let ra_token = CancellationToken::new();
    let dhcpv6_token = CancellationToken::new();
    let (change_tx, change_rx) = watch::channel(());
    let change_tx = Arc::new(change_tx);

    let mut runtime = IPv6PrefixRuntime {
        static_info: vec![],
        pd_info: HashMap::new(),
        pd_delegation_static: vec![],
        pd_delegation_dynamic: vec![],
        relative_boot_time: Instant::now(),
    };
    let mut cleanup_ips = vec![];

    for group in groups {
        match &group.parent {
            PrefixParentSource::Static { base_prefix, parent_prefix_len } => {
                if let Some(RaPrefixConfig { pool_index, preferred_lifetime, valid_lifetime }) =
                    &group.ra
                {
                    if can_delegate_group(PrefixGroupServiceKind::Ra, filter_kinds) {
                        add_static_runtime_info(
                            &mut runtime,
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
                }
                if let Some(NaPrefixConfig { pool_index }) = &group.na {
                    if can_delegate_group(PrefixGroupServiceKind::Na, filter_kinds) {
                        add_static_runtime_info(
                            &mut runtime,
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
                }
                if let Some(pd) = &group.pd {
                    if can_delegate_group(PrefixGroupServiceKind::IaPd, filter_kinds) {
                        add_static_pd_range(&mut runtime, *base_prefix, *parent_prefix_len, pd)
                            .await;
                    }
                }
            }
            PrefixParentSource::Pd { depend_iface, planned_parent_prefix_len } => {
                if let Some(RaPrefixConfig { pool_index, preferred_lifetime, valid_lifetime }) =
                    &group.ra
                {
                    if can_delegate_group(PrefixGroupServiceKind::Ra, filter_kinds) {
                        add_dynamic_runtime_info(
                            &mut runtime,
                            change_tx.clone(),
                            &ra_token,
                            &dhcpv6_token,
                            iface_name,
                            lan_info,
                            route_service,
                            prefix_map,
                            prefix_broadcast_tx,
                            depend_iface,
                            *planned_parent_prefix_len,
                            *pool_index,
                            *preferred_lifetime,
                            *valid_lifetime,
                        )
                        .await;
                    }
                }
                if let Some(NaPrefixConfig { pool_index }) = &group.na {
                    if can_delegate_group(PrefixGroupServiceKind::Na, filter_kinds) {
                        add_dynamic_runtime_info(
                            &mut runtime,
                            change_tx.clone(),
                            &ra_token,
                            &dhcpv6_token,
                            iface_name,
                            lan_info,
                            route_service,
                            prefix_map,
                            prefix_broadcast_tx,
                            depend_iface,
                            *planned_parent_prefix_len,
                            *pool_index,
                            0,
                            0,
                        )
                        .await;
                    }
                }
                if let Some(pd) = &group.pd {
                    if can_delegate_group(PrefixGroupServiceKind::IaPd, filter_kinds) {
                        add_dynamic_pd_range(
                            &mut runtime,
                            &dhcpv6_token,
                            prefix_map,
                            prefix_broadcast_tx,
                            depend_iface,
                            *planned_parent_prefix_len,
                            pd,
                        )
                        .await;
                    }
                }
            }
        }
    }

    {
        let ra_token_clone = ra_token.clone();
        let dhcpv6_token_clone = dhcpv6_token.clone();
        tokio::spawn(async move {
            let _keep_alive = change_tx;
            tokio::join!(ra_token_clone.cancelled(), dhcpv6_token_clone.cancelled());
        });
    }

    PrefixSetupResult {
        runtime,
        ra_token,
        dhcpv6_token,
        change_notify: change_rx,
        cleanup_ips,
    }
}

/// Runtime config for a PD source, extracted from LanIPv6SourceConfig
struct PdSourceConfig {
    depend_iface: String,
    lan_slot: u32,
    sub_prefix_len: u8,
    preferred_lifetime: u32,
    valid_lifetime: u32,
}

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

/// Set up prefix sources (static + PD) and return runtime data, tokens, and change notifications.
///
/// Accepts the new flat `LanIPv6SourceConfig` sources, optionally filtered by service kind.
/// - Ra* sources: used for RA prefix setup (static IP + route, or PD watch)
/// - Na* sources: used for DHCPv6 IA_NA prefix setup (same mechanics)
/// - Pd* sources: NOT handled here (IA_PD pool management is in DHCPv6 server)
///
/// If `filter_kind` is Some, only sources matching that kind are processed.
/// For backward compat with the service layer, RA uses Ra sources, DHCPv6 NA uses Na sources.
pub async fn setup_prefix_sources(
    sources: &[LanIPv6SourceConfig],
    filter_kinds: &[SourceServiceKind],
    iface_name: &str,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
    prefix_map: &IAPrefixMap,
    prefix_broadcast_tx: &broadcast::Sender<IAPrefixEvent>,
) -> PrefixSetupResult {
    let ra_token = CancellationToken::new();
    let dhcpv6_token = CancellationToken::new();
    let (change_tx, change_rx) = watch::channel(());
    let change_tx = Arc::new(change_tx);

    let mut runtime = IPv6PrefixRuntime {
        static_info: vec![],
        pd_info: HashMap::new(),
        pd_delegation_static: vec![],
        pd_delegation_dynamic: vec![],
        relative_boot_time: Instant::now(),
    };
    let mut cleanup_ips = vec![];

    for src in sources {
        if !filter_kinds.contains(&src.service_kind()) {
            continue;
        }

        // Extract common parameters from the source variant
        let (base_prefix_opt, pd_config_opt) = match src {
            LanIPv6SourceConfig::RaStatic {
                base_prefix,
                pool_index,
                preferred_lifetime,
                valid_lifetime,
            } => (Some((*base_prefix, *pool_index, *preferred_lifetime, *valid_lifetime)), None),
            LanIPv6SourceConfig::NaStatic { base_prefix, pool_index } => {
                (Some((*base_prefix, *pool_index, 0, 0)), None)
            }
            LanIPv6SourceConfig::RaPd {
                depend_iface,
                pool_index,
                preferred_lifetime,
                valid_lifetime,
            } => (
                None,
                Some(PdSourceConfig {
                    depend_iface: depend_iface.clone(),
                    lan_slot: *pool_index,
                    sub_prefix_len: 64,
                    preferred_lifetime: *preferred_lifetime,
                    valid_lifetime: *valid_lifetime,
                }),
            ),
            LanIPv6SourceConfig::NaPd { depend_iface, pool_index } => (
                None,
                Some(PdSourceConfig {
                    depend_iface: depend_iface.clone(),
                    lan_slot: *pool_index,
                    sub_prefix_len: 64,
                    preferred_lifetime: 0,
                    valid_lifetime: 0,
                }),
            ),
            // PdStatic: compute sub-block and store in pd_delegation_static
            LanIPv6SourceConfig::PdStatic {
                base_prefix,
                base_prefix_len,
                pool_index,
                pool_len,
            } => {
                let Some((sub_block, _)) = checked_allocate_subnet(
                    *base_prefix,
                    *base_prefix_len,
                    *pool_len,
                    *pool_index as u128,
                ) else {
                    tracing::error!(
                        pool_index = *pool_index,
                        base_prefix = %base_prefix,
                        base_prefix_len = *base_prefix_len,
                        pool_len = *pool_len,
                        "setup_prefix_sources PdStatic: invalid subnet allocation"
                    );
                    continue;
                };
                runtime
                    .pd_delegation_static
                    .push(PdDelegationParent { prefix: sub_block, prefix_len: *pool_len });
                continue;
            }
            // PdPd: watch upstream PD and store in pd_delegation_dynamic
            LanIPv6SourceConfig::PdPd {
                depend_iface,
                max_source_prefix_len,
                pool_index,
                pool_len,
            } => {
                let pd_prefix_info: Option<PdDelegationParent> = None;
                let pd_prefix_info = Arc::new(ArcSwap::from_pointee(pd_prefix_info));
                runtime.pd_delegation_dynamic.push(pd_prefix_info.clone());

                let dhcpv6_token_clone = dhcpv6_token.clone();
                let max_source_prefix_len = *max_source_prefix_len;
                let pool_index = *pool_index;
                let pool_len = *pool_len;
                let depend_iface_owned = depend_iface.clone();
                let prefix_map_clone = prefix_map.clone();
                let prefix_broadcast_tx_clone = prefix_broadcast_tx.clone();

                tokio::spawn(async move {
                    let mut prefix_reader =
                        IAPrefixEventReader::new(prefix_broadcast_tx_clone.subscribe());
                    let mut expire_time = Box::pin(tokio::time::sleep(Duration::from_secs(0)));

                    let ia_prefix = prefix_map_clone.load(&depend_iface_owned);
                    if let Some(ia_prefix) = ia_prefix {
                        if source_prefix_matches_max_len(
                            ia_prefix.prefix_len,
                            max_source_prefix_len,
                        ) && can_delegate_from_pd(ia_prefix.prefix_len, pool_len)
                        {
                            let Some((sub_block, _)) = checked_allocate_subnet(
                                ia_prefix.prefix_ip,
                                ia_prefix.prefix_len,
                                pool_len,
                                lan_slot_to_subnet_index(pool_index, pool_len),
                            ) else {
                                tracing::error!(
                                    pool_index = pool_index,
                                    pool_len = pool_len,
                                    prefix = %ia_prefix.prefix_ip,
                                    prefix_len = ia_prefix.prefix_len,
                                    "setup_prefix_sources PdPd: invalid subnet allocation at init"
                                );
                                return;
                            };
                            pd_prefix_info.store(Arc::new(Some(PdDelegationParent {
                                prefix: sub_block,
                                prefix_len: pool_len,
                            })));
                            expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(
                                ia_prefix.valid_lifetime as u64,
                            )));
                        }
                    }
                    loop {
                        tokio::select! {
                            change_result = prefix_reader.recv() => {
                                tracing::info!("PdPd IA_PREFIX update for {}", depend_iface_owned);
                                let matched = match &change_result {
                                    Ok(IAPrefixEvent::Updated { iface_name }) | Ok(IAPrefixEvent::Expired { iface_name })
                                        if *iface_name == depend_iface_owned => true,
                                    Ok(_) => false,
                                    Err(_) => {
                                        tracing::error!("PdPd change result error. exit loop");
                                        break;
                                    }
                                };
                                if !matched {
                                    continue;
                                }
                                let ia_prefix = prefix_map_clone.load(&depend_iface_owned);
                                if let Some(ia_prefix) = ia_prefix {
                                    if source_prefix_matches_max_len(
                                        ia_prefix.prefix_len,
                                        max_source_prefix_len,
                                    )
                                        && can_delegate_from_pd(ia_prefix.prefix_len, pool_len)
                                    {
                                        let Some((sub_block, _)) = checked_allocate_subnet(
                                            ia_prefix.prefix_ip,
                                            ia_prefix.prefix_len,
                                            pool_len,
                                            lan_slot_to_subnet_index(pool_index, pool_len),
                                        ) else {
                                            tracing::error!(
                                                pool_index = pool_index,
                                                pool_len = pool_len,
                                                prefix = %ia_prefix.prefix_ip,
                                                prefix_len = ia_prefix.prefix_len,
                                                "setup_prefix_sources PdPd: invalid subnet allocation in loop"
                                            );
                                            continue;
                                        };
                                        pd_prefix_info.store(Arc::new(Some(PdDelegationParent {
                                            prefix: sub_block,
                                            prefix_len: pool_len,
                                        })));
                                        expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(ia_prefix.valid_lifetime as u64)));
                                    } else {
                                        pd_prefix_info.store(Arc::new(None));
                                    }
                                } else {
                                    pd_prefix_info.store(Arc::new(None));
                                }
                            },
                            _ = dhcpv6_token_clone.cancelled() => {
                                break;
                            }
                            _ = expire_time.as_mut() => {
                                pd_prefix_info.store(Arc::new(None));
                                tracing::debug!("PdPd expire_time active for {}", depend_iface_owned);
                                expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(u64::MAX)));
                            }
                        }
                    }
                    tracing::info!("PdPd prefix listen for {} is down", depend_iface_owned);
                });
                continue;
            }
        };

        if let Some((base_prefix, pool_index, pref_lt, valid_lt)) = base_prefix_opt {
            // Static source handling
            let rt_prefix_len = 60;
            let sub_prefix_len = 64u8;
            let Some((sub_prefix, sub_router)) = checked_allocate_subnet(
                base_prefix,
                rt_prefix_len,
                sub_prefix_len,
                pool_index as u128,
            ) else {
                tracing::error!(
                    pool_index = pool_index,
                    base_prefix = %base_prefix,
                    "setup_prefix_sources: invalid static subnet allocation"
                );
                continue;
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
            runtime.static_info.push(ICMPv6ConfigInfo {
                rt_prefix: base_prefix,
                rt_prefix_len,
                sub_router,
                sub_prefix,
                sub_prefix_len,
                ra_preferred_lifetime: pref_lt,
                ra_valid_lifetime: valid_lt,
            });
        }

        if let Some(pd_config) = pd_config_opt {
            // PD source handling

            let pd_prefix_info: Option<ICMPv6ConfigInfo> = None;
            let pd_prefix_info = Arc::new(ArcSwap::from_pointee(pd_prefix_info));
            runtime.pd_info.insert(pd_config.depend_iface.clone(), pd_prefix_info.clone());

            let change_tx_clone = change_tx.clone();
            let ra_token_clone = ra_token.clone();
            let dhcpv6_token_clone = dhcpv6_token.clone();
            let iface_name_owned = iface_name.to_string();
            let lan_info_clone = lan_info.clone();
            let route_service_clone = route_service.clone();
            let depend_iface_owned = pd_config.depend_iface.clone();
            let prefix_map_clone = prefix_map.clone();
            let prefix_broadcast_tx_clone = prefix_broadcast_tx.clone();
            tokio::spawn(async move {
                let mut prefix_reader =
                    IAPrefixEventReader::new(prefix_broadcast_tx_clone.subscribe());
                let mut expire_time = Box::pin(tokio::time::sleep(Duration::from_secs(0)));
                let mut applied_state: Option<DynamicPrefixState> = None;

                let ia_prefix = prefix_map_clone.load(&depend_iface_owned);
                if let Some(ia_prefix) = ia_prefix {
                    if can_delegate_from_pd(ia_prefix.prefix_len, pd_config.sub_prefix_len) {
                        let (new_info, new_state) = update_current_info(
                            &iface_name_owned,
                            ia_prefix,
                            &pd_config,
                            expire_time.as_mut(),
                            &lan_info_clone,
                            &route_service_clone,
                        )
                        .await;
                        applied_state = replace_dynamic_prefix_state(
                            &route_service_clone,
                            &iface_name_owned,
                            applied_state,
                            new_state,
                        )
                        .await;
                        pd_prefix_info.store(Arc::new(new_info));
                    }
                }

                // Wait for both RA and DHCPv6 to finish before stopping
                let both_done = async {
                    tokio::join!(ra_token_clone.cancelled(), dhcpv6_token_clone.cancelled());
                };
                tokio::pin!(both_done);

                loop {
                    tokio::select! {
                        change_result = prefix_reader.recv() => {
                            tracing::info!("IA_PREFIX update");
                            let matched = match &change_result {
                                Ok(IAPrefixEvent::Updated { iface_name }) | Ok(IAPrefixEvent::Expired { iface_name })
                                    if *iface_name == depend_iface_owned => true,
                                Ok(_) => false,
                                Err(_) => {
                                    tracing::error!("get change result error. exit loop");
                                    break;
                                }
                            };
                            if !matched {
                                continue;
                            }
                            let ia_prefix = prefix_map_clone.load(&depend_iface_owned);
                            if let Some(ia_prefix) = ia_prefix {
                                if can_delegate_from_pd(ia_prefix.prefix_len, pd_config.sub_prefix_len) {
                                    let (new_info, new_state) = update_current_info(
                                        &iface_name_owned,
                                        ia_prefix,
                                        &pd_config,
                                        expire_time.as_mut(),
                                        &lan_info_clone,
                                        &route_service_clone,
                                    )
                                    .await;
                                    applied_state = replace_dynamic_prefix_state(
                                        &route_service_clone,
                                        &iface_name_owned,
                                        applied_state,
                                        new_state,
                                    )
                                    .await;
                                    pd_prefix_info.store(Arc::new(new_info));
                                } else {
                                    applied_state = replace_dynamic_prefix_state(
                                        &route_service_clone,
                                        &iface_name_owned,
                                        applied_state,
                                        None,
                                    )
                                    .await;
                                    pd_prefix_info.store(Arc::new(None));
                                }
                            } else {
                                applied_state = replace_dynamic_prefix_state(
                                    &route_service_clone,
                                    &iface_name_owned,
                                    applied_state,
                                    None,
                                )
                                .await;
                                pd_prefix_info.store(Arc::new(None));
                            }
                            let _ = change_tx_clone.send(());
                        },
                        _ = &mut both_done => {
                            break;
                        }
                        _ = expire_time.as_mut() => {
                            applied_state = replace_dynamic_prefix_state(
                                &route_service_clone,
                                &iface_name_owned,
                                applied_state,
                                None,
                            )
                            .await;
                            pd_prefix_info.store(Arc::new(None));
                            let _ = change_tx_clone.send(());
                            tracing::debug!("expire_time active");
                            expire_time.as_mut().set(tokio::time::sleep(Duration::from_secs(u64::MAX)));
                        }
                    }
                }

                clear_dynamic_prefix_state(&route_service_clone, applied_state).await;
                tracing::info!("iface: {} prefix listen is down", pd_config.depend_iface);
            });
        }
    }

    // Keep the change_tx sender alive until both RA and DHCPv6 tokens are cancelled.
    {
        let ra_token_clone = ra_token.clone();
        let dhcpv6_token_clone = dhcpv6_token.clone();
        tokio::spawn(async move {
            let _keep_alive = change_tx;
            tokio::join!(ra_token_clone.cancelled(), dhcpv6_token_clone.cancelled());
        });
    }

    PrefixSetupResult {
        runtime,
        ra_token,
        dhcpv6_token,
        change_notify: change_rx,
        cleanup_ips,
    }
}

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

/// Compute subnet network address and router address from a prefix and subnet index
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

/// Add a route with a gateway (via), used for PD delegation routes.
/// e.g. `ip -6 route replace <prefix>/<len> via <gateway> dev <iface> expires <lifetime>`
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

/// Delete a route, used to clean up PD delegation routes on release/expiry.
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

#[cfg(test)]
mod tests {
    use super::{allocate_subnet, source_prefix_matches_max_len};
    use landscape_common::ipv6_pd::LDIAPrefix;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::watch;
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
}
