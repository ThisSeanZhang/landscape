use std::net::Ipv6Addr;

use landscape_common::{
    lan_service::lan_ipv6::DHCPv6IAPDConfig,
    lan_service::lan_ipv6::{LanPrefixGroupConfig, PdPrefixRangeConfig, PrefixParentSource},
    wan_service::ipv6_pd::IAPrefixMap,
};

use super::*;

fn make_pd_status() -> Ipv6ServerStatus {
    make_pd_status_with_filter(56)
}

fn make_pd_status_with_filter(delegate_prefix_len: u8) -> Ipv6ServerStatus {
    let pd_config = DHCPv6IAPDConfig {
        delegate_prefix_len,
        preferred_lifetime: 3600,
        valid_lifetime: 7200,
    };

    let mut status =
        Ipv6ServerStatus::new(None, Some(pd_config), vec![], mpsc::unbounded_channel().0);

    let groups = vec![LanPrefixGroupConfig {
        group_id: "pd-group-1".into(),
        parent: PrefixParentSource::Static {
            base_prefix: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            parent_prefix_len: 48,
        },
        ra: None,
        na: None,
        pd: Some(PdPrefixRangeConfig { pool_len: 56, start_index: 1, end_index: 4 }),
    }];

    let subnets = compute_subnets(&groups, &IAPrefixMap::new(), 300);
    status.update_prefix(&subnets);
    status
}

#[test]
fn delegate_prefix_len_filters_snapshot_pool_blocks() {
    let mut excluded = make_pd_status_with_filter(55);
    assert!(excluded.offer_pd(b"pd-filtered").is_none());

    let mut included = make_pd_status_with_filter(56);
    assert!(included.offer_pd(b"pd-allowed").is_some());
}

#[test]
fn pool_len_above_64_is_not_installed_at_runtime() {
    let groups = vec![LanPrefixGroupConfig {
        group_id: "pd-too-specific".into(),
        parent: PrefixParentSource::Static {
            base_prefix: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            parent_prefix_len: 56,
        },
        ra: None,
        na: None,
        pd: Some(PdPrefixRangeConfig { pool_len: 65, start_index: 1, end_index: 1 }),
    }];

    assert!(compute_subnets(&groups, &IAPrefixMap::new(), 300).is_empty());
}

#[test]
fn new_pd_status_has_no_offers() {
    let status = make_pd_status();
    let duid = b"pd-client-01";
    assert!(!status.has_pd_offer(duid));
}

#[test]
fn offer_pd_allocates_prefix() {
    let mut status = make_pd_status();
    let duid = b"pd-client-01";
    let result = status.offer_pd(duid);
    assert!(result.is_some(), "should allocate a PD prefix");
}

#[test]
fn offer_pd_returns_same_prefix_on_second_call() {
    let mut status = make_pd_status();
    let duid = b"pd-client-02";
    let first = status.offer_pd(duid).unwrap();
    let second = status.offer_pd(duid).unwrap();
    assert_eq!(first, second);
}

#[test]
fn offer_pd_exhausts_pool() {
    let mut status = make_pd_status();
    // 4 slots (1..=4; slot 0 is reserved for WAN)
    let duids: Vec<_> = (0..4).map(|i| format!("pd-client-{:02}", i).into_bytes()).collect();
    for duid in &duids {
        assert!(status.offer_pd(duid).is_some());
    }
    // pool exhausted
    assert!(status.offer_pd(b"pd-client-overflow").is_none());
}

#[test]
fn confirm_pd_with_existing_lease() {
    let mut status = make_pd_status();
    let duid = b"pd-client-03";
    status.offer_pd(duid);
    assert!(status.confirm_pd(duid));
}

#[test]
fn confirm_pd_without_lease_returns_false() {
    let mut status = make_pd_status();
    assert!(!status.confirm_pd(b"unknown-client"));
}

#[test]
fn release_pd_removes_lease() {
    let mut status = make_pd_status();
    let duid = b"pd-client-04";
    status.offer_pd(duid);
    assert!(status.has_pd_offer(duid));
    let released = status.release_pd(duid);
    assert!(released.is_some());
    assert!(!status.has_pd_offer(duid));
}

#[test]
fn release_pd_nonexistent_returns_none() {
    let mut status = make_pd_status();
    assert!(status.release_pd(b"ghost").is_none());
}

#[test]
fn get_pd_prefix_for_existing_lease() {
    let mut status = make_pd_status();
    let duid = b"pd-client-05";
    let prefix = status.offer_pd(duid).unwrap();
    let queried = status.get_pd_prefix(duid);
    assert_eq!(Some(prefix), queried);
}

#[test]
fn get_pd_prefix_for_unknown_returns_none() {
    let status = make_pd_status();
    assert_eq!(status.get_pd_prefix(b"ghost"), None);
}

#[test]
fn confirm_pd_updates_lifetime() {
    let mut status = make_pd_status();
    let duid = b"pd-confirm-lt";
    let (_, prefix_len) = status.offer_pd(duid).unwrap();

    let prefixes = status.all_delegated_prefixes();
    let pfx = prefixes.iter().find(|p| p.prefix_len == prefix_len).unwrap();
    assert_eq!(pfx.valid_lifetime, 120);

    assert!(status.confirm_pd(duid));

    let prefixes = status.all_delegated_prefixes();
    let pfx = prefixes.iter().find(|p| p.prefix_len == prefix_len).unwrap();
    assert_eq!(pfx.valid_lifetime, 600);
}

#[test]
fn update_pd_routes_unknown_duid_returns_none() {
    let mut status = make_pd_status();
    let routes = vec![(Ipv6Addr::LOCALHOST, 64)];
    assert!(status.update_pd_routes(b"ghost", Ipv6Addr::LOCALHOST, routes).is_none());
}

#[test]
fn reconcile_pd_routes_cleans_up_stale() {
    let mut status = make_pd_status();
    let duid = b"pd-reconcile";
    status.offer_pd(duid);

    let stale = vec![(Ipv6Addr::new(0x2001, 0xdb8, 0, 0x500, 0, 0, 0, 0), 56)];
    status.update_pd_routes(duid, Ipv6Addr::LOCALHOST, stale);

    let cleanups = status.reconcile_pd_routes();
    assert!(!cleanups.is_empty(), "stale route should be cleaned up");
    assert_eq!(cleanups[0].routes.len(), 1);
}

#[test]
fn update_pd_routes_and_retrieve_old() {
    let mut status = make_pd_status();
    let duid = b"pd-client-07";
    status.offer_pd(duid);

    let new_routes = vec![(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0), 64)];
    let old = status.update_pd_routes(duid, Ipv6Addr::LOCALHOST, new_routes.clone());
    assert!(old.is_some());
    assert!(old.unwrap().is_empty());

    // update again
    let newer = vec![(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0), 64)];
    let old = status.update_pd_routes(duid, Ipv6Addr::LOCALHOST, newer);
    assert_eq!(old, Some(new_routes));
}

#[test]
fn reconcile_pd_routes_on_empty_status() {
    let mut status = make_pd_status();
    assert!(status.reconcile_pd_routes().is_empty());
}

#[test]
fn drain_all_pd_routes_removes_all_leases() {
    let mut status = make_pd_status();
    let duid1 = b"pd-client-drain-01";
    let duid2 = b"pd-client-drain-02";
    status.offer_pd(duid1);
    status.offer_pd(duid2);

    let routes = status.drain_all_pd_routes();
    // routes start empty, so drain returns empty vec
    assert!(routes.is_empty());
    assert!(!status.has_pd_offer(duid1));
    assert!(!status.has_pd_offer(duid2));
}

#[test]
fn clean_expired_pd_removes_only_expired() {
    let mut status = make_pd_status();
    let duid1 = b"pd-client-exp-01";
    let duid2 = b"pd-client-exp-02";
    status.offer_pd(duid1);
    status.offer_pd(duid2);
    // Both are fresh
    let expired = status.clean_expired_pd();
    assert!(expired.is_empty());
    assert!(status.has_pd_offer(duid1));
    assert!(status.has_pd_offer(duid2));
}
