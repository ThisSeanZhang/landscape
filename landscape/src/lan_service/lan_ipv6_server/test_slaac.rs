use std::net::Ipv6Addr;

use landscape_common::{
    lan_service::lan_ipv6::DHCPv6IANAConfig,
    lan_service::lan_ipv6::{
        LanPrefixGroupConfig, NaPrefixConfig, PrefixParentSource, RaPrefixConfig,
    },
    net::MacAddr,
    wan_service::ipv6_pd::{IAPrefixMap, LDIAPrefix},
};

use super::*;

fn make_slaac_status() -> Ipv6ServerStatus {
    let na_config = DHCPv6IANAConfig {
        max_prefix_len: 64,
        pool_start: 0x100,
        pool_end: Some(0x1FF),
        preferred_lifetime: 3600,
        valid_lifetime: 7200,
    };

    let (tx, _rx) = mpsc::unbounded_channel();
    let mut status = Ipv6ServerStatus::new(Some(na_config), None, vec![], tx);

    let groups = vec![LanPrefixGroupConfig {
        group_id: "default".into(),
        parent: PrefixParentSource::Static {
            base_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            parent_prefix_len: 60,
        },
        ra: Some(RaPrefixConfig {
            pool_index: 1,
            preferred_lifetime: 1800,
            valid_lifetime: 3600,
        }),
        na: Some(NaPrefixConfig { pool_index: 1 }),
        pd: None,
    }];

    let subnets = compute_subnets(&groups, &IAPrefixMap::new(), 300);
    status.update_prefix(&subnets);
    status
}

#[test]
fn static_group_using_wan_reserved_subnet_is_not_installed() {
    let group = LanPrefixGroupConfig {
        group_id: "static-reserved".into(),
        parent: PrefixParentSource::Static {
            base_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            parent_prefix_len: 60,
        },
        ra: Some(RaPrefixConfig {
            pool_index: 0,
            preferred_lifetime: 1800,
            valid_lifetime: 3600,
        }),
        na: Some(NaPrefixConfig { pool_index: 1 }),
        pd: None,
    };

    assert!(compute_subnets(&[group], &IAPrefixMap::new(), 300).is_empty());
}

#[test]
fn record_slaac_addr_succeeds_for_valid_ip() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xAA, 0xBB);
    let result = status.record_slaac_addr(mac, ip);
    assert_eq!(result, SlaacResult::Recorded);
}

#[test]
fn record_slaac_addr_conflict_with_existing_na() {
    let mut status = make_slaac_status();
    let duid = b"na-client-sl";
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Allocate via NA first, which claims the suffix
    let addrs = status.offer_na(duid, mac, None).unwrap();
    let na_ip = addrs[0];

    // Recording the same IP via SLAAC should conflict
    let slaac_mac = MacAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let result = status.record_slaac_addr(slaac_mac, na_ip);
    assert_eq!(result, SlaacResult::Conflict);
}

#[test]
fn touch_slaac_addr_refreshes_matching_existing_entry() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xAA, 0xBB);
    status.record_slaac_addr(mac, ip);
    status.boot_time -= std::time::Duration::from_secs(10);
    status.slaac_entries.get_mut(&ip).unwrap().relative_active_time = 0;

    assert!(status.touch_slaac_addr(mac, ip));
    assert!(status.slaac_entries.get(&ip).unwrap().relative_active_time >= 10);
}

#[test]
fn touch_slaac_addr_does_not_create_unknown_entry() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xCC, 0xDD);

    assert!(!status.touch_slaac_addr(mac, ip));
    assert!(!status.slaac_entries.contains_key(&ip));
}

#[test]
fn touch_slaac_addr_rejects_mismatched_mac() {
    let mut status = make_slaac_status();
    let owner = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let other = MacAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xEE, 0xFF);
    status.record_slaac_addr(owner, ip);
    status.slaac_entries.get_mut(&ip).unwrap().relative_active_time = 0;

    assert!(!status.touch_slaac_addr(other, ip));
    assert_eq!(status.slaac_entries.get(&ip).unwrap().relative_active_time, 0);
}

#[test]
fn clean_expired_slaac_removes_expired_entries() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xCC, 0xDD);
    status.record_slaac_addr(mac, ip);

    // Fresh entry with huge thresholds should neither be probed nor cleaned
    let sweep = status.slaac_expire_sweep(u64::MAX, u64::MAX);
    assert!(sweep.to_probe.is_empty());
    assert!(sweep.expired.is_empty());
}

#[test]
fn clean_expired_slaac_with_zero_threshold_removes_all() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xEE, 0xFF);
    status.record_slaac_addr(mac, ip);

    let sweep = status.slaac_expire_sweep(0, 0);
    assert!(sweep.to_probe.is_empty());
    assert_eq!(sweep.expired.len(), 1);
    assert_eq!(sweep.expired[0], (ip, mac));
    assert!(!status.slaac_entries.contains_key(&ip));
}

#[test]
fn slaac_expire_sweep_marks_idle_entries_for_probe_within_first_stage() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xAA, 0xBB);
    status.record_slaac_addr(mac, ip);
    status.boot_time -= std::time::Duration::from_secs(100);
    status.slaac_entries.get_mut(&ip).unwrap().relative_active_time = 0;

    let sweep = status.slaac_expire_sweep(60, 200);
    assert_eq!(sweep.to_probe, vec![ip]);
    assert!(sweep.expired.is_empty());
    assert!(status.slaac_entries.get(&ip).unwrap().probe_pending);
}

#[test]
fn slaac_expire_sweep_does_not_probe_already_pending_entries() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xAA, 0xBB);
    status.record_slaac_addr(mac, ip);
    status.boot_time -= std::time::Duration::from_secs(100);
    status.slaac_entries.get_mut(&ip).unwrap().relative_active_time = 0;
    status.slaac_entries.get_mut(&ip).unwrap().probe_pending = true;

    let sweep = status.slaac_expire_sweep(60, 200);
    assert!(sweep.to_probe.is_empty());
    assert!(sweep.expired.is_empty());
    assert!(status.slaac_entries.contains_key(&ip));
}

#[test]
fn slaac_expire_sweep_removes_pending_entries_past_second_stage() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xEE, 0xFF);
    status.record_slaac_addr(mac, ip);
    status.boot_time -= std::time::Duration::from_secs(300);
    status.slaac_entries.get_mut(&ip).unwrap().relative_active_time = 0;
    status.slaac_entries.get_mut(&ip).unwrap().probe_pending = true;

    let sweep = status.slaac_expire_sweep(60, 200);
    assert!(sweep.to_probe.is_empty());
    assert_eq!(sweep.expired, vec![(ip, mac)]);
    assert!(!status.slaac_entries.contains_key(&ip));
}

#[test]
fn slaac_observation_clears_probe_pending() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0xAA, 0xBB);
    status.record_slaac_addr(mac, ip);
    status.slaac_entries.get_mut(&ip).unwrap().probe_pending = true;

    assert!(status.touch_slaac_addr(mac, ip));
    assert!(!status.slaac_entries.get(&ip).unwrap().probe_pending);

    status.slaac_entries.get_mut(&ip).unwrap().probe_pending = true;
    status.record_slaac_addr(mac, ip);
    assert!(!status.slaac_entries.get(&ip).unwrap().probe_pending);
}

fn pd_prefix(prefix: &str, prefix_len: u8) -> LDIAPrefix {
    LDIAPrefix {
        preferred_lifetime: 1800,
        valid_lifetime: 3600,
        prefix_len,
        prefix_ip: prefix.parse().unwrap(),
        last_update_time: 0.0,
    }
}

fn dynamic_ra_group(snapshot: u8, pool_index: u32) -> LanPrefixGroupConfig {
    LanPrefixGroupConfig {
        group_id: "dynamic".into(),
        parent: PrefixParentSource::Pd {
            depend_iface: "wan0".into(),
            expected_pd_len_snapshot: snapshot,
        },
        ra: Some(RaPrefixConfig {
            pool_index,
            preferred_lifetime: 300,
            valid_lifetime: 600,
        }),
        na: None,
        pd: None,
    }
}

#[test]
fn dynamic_subnets_use_snapshot_instead_of_actual_prefix_len() {
    let prefix_map = IAPrefixMap::new();
    prefix_map.store("wan0", pd_prefix("2001:db8:1200::", 56), 60);

    let subnets = compute_subnets(&[dynamic_ra_group(60, 15)], &prefix_map, 300);
    assert_eq!(subnets.len(), 1);
    assert_eq!(subnets[0].sub_prefix, "2001:db8:1200:f::".parse::<Ipv6Addr>().unwrap());
    assert_eq!(prefix_map.load_actual("wan0").unwrap().prefix_len, 56);
}

#[test]
fn dynamic_subnets_require_both_wan_and_snapshot_compatibility() {
    let prefix_map = IAPrefixMap::new();
    prefix_map.store("wan0", pd_prefix("2001:db8:1200::", 64), 60);
    assert!(compute_subnets(&[dynamic_ra_group(60, 1)], &prefix_map, 300).is_empty());
    assert!(prefix_map.load_actual("wan0").is_some());

    prefix_map.store("wan0", pd_prefix("2001:db8:1200::", 56), 64);
    assert!(compute_subnets(&[dynamic_ra_group(60, 1)], &prefix_map, 300).is_empty());
    assert!(prefix_map.load_for_lan("wan0").is_some());

    let _ = prefix_map.remove("wan0");
    assert!(compute_subnets(&[dynamic_ra_group(60, 1)], &prefix_map, 300).is_empty());
}
