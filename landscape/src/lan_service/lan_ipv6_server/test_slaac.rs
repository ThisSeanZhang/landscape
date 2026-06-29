use std::net::Ipv6Addr;

use landscape_common::{
    dhcp::v6_server::config::DHCPv6IANAConfig,
    ipv6::lan::{LanPrefixGroupConfig, NaPrefixConfig, PrefixParentSource, RaPrefixConfig},
    ipv6_pd::IAPrefixMap,
    net::MacAddr,
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

    let mut status =
        Ipv6ServerStatus::new(Some(na_config), None, vec![], mpsc::unbounded_channel().0);

    let groups = vec![LanPrefixGroupConfig {
        group_id: "default".into(),
        parent: PrefixParentSource::Static {
            base_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            parent_prefix_len: 64,
        },
        ra: Some(RaPrefixConfig {
            pool_index: 0,
            preferred_lifetime: 1800,
            valid_lifetime: 3600,
        }),
        na: Some(NaPrefixConfig { pool_index: 0 }),
        pd: None,
    }];

    let subnets = compute_subnets(&groups, &IAPrefixMap::new());
    status.update_prefix(&subnets);
    status
}

#[test]
fn record_slaac_addr_succeeds_for_valid_ip() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xAA, 0xBB);
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
fn clean_expired_slaac_removes_expired_entries() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xCC, 0xDD);
    status.record_slaac_addr(mac, ip);

    // Fresh entry with high threshold should not be cleaned
    let expired = status.clean_expired_slaac(u64::MAX);
    assert!(expired.is_empty());
}

#[test]
fn clean_expired_slaac_with_zero_threshold_removes_all() {
    let mut status = make_slaac_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xEE, 0xFF);
    status.record_slaac_addr(mac, ip);

    let expired = status.clean_expired_slaac(0);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0], (ip, mac));
}
