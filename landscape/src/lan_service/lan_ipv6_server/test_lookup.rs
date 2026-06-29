use std::net::Ipv6Addr;

use landscape_common::{
    dhcp::v6_server::config::{DHCPv6IANAConfig, DHCPv6IAPDConfig},
    ipv6::lan::{
        LanPrefixGroupConfig, NaPrefixConfig, PdPrefixRangeConfig, PrefixParentSource,
        RaPrefixConfig,
    },
    ipv6_pd::IAPrefixMap,
    net::MacAddr,
};

use super::*;

fn make_full_status() -> Ipv6ServerStatus {
    let na_config = DHCPv6IANAConfig {
        max_prefix_len: 64,
        pool_start: 0x100,
        pool_end: Some(0x1FF),
        preferred_lifetime: 3600,
        valid_lifetime: 7200,
    };

    let pd_config = DHCPv6IAPDConfig {
        delegate_prefix_len: 56,
        preferred_lifetime: 3600,
        valid_lifetime: 7200,
    };

    let mut status = Ipv6ServerStatus::new(
        Some(na_config),
        Some(pd_config),
        vec![],
        mpsc::unbounded_channel().0,
    );

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
        pd: Some(PdPrefixRangeConfig { pool_len: 56, start_index: 0, end_index: 3 }),
    }];

    let subnets = compute_subnets(&groups, &IAPrefixMap::new());
    status.update_prefix(&subnets);
    status
}

#[test]
fn all_addresses_includes_na_leases() {
    let mut status = make_full_status();
    let duid = b"lookup-na-01";
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    status.offer_na(duid, Some(mac), Some("host1".into()));
    let all = status.all_addresses();
    assert!(!all.is_empty(), "should include NA lease addresses");
    assert!(all.iter().any(|a| a.source == AddrSource::Dhcpv6Na));
}

#[test]
fn all_addresses_includes_slaac_entries() {
    let mut status = make_full_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xAB, 0xCD);
    status.record_slaac_addr(mac, ip);
    let all = status.all_addresses();
    assert!(all.iter().any(|a| a.source == AddrSource::Slaac && a.ip == ip));
}

// ── all_delegated_prefixes tests ────────────────────────────────────────────

#[test]
fn all_delegated_prefixes_includes_pd_leases() {
    let mut status = make_full_status();
    status.offer_pd(b"lookup-pd-01");
    let prefixes = status.all_delegated_prefixes();
    assert_eq!(prefixes.len(), 1);
}

// ── lookup_by_ip tests ──────────────────────────────────────────────────────

#[test]
fn lookup_by_ip_for_slaac_address() {
    let mut status = make_full_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xBB, 0xAA);
    status.record_slaac_addr(mac, ip);
    let addr = status.lookup_by_ip(ip);
    assert!(addr.is_some());
    let addr = addr.unwrap();
    assert_eq!(addr.ip, ip);
    assert_eq!(addr.mac, Some(mac));
    assert_eq!(addr.source, AddrSource::Slaac);
}

#[test]
fn lookup_by_ip_for_na_address() {
    let mut status = make_full_status();
    let duid = b"lookup-na-02";
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let addrs = status.offer_na(duid, Some(mac), Some("host2".into())).unwrap();
    let na_ip = addrs[0];

    let addr = status.lookup_by_ip(na_ip);
    assert!(addr.is_some());
    let addr = addr.unwrap();
    assert_eq!(addr.ip, na_ip);
    assert_eq!(addr.source, AddrSource::Dhcpv6Na);
}

#[test]
fn lookup_by_ip_unknown_returns_none() {
    let status = make_full_status();
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xDE, 0xAD);
    assert!(status.lookup_by_ip(ip).is_none());
}

// ── lookup_ip_by_mac tests ──────────────────────────────────────────────────

#[test]
fn lookup_ip_by_mac_for_na_lease() {
    let mut status = make_full_status();
    let duid = b"lookup-na-03";
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let addrs = status.offer_na(duid, Some(mac), None).unwrap();
    let expected_ip = addrs[0];

    let ip = status.lookup_ip_by_mac(&mac);
    assert_eq!(ip, Some(expected_ip));
}

#[test]
fn lookup_ip_by_mac_for_slaac_entry() {
    let mut status = make_full_status();
    let mac = MacAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xCC, 0xDD);
    status.record_slaac_addr(mac, ip);

    let found = status.lookup_ip_by_mac(&mac);
    assert_eq!(found, Some(ip));
}

#[test]
fn lookup_ip_by_mac_unknown_returns_none() {
    let status = make_full_status();
    let mac = MacAddr::from([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);
    assert!(status.lookup_ip_by_mac(&mac).is_none());
}

// ── to_ipv6_na_info / to_dhcpv6_offer_info tests ────────────────────────────

#[test]
fn to_ipv6_na_info_includes_slaac_entries() {
    let mut status = make_full_status();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xFE, 0xED);
    status.record_slaac_addr(mac, ip);

    let info = status.to_ipv6_na_info();
    assert!(info.offered_ips.contains_key(&ip));
}

#[test]
fn to_ipv6_na_info_empty_without_slaac() {
    let status = make_full_status();
    let info = status.to_ipv6_na_info();
    assert!(info.offered_ips.is_empty());
}

#[test]
fn to_dhcpv6_offer_info_includes_na_and_pd() {
    let mut status = make_full_status();
    status.offer_na(b"info-na-01", None, Some("host-info".into()));
    status.offer_pd(b"info-pd-01");

    let info = status.to_dhcpv6_offer_info();
    assert!(!info.offered_addresses.is_empty());
    assert!(!info.delegated_prefixes.is_empty());
}

// ── suffix_to_addrs tests ───────────────────────────────────────────────────

#[test]
fn suffix_to_addrs_with_valid_prefix() {
    let status = make_full_status();
    let addrs = status.suffix_to_addrs(0x0100);
    assert!(!addrs.is_empty());
    let expected = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0100);
    assert_eq!(addrs[0], expected);
}
