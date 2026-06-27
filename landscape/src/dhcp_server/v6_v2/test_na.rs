use std::net::Ipv6Addr;

use landscape_common::{
    dhcp::v6_server::config::DHCPv6IANAConfig,
    ipv6::lan::{LanPrefixGroupConfig, NaPrefixConfig, PrefixParentSource, RaPrefixConfig},
    ipv6_pd::IAPrefixMap,
    net::MacAddr,
};

use super::*;

fn make_na_status() -> Ipv6ServerStatus {
    let na_config = DHCPv6IANAConfig {
        max_prefix_len: 64,
        pool_start: 0x100,
        pool_end: Some(0x1FF),
        preferred_lifetime: 3600,
        valid_lifetime: 7200,
    };

    Ipv6ServerStatus::new(Some(na_config), None, vec![])
}

fn make_status_with_prefixes() -> Ipv6ServerStatus {
    let na_config = DHCPv6IANAConfig {
        max_prefix_len: 64,
        pool_start: 0x100,
        pool_end: Some(0x1FF),
        preferred_lifetime: 3600,
        valid_lifetime: 7200,
    };

    let mut status = Ipv6ServerStatus::new(Some(na_config), None, vec![]);

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
fn new_status_has_no_offers() {
    let status = make_na_status();
    let duid = b"test-client-01";
    assert!(!status.has_na_offer(duid));
}

#[test]
fn offer_na_allocates_addresses() {
    let mut status = make_status_with_prefixes();
    let duid = b"test-client-01";
    let addrs = status.offer_na(duid, None, None);
    assert!(addrs.is_some(), "should allocate addresses");
    assert!(!addrs.unwrap().is_empty(), "should have at least one address");
}

#[test]
fn offer_na_returns_same_lease_on_second_call() {
    let mut status = make_status_with_prefixes();
    let duid = b"test-client-02";
    let first = status.offer_na(duid, None, None).unwrap();
    let second = status.offer_na(duid, None, None).unwrap();
    assert_eq!(first, second);
}

#[test]
fn confirm_na_with_existing_lease() {
    let mut status = make_status_with_prefixes();
    let duid = b"test-client-03";
    status.offer_na(duid, None, None);
    assert!(status.confirm_na(duid));
}

#[test]
fn confirm_na_without_lease_returns_false() {
    let mut status = make_status_with_prefixes();
    assert!(!status.confirm_na(b"unknown-client"));
}

#[test]
fn release_na_removes_lease() {
    let mut status = make_status_with_prefixes();
    let duid = b"test-client-04";
    status.offer_na(duid, None, None);
    assert!(status.has_na_offer(duid));
    let released = status.release_na(duid);
    assert!(released.is_some());
    assert!(!status.has_na_offer(duid));
}

#[test]
fn release_na_nonexistent_returns_none() {
    let mut status = make_status_with_prefixes();
    assert!(status.release_na(b"ghost").is_none());
}

#[test]
fn get_na_addresses_for_existing_lease() {
    let mut status = make_status_with_prefixes();
    let duid = b"test-client-05";
    let addrs = status.offer_na(duid, None, None).unwrap();
    let queried = status.get_na_addresses(duid);
    assert_eq!(addrs, queried);
}

#[test]
fn get_na_addresses_for_unknown_duid_returns_empty() {
    let status = make_status_with_prefixes();
    assert!(status.get_na_addresses(b"ghost").is_empty());
}

#[test]
fn offer_na_exhausts_pool() {
    let na_config = DHCPv6IANAConfig {
        max_prefix_len: 64,
        pool_start: 0x100,
        pool_end: Some(0x102),
        preferred_lifetime: 3600,
        valid_lifetime: 7200,
    };
    let mut status = Ipv6ServerStatus::new(Some(na_config), None, vec![]);
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
    let subnets2 = compute_subnets(&groups, &IAPrefixMap::new());
    status.update_prefix(&subnets2);

    assert!(status.offer_na(b"client-01", None, None).is_some());
    assert!(status.offer_na(b"client-02", None, None).is_some());
    assert!(status.offer_na(b"client-03", None, None).is_none());
}

#[test]
fn offer_na_uses_static_binding() {
    let mut status = make_status_with_prefixes();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    status.bind_mac_suffix(mac, 0x0200);
    let addrs = status.offer_na(b"static-duid", Some(mac), None).unwrap();
    let expected = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0200);
    assert_eq!(addrs[0], expected);
}

#[test]
fn confirm_na_updates_lifetime() {
    let mut status = make_status_with_prefixes();
    let duid = b"confirm-lt";
    status.offer_na(duid, None, None);

    let addr = status.lookup_by_ip(status.get_na_addresses(duid)[0]).unwrap();
    assert_eq!(addr.valid_lifetime, 120);

    assert!(status.confirm_na(duid));

    let addr = status.lookup_by_ip(status.get_na_addresses(duid)[0]).unwrap();
    assert_eq!(addr.valid_lifetime, 7200);
}

#[test]
fn check_address_owner_for_unallocated_ip() {
    let status = make_status_with_prefixes();
    // IP within the /64 prefix but not allocated → Unallocated
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1234, 0x5678);
    let result = status.check_address_owner(ip, b"some-duid", None);
    assert_eq!(result, NaAddressCheck::Unallocated);
}

#[test]
fn check_address_owner_not_on_link() {
    let status = make_status_with_prefixes();
    // IP outside the /64 prefix → NotOnLink
    let ip = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 1);
    let result = status.check_address_owner(ip, b"some-duid", None);
    assert_eq!(result, NaAddressCheck::NotOnLink);
}

#[test]
fn clean_expired_na_removes_only_expired() {
    let mut status = make_status_with_prefixes();
    let duid1 = b"client-expired-01";
    let duid2 = b"client-active-02";
    status.offer_na(duid1, None, None);
    status.offer_na(duid2, None, None);
    // Both leases are fresh, so clean returns empty
    let expired = status.clean_expired_na();
    assert!(expired.is_empty());
    assert!(status.has_na_offer(duid1));
    assert!(status.has_na_offer(duid2));
}

#[test]
fn update_device_binding_bind_and_unbind() {
    let mut status = make_status_with_prefixes();
    let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0100);

    let result = status.update_device_binding(mac, Some(ip));
    assert!(matches!(result, DeviceBindingResult::Bound(_)));

    // Unbind
    let result = status.update_device_binding(mac, None);
    assert!(matches!(result, DeviceBindingResult::Removed(_)));
}

#[test]
fn bind_mac_suffix_new_binding() {
    let mut status = make_status_with_prefixes();
    let mac = MacAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let suffix = 0x0100u64;
    let result = status.bind_mac_suffix(mac, suffix);
    assert!(matches!(result, MacSuffixBindResult::Bound(_)));
}

#[test]
fn bind_mac_suffix_already_bound() {
    let mut status = make_status_with_prefixes();
    let mac = MacAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let suffix = 0x0100u64;
    status.bind_mac_suffix(mac, suffix);
    let result = status.bind_mac_suffix(mac, suffix);
    assert!(matches!(result, MacSuffixBindResult::AlreadyBound));
}

#[test]
fn remove_mac_binding_returns_changes() {
    let mut status = make_status_with_prefixes();
    let mac = MacAddr::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0101);
    let duid = b"binding-client-01";
    // Create a NA lease first so there is a DUID lease to expire on unbind
    status.offer_na(duid, Some(mac), None);
    // Then bind statically
    status.update_device_binding(mac, Some(ip));
    let changes = status.remove_mac_binding(&mac);
    assert!(!changes.expired.is_empty());
}
