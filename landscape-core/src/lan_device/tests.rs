use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use landscape_common::config_service::enrolled_device::EnrolledDevice;
use landscape_common::event::hub::{
    EnrolledDeviceEvent, IPv4AssignEvent, IPv4AssignInfo, IPv6AssignEvent, IPv6AssignInfo,
    IPv6AssignSource, Ipv6AssignAddress, LanDiscoveryEvent, LanDiscoverySource,
};
use landscape_common::net::MacAddr;
use landscape_common::utils::time::get_f64_timestamp;
use uuid::Uuid;

use super::*;

fn enrolled(
    id: Uuid,
    mac: [u8; 6],
    hostname: Option<&str>,
    ipv4: Option<Ipv4Addr>,
) -> EnrolledDevice {
    EnrolledDevice {
        id,
        update_at: 0.0,
        iface_name: Some("lan0".to_string()),
        name: "device".to_string(),
        fake_name: None,
        remark: None,
        hostname: hostname.map(str::to_string),
        mac: MacAddr::from(mac),
        ipv4,
        ipv6: None,
        tag: Vec::new(),
        dhcp_custom_options: Vec::new(),
        dhcp_filter_options: Vec::new(),
    }
}

fn directory(devices: &[EnrolledDevice]) -> Arc<LanDeviceDirectory> {
    LanDeviceDirectory::with_seed(devices)
}

fn v4(mac: [u8; 6]) -> MacAddr {
    MacAddr::from(mac)
}

fn ipv4_allocated(
    mac: [u8; 6],
    ip: Ipv4Addr,
    hostname: Option<&str>,
    device_id: Option<Uuid>,
) -> IPv4AssignEvent {
    IPv4AssignEvent::Allocated(IPv4AssignInfo {
        iface_name: "lan0".to_string(),
        mac: v4(mac),
        ip,
        hostname: hostname.map(str::to_string),
        device_id,
    })
}

fn ipv4_expired(mac: [u8; 6], ip: Ipv4Addr, hostname: Option<&str>) -> IPv4AssignEvent {
    IPv4AssignEvent::Expired(IPv4AssignInfo {
        iface_name: "lan0".to_string(),
        mac: v4(mac),
        ip,
        hostname: hostname.map(str::to_string),
        device_id: None,
    })
}

fn ipv6_addrs(addrs: Vec<(Ipv6Addr, IPv6AssignSource)>) -> Vec<Ipv6AssignAddress> {
    addrs.into_iter().map(|(ip, source)| Ipv6AssignAddress { ip, source }).collect()
}

fn ipv6_allocated(
    mac: [u8; 6],
    addrs: Vec<(Ipv6Addr, IPv6AssignSource)>,
    device_id: Option<Uuid>,
) -> IPv6AssignEvent {
    IPv6AssignEvent::Allocated(IPv6AssignInfo {
        iface_name: "lan0".to_string(),
        mac: v4(mac),
        ips: ipv6_addrs(addrs),
        device_id,
    })
}

fn ipv6_flush(mac: [u8; 6], addrs: Vec<(Ipv6Addr, IPv6AssignSource)>) -> IPv6AssignEvent {
    IPv6AssignEvent::Flush(IPv6AssignInfo {
        iface_name: "lan0".to_string(),
        mac: v4(mac),
        ips: ipv6_addrs(addrs),
        device_id: None,
    })
}

fn discovery(mac: Option<[u8; 6]>, ip: IpAddr) -> LanDiscoveryEvent {
    LanDiscoveryEvent {
        iface_name: "lan0".to_string(),
        mac: mac.map(v4),
        ip,
        source: LanDiscoverySource::Arp,
    }
}

fn neighbor(mac: Option<[u8; 6]>, ip: Ipv6Addr) -> LanDiscoveryEvent {
    LanDiscoveryEvent {
        iface_name: "lan0".to_string(),
        mac: mac.map(v4),
        ip: IpAddr::V6(ip),
        source: LanDiscoverySource::Neighbor,
    }
}

fn ipv4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn ipv6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

// ── hostname adjudication (migrated from lan_hostname) ──────────────

#[test]
fn dhcp_allocation_does_not_override_enrolled_hostname() {
    let dir = directory(&[enrolled(
        Uuid::new_v4(),
        [0, 1, 2, 3, 4, 5],
        Some("nas"),
        Some(ipv4("192.168.1.10")),
    )]);

    dir.apply_ipv4_event(ipv4_allocated(
        [0, 1, 2, 3, 4, 5],
        ipv4("192.168.1.200"),
        Some("nas"),
        None,
    ));

    let entry = dir.entry_by_hostname("nas").unwrap();
    assert_eq!(entry.ipv4, Some(ipv4("192.168.1.10")));
    assert!(entry.hostname_from_enroll);
}

#[test]
fn dhcp_expiry_clears_only_non_enrolled_hostname() {
    let dir = directory(&[enrolled(
        Uuid::new_v4(),
        [0, 1, 2, 3, 4, 6],
        Some("device"),
        Some(ipv4("192.168.1.51")),
    )]);

    dir.apply_ipv4_event(ipv4_allocated(
        [0, 1, 2, 3, 4, 7],
        ipv4("192.168.1.50"),
        Some("lease"),
        None,
    ));
    assert!(dir.entry_by_hostname("lease").is_some());

    dir.apply_ipv4_event(ipv4_expired([0, 1, 2, 3, 4, 7], ipv4("192.168.1.50"), Some("lease")));
    assert!(dir.entry_by_hostname("lease").is_none());
    assert!(dir.entry_by_hostname("device").is_some());
}

#[test]
fn dhcp_hostname_moves_between_anonymous_devices() {
    let dir = directory(&[]);
    dir.apply_ipv4_event(ipv4_allocated([0, 0, 0, 0, 0, 1], ipv4("10.0.0.5"), Some("phone"), None));
    dir.apply_ipv4_event(ipv4_allocated([0, 0, 0, 0, 0, 2], ipv4("10.0.0.6"), Some("phone"), None));

    // Last non-enrolled claimant owns the name.
    let owner = dir.entry_by_hostname("phone").unwrap();
    assert_eq!(owner.mac, Some(v4([0, 0, 0, 0, 0, 2])));
    assert!(dir.entry_by_mac(&v4([0, 0, 0, 0, 0, 1])).unwrap().hostname.is_none());
}

// ── IPv4 lease lifecycle ─────────────────────────────────────────────

#[test]
fn ipv4_lease_lifecycle_and_reverse_lookup() {
    let dir = directory(&[]);
    let ip = ipv4("10.0.0.5");

    dir.apply_ipv4_event(ipv4_allocated([0, 0, 0, 0, 0, 1], ip, Some("phone"), None));
    let entry = dir.entry_by_ipv4(&ip).unwrap();
    assert_eq!(entry.ipv4_source, Some(AddressSourceV4::Lease));
    assert_eq!(entry.hostname.as_deref(), Some("phone"));

    dir.apply_ipv4_event(ipv4_expired([0, 0, 0, 0, 0, 1], ip, Some("phone")));
    assert!(dir.entry_by_ipv4(&ip).is_none());
    assert!(dir.entry_by_hostname("phone").is_none());
}

#[test]
fn arp_discovery_does_not_displace_lease() {
    let dir = directory(&[]);
    let ip = ipv4("10.0.0.7");

    dir.apply_discovery_event(discovery(Some([0, 0, 0, 0, 0, 9]), IpAddr::V4(ip)));
    assert_eq!(dir.entry_by_ipv4(&ip).unwrap().ipv4_source, Some(AddressSourceV4::Arp));

    dir.apply_ipv4_event(ipv4_allocated([0, 0, 0, 0, 0, 9], ip, None, None));
    assert_eq!(dir.entry_by_ipv4(&ip).unwrap().ipv4_source, Some(AddressSourceV4::Lease));

    // A later ARP observation refreshes but does not downgrade the lease.
    dir.apply_discovery_event(discovery(Some([0, 0, 0, 0, 0, 9]), IpAddr::V4(ip)));
    assert_eq!(dir.entry_by_ipv4(&ip).unwrap().ipv4_source, Some(AddressSourceV4::Lease));
}

// ── address claim arbitration (cross-entry evidence strength) ──────

#[test]
fn arp_discovery_does_not_displace_enrolled_static() {
    let id = Uuid::new_v4();
    let static_ip = ipv4("10.0.0.5");
    let dir = directory(&[enrolled(id, [0, 0, 0, 0, 0, 1], Some("nas"), Some(static_ip))]);

    // ARP observes the static IP on another MAC (stale config / spoofing).
    dir.apply_discovery_event(discovery(Some([0, 0, 0, 0, 0, 2]), IpAddr::V4(static_ip)));

    let owner = dir.entry_by_ipv4(&static_ip).unwrap();
    assert_eq!(owner.device_id, Some(id));
    assert_eq!(owner.ipv4_source, Some(AddressSourceV4::Static));
    assert_eq!(dir.entry_by_mac(&v4([0, 0, 0, 0, 0, 2])).unwrap().ipv4, None);
}

#[test]
fn arp_discovery_does_not_displace_other_devices_lease() {
    let dir = directory(&[]);
    let ip = ipv4("10.0.0.6");

    dir.apply_ipv4_event(ipv4_allocated([0, 0, 0, 0, 0, 1], ip, None, None));
    dir.apply_discovery_event(discovery(Some([0, 0, 0, 0, 0, 2]), IpAddr::V4(ip)));

    let owner = dir.entry_by_ipv4(&ip).unwrap();
    assert_eq!(owner.mac, Some(v4([0, 0, 0, 0, 0, 1])));
    assert_eq!(owner.ipv4_source, Some(AddressSourceV4::Lease));
    assert_eq!(dir.entry_by_mac(&v4([0, 0, 0, 0, 0, 2])).unwrap().ipv4, None);
}

#[test]
fn dhcp_lease_does_not_displace_enrolled_static() {
    let id = Uuid::new_v4();
    let static_ip = ipv4("10.0.0.7");
    let dir = directory(&[enrolled(id, [0, 0, 0, 0, 0, 1], Some("nas"), Some(static_ip))]);

    // Pool/static overlap (config error): the operator intent wins.
    dir.apply_ipv4_event(ipv4_allocated([0, 0, 0, 0, 0, 2], static_ip, Some("phone"), None));

    let owner = dir.entry_by_ipv4(&static_ip).unwrap();
    assert_eq!(owner.device_id, Some(id));
    assert_eq!(owner.ipv4_source, Some(AddressSourceV4::Static));
    // The lease holder keeps its hostname but not the conflicting address.
    assert_eq!(dir.entry_by_hostname("phone").unwrap().ipv4, None);
}

#[test]
fn arp_observed_ip_moves_between_anonymous_devices() {
    let dir = directory(&[]);
    let ip = ipv4("10.0.0.8");

    dir.apply_discovery_event(discovery(Some([0, 0, 0, 0, 0, 1]), IpAddr::V4(ip)));
    assert_eq!(dir.entry_by_ipv4(&ip).unwrap().mac, Some(v4([0, 0, 0, 0, 0, 1])));

    // Equal evidence: the latest observation wins (the address moved).
    dir.apply_discovery_event(discovery(Some([0, 0, 0, 0, 0, 2]), IpAddr::V4(ip)));
    assert_eq!(dir.entry_by_ipv4(&ip).unwrap().mac, Some(v4([0, 0, 0, 0, 0, 2])));
    assert_eq!(dir.entry_by_mac(&v4([0, 0, 0, 0, 0, 1])).unwrap().ipv4, None);
}

#[test]
fn enrolled_static_displaces_arp_owner() {
    let dir = directory(&[]);
    let ip = ipv4("10.0.0.9");

    dir.apply_discovery_event(discovery(Some([0, 0, 0, 0, 0, 2]), IpAddr::V4(ip)));
    assert_eq!(dir.entry_by_ipv4(&ip).unwrap().ipv4_source, Some(AddressSourceV4::Arp));

    // Enrolling a static binding afterwards takes the address over.
    let id = Uuid::new_v4();
    dir.apply_device_event(EnrolledDeviceEvent::Updated {
        old: None,
        new: enrolled(id, [0, 0, 0, 0, 0, 1], Some("nas"), Some(ip)),
    });

    let owner = dir.entry_by_ipv4(&ip).unwrap();
    assert_eq!(owner.device_id, Some(id));
    assert_eq!(owner.ipv4_source, Some(AddressSourceV4::Static));
    assert_eq!(dir.entry_by_mac(&v4([0, 0, 0, 0, 0, 2])).unwrap().ipv4, None);
}

#[test]
fn neighbor_discovery_does_not_displace_dhcpv6_of_another_device() {
    let dir = directory(&[]);
    let ip = ipv6("fd00::1");

    dir.apply_ipv6_event(ipv6_allocated(
        [0, 0, 0, 0, 0, 1],
        vec![(ip, IPv6AssignSource::Dhcpv6)],
        None,
    ));
    dir.apply_discovery_event(neighbor(Some([0, 0, 0, 0, 0, 2]), ip));

    let owner = dir.entry_by_ipv6(&ip).unwrap();
    assert_eq!(owner.mac, Some(v4([0, 0, 0, 0, 0, 1])));
    assert_eq!(owner.ipv6_addrs.get(&ip), Some(&AddressSourceV6::Dhcpv6));
    assert!(dir.entry_by_mac(&v4([0, 0, 0, 0, 0, 2])).unwrap().ipv6_addrs.is_empty());
}

#[test]
fn slaac_address_moves_between_entries() {
    let dir = directory(&[]);
    let ip = ipv6("fd00::2");

    dir.apply_ipv6_event(ipv6_allocated(
        [0, 0, 0, 0, 0, 1],
        vec![(ip, IPv6AssignSource::Slaac)],
        None,
    ));
    dir.apply_discovery_event(neighbor(Some([0, 0, 0, 0, 0, 2]), ip));

    // Equal evidence (neighbor observation is SLAAC-tagged): latest wins.
    let owner = dir.entry_by_ipv6(&ip).unwrap();
    assert_eq!(owner.mac, Some(v4([0, 0, 0, 0, 0, 2])));
    assert!(dir.entry_by_mac(&v4([0, 0, 0, 0, 0, 1])).unwrap().ipv6_addrs.is_empty());
}

// ── IPv6 sets and AAAA priority ──────────────────────────────────────

#[test]
fn ipv6_allocated_expired_flush() {
    let dir = directory(&[]);
    let a = ipv6("2001:db8:1::10");
    let b = ipv6("2001:db8:1::20");
    let mac = [0, 0, 0, 0, 0, 2];

    dir.apply_ipv6_event(ipv6_allocated(mac, vec![(a, IPv6AssignSource::Dhcpv6)], None));
    assert!(dir.entry_by_ipv6(&a).is_some());

    dir.apply_ipv6_event(IPv6AssignEvent::Expired(IPv6AssignInfo {
        iface_name: "lan0".to_string(),
        mac: v4(mac),
        ips: ipv6_addrs(vec![(a, IPv6AssignSource::Dhcpv6)]),
        device_id: None,
    }));
    assert!(dir.entry_by_ipv6(&a).is_none());

    dir.apply_ipv6_event(ipv6_flush(
        mac,
        vec![(a, IPv6AssignSource::Dhcpv6), (b, IPv6AssignSource::Slaac)],
    ));
    let entry = dir.entry_by_ipv6(&b).unwrap();
    assert_eq!(entry.ipv6_addrs.len(), 2);

    // Flush with an empty set wipes the device's addresses.
    dir.apply_ipv6_event(ipv6_flush(mac, vec![]));
    assert!(dir.entry_by_ipv6(&a).is_none());
    assert!(dir.entry_by_ipv6(&b).is_none());
}

#[test]
fn preferred_ipv6_prefers_managed_sources() {
    let dir = directory(&[]);
    let slaac = ipv6("2001:db8:1::1");
    let dhcpv6 = ipv6("2001:db8:1::2");
    let mac = [0, 0, 0, 0, 0, 3];

    dir.apply_ipv6_event(ipv6_allocated(mac, vec![(slaac, IPv6AssignSource::Slaac)], None));
    assert_eq!(dir.entry_by_mac(&v4(mac)).unwrap().preferred_ipv6(), Some(slaac));

    dir.apply_ipv6_event(ipv6_allocated(mac, vec![(dhcpv6, IPv6AssignSource::Dhcpv6)], None));
    assert_eq!(dir.entry_by_mac(&v4(mac)).unwrap().preferred_ipv6(), Some(dhcpv6));
}

#[test]
fn enrolled_suffix_upgrades_address_to_static() {
    let id = Uuid::new_v4();
    let mut device = enrolled(id, [0, 0, 0, 0, 0, 4], None, None);
    device.ipv6 = Some(ipv6("::abcd")); // PD host suffix

    let dir = directory(&[device]);
    let assigned = ipv6("2001:db8:99:1::abcd");

    dir.apply_ipv6_event(ipv6_allocated(
        [0, 0, 0, 0, 0, 4],
        vec![(assigned, IPv6AssignSource::Dhcpv6)],
        Some(id),
    ));
    let entry = dir.entry_by_device_id(&id).unwrap();
    assert_eq!(entry.ipv6_addrs.get(&assigned), Some(&AddressSourceV6::Static));
    assert_eq!(entry.preferred_ipv6(), Some(assigned));
}

// ── multi-anchor / MAC-less ──────────────────────────────────────────

#[test]
fn mac_less_discovery_creates_ip_anchored_entry_then_mac_absorbs() {
    let dir = directory(&[]);
    let ip = ipv4("10.0.0.9");

    // L3 observation without a MAC: anonymous IP-anchored entry.
    dir.apply_discovery_event(discovery(None, IpAddr::V4(ip)));
    let anon = dir.entry_by_ipv4(&ip).unwrap();
    assert_eq!(anon.mac, None);
    assert_eq!(anon.ipv4_source, Some(AddressSourceV4::Arp));

    // A DHCP ACK for the same IP anchors it to the MAC; the address
    // moves and the anonymous entry no longer owns it.
    dir.apply_ipv4_event(ipv4_allocated([0, 0, 0, 0, 0, 8], ip, None, None));
    let entry = dir.entry_by_ipv4(&ip).unwrap();
    assert_eq!(entry.mac, Some(v4([0, 0, 0, 0, 0, 8])));
}

#[test]
fn mac_less_observation_attaches_to_existing_ip_owner() {
    let dir = directory(&[]);
    let ip = ipv4("10.0.0.10");

    dir.apply_ipv4_event(ipv4_allocated([0, 0, 0, 0, 0, 1], ip, None, None));
    dir.apply_discovery_event(discovery(None, IpAddr::V4(ip)));

    // Attached to the existing owner (no duplicate entry created).
    assert_eq!(dir.entries.len(), 1);
}

// ── enrolled device events ───────────────────────────────────────────

#[test]
fn device_deleted_keeps_observations_but_drops_identity() {
    let id = Uuid::new_v4();
    let device = enrolled(id, [0, 0, 0, 0, 0, 5], Some("cam"), Some(ipv4("10.0.0.20")));
    let dir = directory(&[device]);

    dir.apply_ipv6_event(ipv6_allocated(
        [0, 0, 0, 0, 0, 5],
        vec![(ipv6("fd00::5"), IPv6AssignSource::Slaac)],
        Some(id),
    ));

    dir.apply_device_event(EnrolledDeviceEvent::Deleted {
        old: enrolled(id, [0, 0, 0, 0, 0, 5], Some("cam"), Some(ipv4("10.0.0.20"))),
    });

    let entry = dir.entry_by_mac(&v4([0, 0, 0, 0, 0, 5])).unwrap();
    assert_eq!(entry.device_id, None);
    assert_eq!(entry.display_name, None);
    assert!(dir.entry_by_hostname("cam").is_none());
    assert!(dir.entry_by_ipv4(&ipv4("10.0.0.20")).is_none()); // static released
    assert!(dir.entry_by_ipv6(&ipv6("fd00::5")).is_some()); // observation kept
}

// ── GC and snapshot ──────────────────────────────────────────────────

#[test]
fn sweep_removes_idle_anonymous_entries_only() {
    let id = Uuid::new_v4();
    let dir = directory(&[enrolled(id, [0, 0, 0, 0, 0, 6], None, None)]);
    dir.apply_discovery_event(discovery(Some([0, 0, 0, 0, 0, 7]), IpAddr::V4(ipv4("10.0.0.30"))));

    // Age the anonymous entry past the TTL.
    let anon_mac = v4([0, 0, 0, 0, 0, 7]);
    let anon_id = *dir.by_mac.get(&anon_mac).unwrap().value();
    dir.update_entry(&anon_id, |e| e.last_active -= ANONYMOUS_TTL_SECS + 1.0);

    assert!(dir.sweep_expired(get_f64_timestamp()));
    assert!(dir.entry_by_mac(&anon_mac).is_none());
    assert!(dir.entry_by_device_id(&id).is_some()); // enrolled stays
}

#[test]
fn snapshot_reflects_live_tables_after_rebuild() {
    let dir = directory(&[]);
    let ip = ipv4("10.0.0.40");
    dir.apply_ipv4_event(ipv4_allocated([0, 0, 0, 0, 0, 9], ip, Some("tv"), None));
    dir.rebuild_snapshot();

    let snapshot = dir.snapshot();
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.by_hostname.get("tv").unwrap().ipv4, Some(ip));
    assert_eq!(snapshot.by_ipv4.get(&ip).unwrap().hostname.as_deref(), Some("tv"));
    assert!(snapshot.ipv6_sets_by_device_id().is_empty());
}

#[test]
fn is_online_requires_lease_dhcpv6_or_recent_activity() {
    let dir = directory(&[]);
    let mac = [0, 0, 0, 0, 0, 11];

    // SLAAC-only, freshly observed: online via last_active.
    dir.apply_ipv6_event(ipv6_allocated(
        mac,
        vec![(ipv6("fd00::1"), IPv6AssignSource::Slaac)],
        None,
    ));
    assert!(dir.entry_by_mac(&v4(mac)).unwrap().is_online());

    // Stale last_active + SLAAC-only: offline.
    let id = *dir.by_mac.get(&v4(mac)).unwrap().value();
    dir.update_entry(&id, |e| e.last_active -= ONLINE_IDLE_SECS + 1.0);
    assert!(!dir.entry_by_mac(&v4(mac)).unwrap().is_online());

    // A DHCPv6 address alone keeps it online.
    dir.update_entry(&id, |e| {
        e.ipv6_addrs.insert(ipv6("fd00::2"), AddressSourceV6::Dhcpv6);
    });
    assert!(dir.entry_by_mac(&v4(mac)).unwrap().is_online());
}
