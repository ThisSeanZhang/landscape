use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arc_swap::ArcSwap;
use hickory_proto::serialize::binary::BinEncodable;
use landscape_common::{
    event::hub::{IPv6AssignEvent, Ipv6AssignAddress},
    net::MacAddr,
    sys_service::lan_hostname::LanHostnameConfig,
};
use landscape_core::lan_device::DirectorySeedDevice;

use super::arpa::is_managed_ptr_addr;
use super::ddr::build_ddr_records;
use super::forward::is_blocked_tld;
use super::zone::LocalZone;
use super::*;
use hickory_proto::rr::{RData, RecordType, rdata::A};

struct MockLocalAnswerProvider {
    addrs: Vec<IpAddr>,
}

impl LocalDnsAnswerProvider for MockLocalAnswerProvider {
    fn load_local_answer_addrs(&self, query_type: RecordType) -> Arc<Vec<IpAddr>> {
        let addrs = self
            .addrs
            .iter()
            .copied()
            .filter(|addr| {
                matches!(
                    (addr, query_type),
                    (IpAddr::V4(_), RecordType::A) | (IpAddr::V6(_), RecordType::AAAA)
                )
            })
            .collect();
        Arc::new(addrs)
    }
}

fn seed(mac: [u8; 6], hostname: Option<&str>, ipv4: Option<Ipv4Addr>) -> DirectorySeedDevice {
    DirectorySeedDevice {
        mac: MacAddr(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
        hostname: hostname.map(str::to_string),
        ipv4,
        ipv6: None,
    }
}

fn hostname_config(enable: bool, lan_suffix: &str) -> Arc<ArcSwap<LanHostnameConfig>> {
    Arc::new(ArcSwap::from_pointee(LanHostnameConfig {
        enable,
        lan_suffix: lan_suffix.to_string(),
    }))
}

fn directory(devices: Vec<DirectorySeedDevice>) -> Arc<LanDeviceDirectory> {
    LanDeviceDirectory::new_seeded_for_test(devices)
}

fn v6_allocated(mac: [u8; 6], addrs: Vec<(Ipv6Addr, bool)>) -> IPv6AssignEvent {
    IPv6AssignEvent::Allocated(landscape_common::event::hub::IPv6AssignInfo {
        iface_name: "eth0".to_string(),
        mac: MacAddr(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
        ips: addrs
            .into_iter()
            .map(
                |(ip, dhcpv6)| {
                    if dhcpv6 {
                        Ipv6AssignAddress::dhcpv6(ip)
                    } else {
                        Ipv6AssignAddress::slaac(ip)
                    }
                },
            )
            .collect(),
        device_id: None,
    })
}

fn make_resolver(
    directory: Arc<LanDeviceDirectory>,
    config: Arc<ArcSwap<LanHostnameConfig>>,
) -> LocalResolver {
    LocalResolver::new(directory, config, None, None, None)
}

fn pd(name: &str) -> ParsedDomain {
    ParsedDomain::new(name).unwrap()
}

#[tokio::test]
async fn resolve_local_handles_blocked_localhost_and_zone() {
    let dev = seed([0, 0, 0, 0, 0, 2], Some("dev"), Some(Ipv4Addr::new(10, 0, 0, 2)));
    let resolver = make_resolver(directory(vec![dev]), hostname_config(true, "lan"));

    for domain in ["example.invalid.", "somewhere.onion.", "bar.test."] {
        assert!(matches!(
            resolver.resolve_local(&pd(domain), RecordType::A),
            Some(LocalAnswer::Empty { outcome: DnsOutcome::NxDomain })
        ));
    }

    match resolver.resolve_local(&pd("localhost."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].data, RData::A(A(Ipv4Addr::LOCALHOST)));
        }
        LocalAnswer::Empty { .. } => panic!("localhost must be answered"),
    }

    match resolver.resolve_local(&pd("dev.lan."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].data, RData::A(A(Ipv4Addr::new(10, 0, 0, 2))));
        }
        LocalAnswer::Empty { .. } => panic!("zone host must be answered"),
    }

    // Zone apex has no hostname: answered locally with NXDOMAIN.
    assert!(matches!(
        resolver.resolve_local(&pd("lan."), RecordType::A),
        Some(LocalAnswer::Empty { outcome: DnsOutcome::NxDomain })
    ));

    // Unknown `.local` host stays NOERROR/empty so mDNS can take over.
    match resolver.resolve_local(&pd("unknown.local."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::Local);
        }
        LocalAnswer::Empty { .. } => panic!("unknown `.local` host must be answered"),
    }

    assert!(resolver.resolve_local(&pd("example.com."), RecordType::A).is_none());
}

#[tokio::test]
async fn resolve_local_dispatches_arpa_locally() {
    let dev = seed([0, 0, 0, 0, 0, 2], Some("dev"), Some(Ipv4Addr::new(10, 0, 0, 2)));
    let resolver = make_resolver(directory(vec![dev]), hostname_config(true, "lan"));

    match resolver.resolve_local(&pd("resolver.arpa."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::Local);
        }
        LocalAnswer::Empty { .. } => panic!("resolver.arpa. must be answered"),
    }

    // DDR without a DoH endpoint configured: no records, still local.
    match resolver.resolve_local(&pd("_dns.resolver.arpa."), RecordType::SVCB).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::Local);
        }
        LocalAnswer::Empty { .. } => panic!("_dns.resolver.arpa. must be answered"),
    }

    match resolver.resolve_local(&pd("ipv4only.arpa."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::Local);
        }
        LocalAnswer::Empty { .. } => panic!("ipv4only.arpa. must be answered"),
    }

    match resolver.resolve_local(&pd("ipv6only.arpa."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::Local);
        }
        LocalAnswer::Empty { .. } => panic!("ipv6only.arpa. must be answered"),
    }

    // Not the configured zone suffix.
    match resolver.resolve_local(&pd("home.arpa."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::NxDomain);
        }
        LocalAnswer::Empty { .. } => panic!("unmatched `.arpa` must be answered"),
    }

    // Managed address without a registered hostname: NXDOMAIN answer.
    match resolver.resolve_local(&pd("1.0.0.10.in-addr.arpa."), RecordType::PTR).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::NxDomain);
        }
        LocalAnswer::Empty { .. } => panic!("managed PTR must be answered"),
    }

    // Unmanaged address: falls through to the cache/upstream stage.
    assert!(resolver.resolve_local(&pd("8.8.8.8.in-addr.arpa."), RecordType::PTR).is_none());

    // LAN zone under `.arpa` when the full suffix matches.
    let nas = seed([0, 0, 0, 0, 0, 3], Some("nas"), Some(Ipv4Addr::new(10, 0, 0, 3)));
    let resolver = make_resolver(directory(vec![nas]), hostname_config(true, "home.arpa"));
    match resolver.resolve_local(&pd("nas.home.arpa."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
        }
        LocalAnswer::Empty { .. } => panic!("zone host under `.arpa` must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_handles_idn_at_lan_suffix_byte_offset() {
    // Before ParsedDomain canonicalization, subtracting the three-byte
    // "lan" suffix put byte offset 19 inside this character (bytes 17..20).
    let input = "aaaaaaaaaaaaaaaaa载.x.";
    let domain = pd(input);
    assert!(domain.name().is_ascii());

    let resolver = make_resolver(directory(vec![]), hostname_config(true, "lan"));
    assert!(resolver.resolve_local(&domain, RecordType::A).is_none());
}

fn arpa_name_from_ipv6(addr: Ipv6Addr) -> String {
    let octets = addr.octets();
    let nibbles: Vec<String> = octets
        .iter()
        .rev()
        .flat_map(|b| [format!("{:x}", b & 0x0f), format!("{:x}", b >> 4)])
        .collect();
    format!("{}.ip6.arpa.", nibbles.join("."))
}

#[tokio::test]
async fn resolve_local_ptr_returns_registered_lan_hostname() {
    let nas = seed([0, 0, 0, 0, 0, 50], Some("nas"), Some(Ipv4Addr::new(192, 168, 1, 50)));
    let resolver = make_resolver(directory(vec![nas]), hostname_config(true, "lan"));

    match resolver.resolve_local(&pd("50.1.168.192.in-addr.arpa."), RecordType::PTR).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
            match &records[0].data {
                RData::PTR(ptr) => assert_eq!(ptr.0.to_string(), "nas.lan."),
                other => panic!("expected PTR record, got {:?}", other),
            }
        }
        LocalAnswer::Empty { .. } => panic!("registered PTR must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_ptr_returns_hostname_only_when_suffix_empty() {
    let dev = seed([0, 0, 0, 0, 0, 5], Some("dev"), Some(Ipv4Addr::new(10, 0, 0, 5)));
    let resolver = make_resolver(directory(vec![dev]), hostname_config(true, ""));

    match resolver.resolve_local(&pd("5.0.0.10.in-addr.arpa."), RecordType::PTR).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            match &records[0].data {
                RData::PTR(ptr) => assert_eq!(ptr.0.to_string(), "dev."),
                other => panic!("expected PTR record, got {:?}", other),
            }
        }
        LocalAnswer::Empty { .. } => panic!("registered PTR must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_ptr_ipv6_returns_registered_lan_hostname() {
    let ipv6 = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 99);
    let mac = [0, 0, 0, 0, 0, 1];
    let dir = directory(vec![seed(mac, Some("srv"), Some(Ipv4Addr::new(192, 168, 1, 1)))]);
    dir.apply_ipv6_event_for_test(v6_allocated(mac, vec![(ipv6, true)]));
    let resolver = make_resolver(dir, hostname_config(true, "lan"));

    let arpa_name = arpa_name_from_ipv6(ipv6);
    match resolver.resolve_local(&pd(&arpa_name), RecordType::PTR).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
            match &records[0].data {
                RData::PTR(ptr) => assert_eq!(ptr.0.to_string(), "srv.lan."),
                other => panic!("expected PTR record, got {:?}", other),
            }
        }
        LocalAnswer::Empty { .. } => panic!("registered IPv6 PTR must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_ptr_returns_none_when_ipv6_not_matched() {
    let mac = [0, 0, 0, 0, 0, 1];
    let dir = directory(vec![seed(mac, Some("srv"), Some(Ipv4Addr::new(10, 0, 0, 10)))]);
    dir.apply_ipv6_event_for_test(v6_allocated(
        mac,
        vec![(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), false)],
    ));
    let resolver = make_resolver(dir, hostname_config(true, "lan"));

    let other = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 99);
    match resolver.resolve_local(&pd(&arpa_name_from_ipv6(other)), RecordType::PTR).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::NxDomain);
        }
        LocalAnswer::Empty { .. } => panic!("managed IPv6 PTR must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_aaaa_returns_registered_ipv6() {
    let ipv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let mac = [0, 0, 0, 0, 0, 100];
    let dir = directory(vec![seed(mac, Some("dev"), Some(Ipv4Addr::new(192, 168, 1, 100)))]);
    dir.apply_ipv6_event_for_test(v6_allocated(mac, vec![(ipv6, false)]));
    let resolver = make_resolver(dir, hostname_config(true, "lan"));

    match resolver.resolve_local(&pd("dev.lan."), RecordType::AAAA).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
            match &records[0].data {
                RData::AAAA(aaaa) => assert_eq!(aaaa.0, ipv6),
                other => panic!("expected AAAA record, got {:?}", other),
            }
        }
        LocalAnswer::Empty { .. } => panic!("zone host must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_aaaa_prefers_dhcpv6_over_slaac() {
    let slaac = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let dhcpv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let mac = [0, 0, 0, 0, 0, 101];
    let dir = directory(vec![seed(mac, Some("dev"), Some(Ipv4Addr::new(10, 0, 0, 2)))]);
    dir.apply_ipv6_event_for_test(v6_allocated(mac, vec![(slaac, false), (dhcpv6, true)]));
    let resolver = make_resolver(dir, hostname_config(true, "lan"));

    match resolver.resolve_local(&pd("dev.lan."), RecordType::AAAA).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            match &records[0].data {
                RData::AAAA(aaaa) => assert_eq!(aaaa.0, dhcpv6),
                other => panic!("expected AAAA record, got {:?}", other),
            }
        }
        LocalAnswer::Empty { .. } => panic!("zone host must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_aaaa_returns_nxdomain_when_no_ipv6() {
    let dev = seed([0, 0, 0, 0, 0, 100], Some("dev"), Some(Ipv4Addr::new(192, 168, 1, 100)));
    let resolver = make_resolver(directory(vec![dev]), hostname_config(true, "lan"));

    match resolver.resolve_local(&pd("dev.lan."), RecordType::AAAA).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::NxDomain);
        }
        LocalAnswer::Empty { .. } => panic!("zone host must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_multi_label_suffix_resolves_host() {
    let ip = Ipv4Addr::new(192, 168, 1, 60);
    let nas = seed([0, 0, 0, 0, 0, 60], Some("nas"), Some(ip));
    let resolver = make_resolver(directory(vec![nas]), hostname_config(true, "home.lan"));

    match resolver.resolve_local(&pd("nas.home.lan."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
            match &records[0].data {
                RData::A(a) => assert_eq!(a.0, ip),
                other => panic!("expected A record, got {:?}", other),
            }
        }
        LocalAnswer::Empty { .. } => panic!("zone host must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_multi_label_suffix_does_not_match_last_label_only() {
    let ip = Ipv4Addr::new(192, 168, 1, 61);
    let nas = seed([0, 0, 0, 0, 0, 61], Some("nas"), Some(ip));
    let resolver = make_resolver(directory(vec![nas]), hostname_config(true, "home.lan"));

    // `nas.lan` is outside the `home.lan` zone, so it must not be
    // answered from the directory.
    assert!(resolver.resolve_local(&pd("nas.lan."), RecordType::A).is_none());
}

#[tokio::test]
async fn resolve_local_arpa_multi_label_suffix_resolves_host() {
    let ip = Ipv4Addr::new(192, 168, 1, 62);
    let nas = seed([0, 0, 0, 0, 0, 62], Some("nas"), Some(ip));
    let resolver = make_resolver(directory(vec![nas]), hostname_config(true, "mylan.arpa"));

    // `.arpa` names used to answer NXDOMAIN for every suffix except the
    // hardcoded `home`.
    match resolver.resolve_local(&pd("nas.mylan.arpa."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
            match &records[0].data {
                RData::A(a) => assert_eq!(a.0, ip),
                other => panic!("expected A record, got {:?}", other),
            }
        }
        LocalAnswer::Empty { .. } => panic!("zone host under `.arpa` must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_home_arpa_suffix_resolves_only_when_enabled() {
    let ip = Ipv4Addr::new(192, 168, 1, 63);
    let nas = seed([0, 0, 0, 0, 0, 63], Some("nas"), Some(ip));
    let domain = pd("nas.home.arpa.");

    let enabled = make_resolver(directory(vec![nas.clone()]), hostname_config(true, "home.arpa"));
    match enabled.resolve_local(&domain, RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
            assert!(matches!(&records[0].data, RData::A(a) if a.0 == ip));
        }
        LocalAnswer::Empty { .. } => panic!("zone host under `.arpa` must be answered"),
    }

    let disabled = make_resolver(directory(vec![nas]), hostname_config(false, "home.arpa"));
    match disabled.resolve_local(&domain, RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::NxDomain);
        }
        LocalAnswer::Empty { .. } => panic!("`.arpa` names must be answered"),
    }
}

#[tokio::test]
async fn resolve_local_loopback_ptr_returns_localhost() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, "lan"));

    match resolver.resolve_local(&pd("1.0.0.127.in-addr.arpa."), RecordType::PTR).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
            match &records[0].data {
                RData::PTR(ptr) => assert_eq!(ptr.0.to_string(), "localhost."),
                other => panic!("expected PTR record, got {:?}", other),
            }
        }
        LocalAnswer::Empty { .. } => panic!("loopback PTR must be answered"),
    }
}

#[tokio::test]
async fn forward_lookup_has_no_builtin_localhost() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, "lan"));

    // `localhost.lan` falls into the LAN zone; the directory knows no
    // such device, so the answer is negative rather than a builtin
    // loopback record.
    match resolver.resolve_local(&pd("localhost.lan."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, outcome } => {
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::NxDomain);
        }
        LocalAnswer::Empty { .. } => panic!("LAN zone host must be answered"),
    }
}

// --- match_local_zone ---

#[test]
fn match_local_zone_matches_configured_suffix() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, "lan"));
    let m = resolver.match_local_zone("nas.lan").unwrap();
    assert_eq!(m.zone, LocalZone::LanSuffix);
    assert_eq!(m.hostname, Some("nas"));
}

#[test]
fn match_local_zone_matches_multi_label_suffix() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, "home.arpa"));
    let m = resolver.match_local_zone("nas.home.arpa").unwrap();
    assert_eq!(m.zone, LocalZone::LanSuffix);
    assert_eq!(m.hostname, Some("nas"));
}

#[test]
fn match_local_zone_keeps_sub_labels_in_hostname() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, "lan"));
    assert_eq!(resolver.match_local_zone("a.b.lan").unwrap().hostname, Some("a.b"));
}

#[test]
fn match_local_zone_reports_apex_without_hostname() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, "lan"));
    let m = resolver.match_local_zone("lan").unwrap();
    assert_eq!(m.zone, LocalZone::LanSuffix);
    assert_eq!(m.hostname, None);
}

#[test]
fn match_local_zone_always_matches_mdns_local() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, ""));
    let m = resolver.match_local_zone("printer.local").unwrap();
    assert_eq!(m.zone, LocalZone::MdnsLocal);
    assert_eq!(m.hostname, Some("printer"));

    let resolver2 = make_resolver(directory(vec![]), hostname_config(true, "home.arpa"));
    assert_eq!(resolver2.match_local_zone("printer.local").unwrap().zone, LocalZone::MdnsLocal);
}

#[test]
fn match_local_zone_is_case_insensitive() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, "lan"));
    assert_eq!(resolver.match_local_zone("NAS.LAN").unwrap().hostname, Some("NAS"));
}

#[test]
fn match_local_zone_rejects_unrelated_names() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, "lan"));
    assert!(resolver.match_local_zone("example.com").is_none());
    assert!(resolver.match_local_zone("notlan").is_none());
    assert!(resolver.match_local_zone("host.mylan").is_none());
}

#[test]
fn match_local_zone_ignores_empty_suffix() {
    let resolver = make_resolver(directory(vec![]), hostname_config(true, ""));
    assert!(resolver.match_local_zone("").is_none());
    assert!(resolver.match_local_zone("nas.lan").is_none());
}

// --- is_managed_ptr_addr ---

#[test]
fn managed_ptr_addr_accepts_private_ipv4() {
    assert!(is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    assert!(is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
}

#[test]
fn managed_ptr_addr_accepts_loopback_and_link_local() {
    assert!(is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
    assert!(is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
}

#[test]
fn managed_ptr_addr_accepts_unique_local_ipv6() {
    assert!(is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))));
    assert!(is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
}

#[test]
fn managed_ptr_addr_accepts_shared_cgn_ipv4() {
    assert!(is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    assert!(is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));
}

#[test]
fn managed_ptr_addr_accepts_unspecified_and_broadcast() {
    assert!(is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    assert!(is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::BROADCAST)));
    assert!(is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
}

#[test]
fn managed_ptr_addr_rejects_public_ipv4() {
    assert!(!is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    assert!(!is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert!(!is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
}

#[test]
fn managed_ptr_addr_rejects_global_unicast_ipv6() {
    assert!(!is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    assert!(!is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1))));
}

// --- runtime config changes ---

#[tokio::test]
async fn config_update_applies_suffix_without_touching_directory() {
    let ip = Ipv4Addr::new(192, 168, 1, 10);
    let nas = seed([0, 0, 0, 0, 0, 10], Some("nas"), Some(ip));
    let dir = directory(vec![nas]);
    let config = hostname_config(true, "lan");
    let resolver = make_resolver(dir.clone(), config.clone());

    config.store(Arc::new(LanHostnameConfig { enable: true, lan_suffix: "home".to_string() }));

    assert!(resolver.match_local_zone("nas.lan").is_none());
    assert!(resolver.match_local_zone("nas.home").is_some());
    match resolver.resolve_local(&pd("nas.home."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, .. } => {
            assert!(matches!(&records[0].data, RData::A(a) if a.0 == ip));
        }
        LocalAnswer::Empty { .. } => panic!("zone host must be answered"),
    }
    match resolver.resolve_local(&pd("10.1.168.192.in-addr.arpa."), RecordType::PTR).unwrap() {
        LocalAnswer::Answered { records, .. } => {
            assert!(
                matches!(&records[0].data, RData::PTR(ptr) if ptr.0.to_string() == "nas.home.")
            );
        }
        LocalAnswer::Empty { .. } => panic!("registered PTR must be answered"),
    }
}

#[tokio::test]
async fn disabled_config_stops_resolution_without_touching_directory() {
    let ip = Ipv4Addr::new(192, 168, 1, 10);
    let nas = seed([0, 0, 0, 0, 0, 11], Some("nas"), Some(ip));
    let dir = directory(vec![nas]);
    let config = hostname_config(true, "lan");
    let resolver = make_resolver(dir.clone(), config.clone());

    config.store(Arc::new(LanHostnameConfig { enable: false, lan_suffix: "lan".to_string() }));

    assert!(resolver.match_local_zone("nas.lan").is_none());
    assert!(resolver.match_local_zone("nas.local").is_some());
    assert!(resolver.resolve_local(&pd("nas.lan."), RecordType::A).is_none());
    // Disabled config does not own managed PTR: falls through upstream.
    assert!(resolver.resolve_local(&pd("10.1.168.192.in-addr.arpa."), RecordType::PTR).is_none());

    config.store(Arc::new(LanHostnameConfig { enable: true, lan_suffix: "lan".to_string() }));
    match resolver.resolve_local(&pd("nas.lan."), RecordType::A).unwrap() {
        LocalAnswer::Answered { records, .. } => {
            assert!(matches!(&records[0].data, RData::A(a) if a.0 == ip));
        }
        LocalAnswer::Empty { .. } => panic!("zone host must be answered"),
    }
}

#[test]
fn build_ddr_records_encodes_svc_params_in_increasing_order() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 5, 1)), IpAddr::V6(Ipv6Addr::LOCALHOST)],
    };
    let records =
        build_ddr_records(&["api.example.com".to_string()], 443, "/dns-query", Some(&provider));

    assert_eq!(records.len(), 1);
    let svcb = match &records[0].data {
        RData::SVCB(svcb) => svcb.clone(),
        _ => panic!("expected SVCB record"),
    };

    let keys = svcb.svc_params.iter().map(|(key, _)| u16::from(*key)).collect::<Vec<_>>();
    assert_eq!(keys, vec![1, 3, 4, 6, 7]);

    let mut wire = Vec::new();
    let mut encoder = hickory_proto::serialize::binary::BinEncoder::new(&mut wire);
    svcb.emit(&mut encoder).expect("SVCB should encode successfully");
    assert!(wire.windows(b"/dns-query{?dns}".len()).any(|w| w == b"/dns-query{?dns}"));
}

#[test]
fn is_blocked_tld_matches_special_use_tlds() {
    assert!(is_blocked_tld("invalid"));
    assert!(is_blocked_tld("test"));
    assert!(is_blocked_tld("onion"));
    assert!(!is_blocked_tld("com"));
}
