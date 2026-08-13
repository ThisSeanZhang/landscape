use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
};

use hickory_proto::rr::{
    rdata::{
        svcb::{Alpn, IpHint, SvcParamKey, SvcParamValue, SVCB},
        A, AAAA, PTR,
    },
    Name, RData, Record, RecordType,
};
use landscape_common::{
    dns::{
        dnr::{encode_unknown_svc_param_value, normalize_advertise_domains, normalize_doh_path_template},
        DohRuntimeConfig,
    },
    metric::dns::DnsOutcome,
};
use landscape_core::lan_hostname::{LanHostnameRegistry, LocalZone, LocalZoneMatch};

use crate::{
    domain::PreprocessedDomain,
    server::{DohAdvertiseProvider, LocalDnsAnswerProvider},
};

const DDR_DISCOVERY_NAME: &str = "_dns.resolver.arpa.";
const DDR_TTL_SECS: u32 = 60;
const HOSTNAME_TTL: u32 = 60;

/// Local answers that never leave the resolver: blocked TLDs, localhost, the
/// configured LAN hostname zone, `local.` (mDNS), reverse PTR for managed
/// addresses, special-use `.arpa` names and DoH Discovery of Resolvers (DDR)
/// records.
#[derive(Clone)]
pub struct LocalResolver {
    lan_hostname_registry: Arc<LanHostnameRegistry>,
    local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
    doh_advertise_provider: Option<Arc<dyn DohAdvertiseProvider>>,
    doh_runtime: Option<DohRuntimeConfig>,
}

impl LocalResolver {
    pub fn new(
        lan_hostname_registry: Arc<LanHostnameRegistry>,
        local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
        doh_advertise_provider: Option<Arc<dyn DohAdvertiseProvider>>,
        doh_runtime: Option<DohRuntimeConfig>,
    ) -> Self {
        Self {
            lan_hostname_registry,
            local_answer_provider,
            doh_advertise_provider,
            doh_runtime,
        }
    }

    /// Local interface addresses shared with the redirect engine
    /// (`AllLocalIps` answer mode) and DDR records (address hints).
    pub fn local_answer_provider(&self) -> Option<&Arc<dyn LocalDnsAnswerProvider>> {
        self.local_answer_provider.as_ref()
    }

    /// Local stage of the forward resolution chain. Returns `None` when the
    /// name is not local and must continue to the cache/upstream stage.
    pub fn resolve_forward_local(
        &self,
        domain: &PreprocessedDomain,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, DnsOutcome)> {
        let tld = domain.tld();

        // (2a) Blocked TLDs → NXDOMAIN
        if is_blocked_tld(tld) {
            return Some((vec![], DnsOutcome::NxDomain));
        }
        // (2b) Localhost → loopback
        if tld == "localhost" {
            let records = Self::lookup_localhost(domain, query_type);
            return Some((records, DnsOutcome::Local));
        }
        // (2c) Local zone (configured LAN suffix or local.) → hostname registry
        if let Some(zone) = self.matching_local_zone(domain) {
            return Some(self.resolve_local_domain(domain, zone, query_type));
        }
        None
    }

    /// Local stage of the `.arpa` chain. Returns `None` only when a reverse
    /// query owns no local answer and must fall through to cache/upstream.
    pub fn resolve_arpa(
        &self,
        domain: &PreprocessedDomain,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, DnsOutcome)> {
        let arpa_suffix = match domain.arpa_prefix() {
            Some(s) => s,
            None => return Some((vec![], DnsOutcome::NxDomain)),
        };
        let label = match domain.arpa_sld() {
            Some(sld) => sld,
            None => return Some((vec![], DnsOutcome::NxDomain)),
        };

        match label {
            // (2) resolver.arpa. → DDR
            "resolver" if arpa_suffix == "resolver" || arpa_suffix == "_dns.resolver" => {
                if query_type == RecordType::SVCB && arpa_suffix == "_dns.resolver" {
                    let records = self.build_ddr_records();
                    return Some((records, DnsOutcome::Local));
                }
                Some((vec![], DnsOutcome::Local))
            }
            // (3) in-addr.arpa. / ip6.arpa. → PTR
            "in-addr" | "ip6" => {
                // `parse_arpa_name` requires an FQDN, so parse `domain.raw()` (with trailing dot).
                let Ok(dns_name) = Name::from_str(domain.raw()) else {
                    return Some((vec![], DnsOutcome::NxDomain));
                };
                let Ok(net) = dns_name.parse_arpa_name() else {
                    return Some((vec![], DnsOutcome::NxDomain));
                };
                let addr = net.addr();
                self.resolve_ptr_by_addr(&addr, domain)
            }
            // (4) ipv4only.arpa. → NODATA (special-use domain, RFC 8880)
            "ipv4only" if arpa_suffix == "ipv4only" => Some((vec![], DnsOutcome::Local)),
            // (5) Remaining .arpa names belong to the configured LAN zone only
            // when the complete suffix matches (for example, `home.arpa`).
            _ => match self.matching_local_zone(domain) {
                Some(zone) => Some(self.resolve_local_domain(domain, zone, query_type)),
                None => Some((vec![], DnsOutcome::NxDomain)),
            },
        }
    }

    /// Matches a name against the live LAN-hostname config or the mDNS `.local`
    /// zone. Keeping this decision in one place makes normal
    /// queries, `.arpa` queries, config checks, and cache refreshes agree after
    /// a runtime config change.
    pub fn matching_local_zone<'a>(
        &self,
        domain: &'a PreprocessedDomain,
    ) -> Option<LocalZoneMatch<'a>> {
        let mut zone = self.lan_hostname_registry.match_local_zone(domain.name())?;

        // `.local` remains mDNS territory even if a legacy or hand-edited
        // config incorrectly chooses `local` as the LAN suffix.
        if domain.tld() == "local" {
            zone.zone = LocalZone::MdnsLocal;
        }

        Some(zone)
    }

    pub fn lookup_localhost(domain: &PreprocessedDomain, query_type: RecordType) -> Vec<Record> {
        let rname = domain.as_dns_name().clone();

        match query_type {
            RecordType::A => {
                let record =
                    Record::from_rdata(rname, HOSTNAME_TTL, RData::A(A(Ipv4Addr::LOCALHOST)));
                vec![record]
            }
            RecordType::AAAA => {
                let record =
                    Record::from_rdata(rname, HOSTNAME_TTL, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)));
                vec![record]
            }
            _ => vec![],
        }
    }

    pub fn lookup_lan_hostname(
        &self,
        domain: &PreprocessedDomain,
        hostname: &str,
        query_type: RecordType,
    ) -> Vec<Record> {
        let rname = domain.as_dns_name().clone();

        match query_type {
            RecordType::A => {
                if let Some(ip) = self.lan_hostname_registry.resolve_a_by_hostname(hostname) {
                    let rdata = RData::A(A(ip));
                    let record = Record::from_rdata(rname, HOSTNAME_TTL, rdata);
                    vec![record]
                } else {
                    vec![]
                }
            }
            RecordType::AAAA => {
                if let Some(ip) = self.lan_hostname_registry.resolve_aaaa_by_hostname(hostname) {
                    let rdata = RData::AAAA(AAAA(ip));
                    let record = Record::from_rdata(rname, HOSTNAME_TTL, rdata);
                    vec![record]
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }

    /// Reverse PTR answer for managed addresses. `None` means the address is
    /// not owned locally and the query must continue to the cache/upstream
    /// stage.
    fn resolve_ptr_by_addr(
        &self,
        addr: &IpAddr,
        domain: &PreprocessedDomain,
    ) -> Option<(Vec<Record>, DnsOutcome)> {
        const PTR_TTL: u32 = 60;

        if !LanHostnameRegistry::is_managed_ptr_addr(addr) {
            return None;
        }

        // localhost PTR is owned by the resolver, not the device registry.
        if addr.is_loopback() {
            let Ok(target) = Name::from_utf8("localhost.") else {
                return Some((vec![], DnsOutcome::Error));
            };
            let record =
                Record::from_rdata(domain.as_dns_name().clone(), PTR_TTL, RData::PTR(PTR(target)));
            return Some((vec![record], DnsOutcome::Local));
        }

        if !self.lan_hostname_registry.is_enabled() {
            return None;
        }

        match self.lan_hostname_registry.resolve_ptr_by_addr(addr) {
            Some(fqdn) => {
                let Ok(target) = Name::from_utf8(&fqdn) else {
                    return Some((vec![], DnsOutcome::Error));
                };
                let rdata = RData::PTR(PTR(target));
                let record = Record::from_rdata(domain.as_dns_name().clone(), PTR_TTL, rdata);
                Some((vec![record], DnsOutcome::Local))
            }
            None => Some((vec![], DnsOutcome::NxDomain)),
        }
    }

    fn resolve_local_domain(
        &self,
        domain: &PreprocessedDomain,
        zone: LocalZoneMatch<'_>,
        query_type: RecordType,
    ) -> (Vec<Record>, DnsOutcome) {
        // The zone apex carries no hostname, and neither does an unknown host:
        // both are answered locally so a local zone never leaks upstream.
        let records = match zone.hostname {
            Some(hostname) => self.lookup_lan_hostname(domain, hostname, query_type),
            None => vec![],
        };
        let outcome = if records.is_empty() {
            match zone.zone {
                // `local.` is mDNS territory: staying NOERROR/empty lets a
                // client fall back to multicast instead of caching a failure.
                LocalZone::MdnsLocal => DnsOutcome::Local,
                LocalZone::LanSuffix => DnsOutcome::NxDomain,
            }
        } else {
            DnsOutcome::Local
        };
        (records, outcome)
    }

    /// DoH Discovery of Resolvers (DDR) SVCB records for the
    /// `_dns.resolver.arpa.` name.
    pub fn build_ddr_records(&self) -> Vec<Record> {
        let Some(doh_runtime) = self.doh_runtime.as_ref() else {
            return Vec::new();
        };
        let Some(provider) = self.doh_advertise_provider.as_ref() else {
            return Vec::new();
        };
        let domains = normalize_advertise_domains(provider.advertise_domains());
        if domains.is_empty() {
            return Vec::new();
        }

        build_ddr_records(
            &domains,
            doh_runtime.listen_port,
            &doh_runtime.http_endpoint,
            self.local_answer_provider.as_deref(),
        )
    }
}

/// Special-use TLDs that never resolve.
pub(crate) fn is_blocked_tld(tld: &str) -> bool {
    matches!(tld, "invalid" | "test" | "onion")
}

fn build_ddr_records(
    domains: &[String],
    port: u16,
    doh_path: &str,
    local_answer_provider: Option<&dyn LocalDnsAnswerProvider>,
) -> Vec<Record> {
    let Ok(owner) = Name::from_str(DDR_DISCOVERY_NAME) else {
        return Vec::new();
    };
    let Some(doh_path) = normalize_doh_path_template(doh_path) else {
        return Vec::new();
    };
    let ipv4_hints = load_ipv4_hints(local_answer_provider);
    let ipv6_hints = load_ipv6_hints(local_answer_provider);

    domains
        .iter()
        .filter_map(|domain| {
            let target = Name::from_str(&format!("{}.", domain)).ok()?;
            let mut params =
                vec![(SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])))];
            params.push((SvcParamKey::Port, SvcParamValue::Port(port)));
            if !ipv4_hints.is_empty() {
                params.push((
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(ipv4_hints.clone())),
                ));
            }
            if !ipv6_hints.is_empty() {
                params.push((
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(ipv6_hints.clone())),
                ));
            }
            params.push((
                SvcParamKey::Unknown(7),
                SvcParamValue::Unknown(encode_unknown_svc_param_value(doh_path.as_bytes())),
            ));
            Some(Record::from_rdata(
                owner.clone(),
                DDR_TTL_SECS,
                RData::SVCB(SVCB::new(1, target, params)),
            ))
        })
        .collect()
}

fn load_ipv4_hints(provider: Option<&dyn LocalDnsAnswerProvider>) -> Vec<A> {
    provider
        .map(|provider| provider.load_local_answer_addrs(RecordType::A))
        .unwrap_or_default()
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(ip) => Some(A(*ip)),
            _ => None,
        })
        .collect()
}

fn load_ipv6_hints(provider: Option<&dyn LocalDnsAnswerProvider>) -> Vec<AAAA> {
    provider
        .map(|provider| provider.load_local_answer_addrs(RecordType::AAAA))
        .unwrap_or_default()
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V6(ip) => Some(AAAA(*ip)),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::serialize::binary::BinEncodable;
    use landscape_common::{
        event::hub::{EnrolledDeviceEventReader, IPv4AssignEventReader},
        sys_service::lan_hostname::LanHostnameConfig,
    };

    use super::*;

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

    fn registry(
        enable: bool,
        lan_suffix: &str,
        devices: Vec<(String, Ipv4Addr)>,
    ) -> Arc<LanHostnameRegistry> {
        LanHostnameRegistry::new(
            LanHostnameConfig { enable, lan_suffix: lan_suffix.to_string() },
            devices,
            {
                let (_tx, rx) = tokio::sync::broadcast::channel(8);
                IPv4AssignEventReader::new(rx)
            },
            {
                let (_tx, rx) = tokio::sync::broadcast::channel(8);
                EnrolledDeviceEventReader::new(rx)
            },
        )
    }

    fn make_resolver(reg: Arc<LanHostnameRegistry>) -> LocalResolver {
        LocalResolver::new(reg, None, None, None)
    }

    fn pd(name: &str) -> PreprocessedDomain {
        PreprocessedDomain::new(name).unwrap()
    }

    #[tokio::test]
    async fn resolve_forward_local_handles_blocked_localhost_and_zone() {
        let reg = registry(true, "lan", vec![("dev".to_string(), Ipv4Addr::new(10, 0, 0, 2))]);
        let resolver = make_resolver(reg);

        let (records, outcome) =
            resolver.resolve_forward_local(&pd("example.invalid."), RecordType::A).unwrap();
        assert!(records.is_empty());
        assert_eq!(outcome, DnsOutcome::NxDomain);

        let (records, outcome) =
            resolver.resolve_forward_local(&pd("localhost."), RecordType::A).unwrap();
        assert_eq!(outcome, DnsOutcome::Local);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, RData::A(A(Ipv4Addr::LOCALHOST)));

        let (records, outcome) =
            resolver.resolve_forward_local(&pd("dev.lan."), RecordType::A).unwrap();
        assert_eq!(outcome, DnsOutcome::Local);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, RData::A(A(Ipv4Addr::new(10, 0, 0, 2))));

        // Zone apex has no hostname: answered locally with NXDOMAIN.
        let (records, outcome) =
            resolver.resolve_forward_local(&pd("lan."), RecordType::A).unwrap();
        assert!(records.is_empty());
        assert_eq!(outcome, DnsOutcome::NxDomain);

        // Unknown `.local` host stays NOERROR/empty so mDNS can take over.
        let (records, outcome) =
            resolver.resolve_forward_local(&pd("unknown.local."), RecordType::A).unwrap();
        assert!(records.is_empty());
        assert_eq!(outcome, DnsOutcome::Local);

        assert!(resolver.resolve_forward_local(&pd("example.com."), RecordType::A).is_none());
    }

    #[tokio::test]
    async fn resolve_arpa_dispatches_locally() {
        let reg = registry(true, "lan", vec![("dev".to_string(), Ipv4Addr::new(10, 0, 0, 2))]);
        let resolver = make_resolver(reg);

        let (records, outcome) =
            resolver.resolve_arpa(&pd("resolver.arpa."), RecordType::A).unwrap();
        assert!(records.is_empty());
        assert_eq!(outcome, DnsOutcome::Local);

        // DDR without a DoH endpoint configured: no records, still local.
        let (records, outcome) =
            resolver.resolve_arpa(&pd("_dns.resolver.arpa."), RecordType::SVCB).unwrap();
        assert!(records.is_empty());
        assert_eq!(outcome, DnsOutcome::Local);

        let (records, outcome) =
            resolver.resolve_arpa(&pd("ipv4only.arpa."), RecordType::A).unwrap();
        assert!(records.is_empty());
        assert_eq!(outcome, DnsOutcome::Local);

        // Not the configured zone suffix.
        let (records, outcome) =
            resolver.resolve_arpa(&pd("home.arpa."), RecordType::A).unwrap();
        assert!(records.is_empty());
        assert_eq!(outcome, DnsOutcome::NxDomain);

        // Managed address without a registered hostname: NXDOMAIN answer.
        let (records, outcome) =
            resolver.resolve_arpa(&pd("1.0.0.10.in-addr.arpa."), RecordType::PTR).unwrap();
        assert!(records.is_empty());
        assert_eq!(outcome, DnsOutcome::NxDomain);

        // Unmanaged address: falls through to the cache/upstream stage.
        assert!(resolver.resolve_arpa(&pd("8.8.8.8.in-addr.arpa."), RecordType::PTR).is_none());

        // LAN zone under `.arpa` when the full suffix matches.
        let reg = registry(true, "home.arpa", vec![("nas".to_string(), Ipv4Addr::new(10, 0, 0, 3))]);
        let resolver = make_resolver(reg);
        let (records, outcome) =
            resolver.resolve_arpa(&pd("nas.home.arpa."), RecordType::A).unwrap();
        assert_eq!(outcome, DnsOutcome::Local);
        assert_eq!(records.len(), 1);
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
}
