use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::rr::{
    RData, Record, RecordType,
    rdata::{A, AAAA},
};
use landscape_common::metric::dns::DnsOutcome;

use crate::domain::ParsedDomain;

use super::zone::{LocalZone, LocalZoneMatch};
use super::{LocalAnswer, LocalResolver};

const HOSTNAME_TTL: u32 = 60;

impl LocalResolver {
    /// Local stage of the forward path.
    pub(super) fn resolve_forward_local(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<LocalAnswer> {
        let tld = domain.tld();

        // (2a) Blocked TLDs → NXDOMAIN
        if is_blocked_tld(tld) {
            return Some(LocalAnswer::Empty { outcome: DnsOutcome::NxDomain });
        }
        // (2b) Localhost → loopback
        if tld == "localhost" {
            let records = Self::lookup_localhost(domain, query_type);
            return Some(LocalAnswer::Answered { records, outcome: DnsOutcome::Local });
        }
        // (2c) Local zone (configured LAN suffix or local.) → device directory
        if let Some(zone) = self.matching_local_zone(domain) {
            return Some(self.resolve_local_domain(domain, zone, query_type));
        }
        None
    }

    fn lookup_localhost(domain: &ParsedDomain, query_type: RecordType) -> Vec<Record> {
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

    fn lookup_lan_hostname(
        &self,
        domain: &ParsedDomain,
        hostname: &str,
        query_type: RecordType,
    ) -> Vec<Record> {
        if !self.is_enabled() || hostname.is_empty() {
            return vec![];
        }
        let Some(entry) = self.directory.entry_by_hostname(hostname) else {
            return vec![];
        };
        let rname = domain.as_dns_name().clone();

        match query_type {
            RecordType::A => entry
                .ipv4
                .map(|ip| Record::from_rdata(rname, HOSTNAME_TTL, RData::A(A(ip))))
                .into_iter()
                .collect(),
            // One AAAA per name: the most managed address wins
            // (`Static > Dhcpv6 > Slaac`).
            RecordType::AAAA => entry
                .preferred_ipv6()
                .map(|ip| Record::from_rdata(rname, HOSTNAME_TTL, RData::AAAA(AAAA(ip))))
                .into_iter()
                .collect(),
            _ => vec![],
        }
    }

    pub(super) fn resolve_local_domain(
        &self,
        domain: &ParsedDomain,
        zone: LocalZoneMatch<'_>,
        query_type: RecordType,
    ) -> LocalAnswer {
        // The zone apex carries no hostname: it is answered locally so a local
        // zone never leaks upstream.
        let Some(hostname) = zone.hostname else {
            let outcome = match zone.zone {
                // `local.` is mDNS territory: staying NOERROR/empty lets a
                // client fall back to multicast instead of caching a failure.
                LocalZone::MdnsLocal => DnsOutcome::Local,
                LocalZone::LanSuffix => DnsOutcome::NxDomain,
            };
            return LocalAnswer::Empty { outcome };
        };

        let records = self.lookup_lan_hostname(domain, hostname, query_type);
        let outcome = if records.is_empty() {
            match zone.zone {
                LocalZone::MdnsLocal => DnsOutcome::Local,
                LocalZone::LanSuffix => DnsOutcome::NxDomain,
            }
        } else {
            DnsOutcome::Local
        };
        LocalAnswer::Answered { records, outcome }
    }
}

/// Special-use TLDs that never resolve.
pub(crate) fn is_blocked_tld(tld: &str) -> bool {
    matches!(tld, "invalid" | "test" | "onion")
}
