use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::PTR};
use landscape_common::metric::dns::DnsOutcome;

use crate::domain::ParsedDomain;

use super::{LocalAnswer, LocalResolver};

/// Reverse queries for these addresses are owned by the local resolver.
pub(super) fn is_managed_ptr_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || is_shared_ipv4(*ip)
                || ip.is_unspecified()
                || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            ip.is_unique_local()
                || ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
        }
    }
}

fn is_shared_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

impl LocalResolver {
    /// Local stage of the `.arpa` path. Returns `None` only when a reverse
    /// query owns no local answer and must fall through to cache/upstream.
    pub(super) fn resolve_arpa(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<LocalAnswer> {
        let arpa_suffix = match domain.arpa_prefix() {
            Some(s) => s,
            None => {
                return Some(LocalAnswer::Answered {
                    records: vec![],
                    outcome: DnsOutcome::NxDomain,
                });
            }
        };
        let label = match domain.arpa_sld() {
            Some(sld) => sld,
            None => {
                return Some(LocalAnswer::Answered {
                    records: vec![],
                    outcome: DnsOutcome::NxDomain,
                });
            }
        };

        match label {
            // (2) resolver.arpa. → DDR
            "resolver" if arpa_suffix == "resolver" || arpa_suffix == "_dns.resolver" => {
                if query_type == RecordType::SVCB && arpa_suffix == "_dns.resolver" {
                    let records = self.build_ddr_records();
                    return Some(LocalAnswer::Answered { records, outcome: DnsOutcome::Local });
                }
                Some(LocalAnswer::Answered { records: vec![], outcome: DnsOutcome::Local })
            }
            // (3) in-addr.arpa. / ip6.arpa. → PTR
            "in-addr" | "ip6" => {
                // `parse_arpa_name` requires an FQDN, so parse `domain.raw()` (with trailing dot).
                let Ok(dns_name) = Name::from_str(domain.raw()) else {
                    return Some(LocalAnswer::Answered {
                        records: vec![],
                        outcome: DnsOutcome::NxDomain,
                    });
                };
                let Ok(net) = dns_name.parse_arpa_name() else {
                    return Some(LocalAnswer::Answered {
                        records: vec![],
                        outcome: DnsOutcome::NxDomain,
                    });
                };
                let addr = net.addr();
                self.resolve_ptr_by_addr(&addr, domain)
            }
            // (4) ipv4only.arpa. / ipv6only.arpa. → NODATA (special-use
            // domains for NAT64/NAT46 discovery, RFC 8880)
            "ipv4only" if arpa_suffix == "ipv4only" => {
                Some(LocalAnswer::Answered { records: vec![], outcome: DnsOutcome::Local })
            }
            "ipv6only" if arpa_suffix == "ipv6only" => {
                Some(LocalAnswer::Answered { records: vec![], outcome: DnsOutcome::Local })
            }
            // (5) Remaining .arpa names belong to the configured LAN zone only
            // when the complete suffix matches (for example, `home.arpa`).
            _ => match self.matching_local_zone(domain) {
                Some(zone) => match self.resolve_local_domain(domain, zone, query_type) {
                    // Every `.arpa` answer carries a records field: check and
                    // refresh report `records: Some(...)` for all `.arpa`
                    // names, apexes included.
                    LocalAnswer::Empty { outcome } => {
                        Some(LocalAnswer::Answered { records: vec![], outcome })
                    }
                    answer => Some(answer),
                },
                None => {
                    Some(LocalAnswer::Answered { records: vec![], outcome: DnsOutcome::NxDomain })
                }
            },
        }
    }

    /// Reverse PTR answer for managed addresses, backed by the device
    /// directory's address anchors. `None` means the address is not owned
    /// locally and the query must continue to the cache/upstream stage.
    fn resolve_ptr_by_addr(&self, addr: &IpAddr, domain: &ParsedDomain) -> Option<LocalAnswer> {
        const PTR_TTL: u32 = 60;

        if !is_managed_ptr_addr(addr) {
            return None;
        }

        // localhost PTR is owned by the resolver, not the device directory.
        if addr.is_loopback() {
            let Ok(target) = Name::from_utf8("localhost.") else {
                return Some(LocalAnswer::Answered { records: vec![], outcome: DnsOutcome::Error });
            };
            let record =
                Record::from_rdata(domain.as_dns_name().clone(), PTR_TTL, RData::PTR(PTR(target)));
            return Some(LocalAnswer::Answered {
                records: vec![record],
                outcome: DnsOutcome::Local,
            });
        }

        if !self.is_enabled() {
            return None;
        }

        let entry = match addr {
            IpAddr::V4(ip) => self.directory.entry_by_ipv4(ip),
            IpAddr::V6(ip) => self.directory.entry_by_ipv6(ip),
        };
        let hostname = entry.and_then(|entry| entry.hostname.clone());
        let Some(hostname) = hostname else {
            return Some(LocalAnswer::Answered { records: vec![], outcome: DnsOutcome::NxDomain });
        };

        let suffix = self.hostname_config.load().lan_suffix.clone();
        let fqdn = if suffix.is_empty() {
            format!("{hostname}.")
        } else {
            format!("{hostname}.{suffix}.")
        };
        let Ok(target) = Name::from_utf8(&fqdn) else {
            return Some(LocalAnswer::Answered { records: vec![], outcome: DnsOutcome::Error });
        };
        let rdata = RData::PTR(PTR(target));
        let record = Record::from_rdata(domain.as_dns_name().clone(), PTR_TTL, rdata);
        Some(LocalAnswer::Answered { records: vec![record], outcome: DnsOutcome::Local })
    }
}
