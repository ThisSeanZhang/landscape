use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use hickory_proto::{
    op::{LowerQuery, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        DNSClass, Name, RData, Record, RecordType,
    },
};
use landscape_common::metric::dns::DnsResultStatus;

const LOCALHOST_TTL_SECS: u32 = 60;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PreflightDecision {
    Continue,
    Respond { code: ResponseCode, records: Vec<Record>, status: DnsResultStatus },
}

impl PreflightDecision {
    fn no_records(code: ResponseCode, status: DnsResultStatus) -> Self {
        Self::Respond { code, records: Vec::new(), status }
    }
}

pub(crate) fn classify_query_count(query_count: usize) -> PreflightDecision {
    if query_count == 1 {
        PreflightDecision::Continue
    } else {
        PreflightDecision::no_records(ResponseCode::FormErr, DnsResultStatus::Error)
    }
}

pub(crate) fn classify_hard_query(op_code: OpCode, query: &LowerQuery) -> PreflightDecision {
    if op_code != OpCode::Query {
        return PreflightDecision::no_records(ResponseCode::NotImp, DnsResultStatus::Error);
    }

    if query.query_class() != DNSClass::IN {
        return PreflightDecision::no_records(ResponseCode::Refused, DnsResultStatus::Error);
    }

    match blocked_record_type_response(query.query_type()) {
        Some(code) => PreflightDecision::no_records(code, DnsResultStatus::Error),
        None => PreflightDecision::Continue,
    }
}

pub(crate) fn classify_hard_local_zone(domain: &str, query_type: RecordType) -> PreflightDecision {
    let domain = normalize_domain(domain);
    if is_at_or_under(&domain, "localhost.") {
        return localhost_response(&domain, query_type);
    }

    PreflightDecision::Continue
}

pub(crate) fn classify_overrideable_local_zone(domain: &str) -> PreflightDecision {
    let domain = normalize_domain(domain);

    if is_at_or_under(&domain, "local.") {
        return PreflightDecision::no_records(ResponseCode::NoError, DnsResultStatus::Local);
    }

    if is_at_or_under(&domain, "ipv4only.arpa.") {
        return PreflightDecision::no_records(ResponseCode::NoError, DnsResultStatus::Local);
    }

    if is_at_or_under(&domain, "home.arpa.")
        || is_at_or_under(&domain, "invalid.")
        || is_at_or_under(&domain, "test.")
        || is_at_or_under(&domain, "onion.")
        || is_private_reverse_zone(&domain)
    {
        return PreflightDecision::no_records(ResponseCode::NXDomain, DnsResultStatus::NxDomain);
    }

    PreflightDecision::Continue
}

fn blocked_record_type_response(query_type: RecordType) -> Option<ResponseCode> {
    match query_type {
        RecordType::ANY | RecordType::AXFR | RecordType::IXFR => Some(ResponseCode::Refused),
        RecordType::OPT | RecordType::ZERO => Some(ResponseCode::FormErr),
        RecordType::TSIG | RecordType::Unknown(249) => Some(ResponseCode::NotImp),
        _ => None,
    }
}

fn localhost_response(domain: &str, query_type: RecordType) -> PreflightDecision {
    let Ok(name) = Name::from_str(domain) else {
        return PreflightDecision::no_records(ResponseCode::FormErr, DnsResultStatus::Error);
    };

    let rdata = match query_type {
        RecordType::A => Some(RData::A(A(Ipv4Addr::LOCALHOST))),
        RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
        _ => None,
    };
    let records = rdata
        .map(|rdata| vec![Record::from_rdata(name, LOCALHOST_TTL_SECS, rdata)])
        .unwrap_or_default();

    PreflightDecision::Respond {
        code: ResponseCode::NoError,
        records,
        status: DnsResultStatus::Local,
    }
}

fn is_private_reverse_zone(domain: &str) -> bool {
    if !domain.ends_with(".arpa.") {
        return false;
    }

    let Ok(name) = Name::from_str(domain) else {
        return false;
    };
    let Ok(net) = name.parse_arpa_name() else {
        return false;
    };

    match net.addr() {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || is_shared_ipv4(ip)
                || ip.octets()[0] == 0
                || ip.octets()[0] == 255
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

fn is_at_or_under(domain: &str, zone: &str) -> bool {
    domain == zone || domain.ends_with(&format!(".{zone}"))
}

fn normalize_domain(domain: &str) -> String {
    let mut domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    domain.push('.');
    domain
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    fn make_query(name: &str, record_type: RecordType, class: DNSClass) -> LowerQuery {
        let mut query = Query::query(Name::from_str(name).unwrap(), record_type);
        query.set_query_class(class);
        LowerQuery::query(query)
    }

    fn response_code(decision: PreflightDecision) -> Option<ResponseCode> {
        match decision {
            PreflightDecision::Respond { code, .. } => Some(code),
            PreflightDecision::Continue => None,
        }
    }

    #[test]
    fn query_count_must_be_exactly_one() {
        assert_eq!(classify_query_count(1), PreflightDecision::Continue);
        assert_eq!(response_code(classify_query_count(0)), Some(ResponseCode::FormErr));
        assert_eq!(response_code(classify_query_count(2)), Some(ResponseCode::FormErr));
    }

    #[test]
    fn hard_query_rejects_non_standard_opcode_and_class() {
        let query = make_query("example.com.", RecordType::A, DNSClass::IN);
        assert_eq!(
            response_code(classify_hard_query(OpCode::Status, &query)),
            Some(ResponseCode::NotImp)
        );

        let query = make_query("version.bind.", RecordType::TXT, DNSClass::CH);
        assert_eq!(
            response_code(classify_hard_query(OpCode::Query, &query)),
            Some(ResponseCode::Refused)
        );
    }

    #[test]
    fn hard_query_rejects_non_forwardable_types() {
        for (record_type, code) in [
            (RecordType::ANY, ResponseCode::Refused),
            (RecordType::AXFR, ResponseCode::Refused),
            (RecordType::IXFR, ResponseCode::Refused),
            (RecordType::OPT, ResponseCode::FormErr),
            (RecordType::ZERO, ResponseCode::FormErr),
            (RecordType::TSIG, ResponseCode::NotImp),
            (RecordType::Unknown(249), ResponseCode::NotImp),
        ] {
            let query = make_query("example.com.", record_type, DNSClass::IN);
            assert_eq!(response_code(classify_hard_query(OpCode::Query, &query)), Some(code));
        }
    }

    #[test]
    fn localhost_is_answered_locally() {
        let PreflightDecision::Respond { code, records, status } =
            classify_hard_local_zone("foo.localhost.", RecordType::A)
        else {
            panic!("localhost must be handled locally");
        };

        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(status, DnsResultStatus::Local);
        assert_eq!(records.len(), 1);
        assert!(matches!(records[0].data(), RData::A(A(ip)) if *ip == Ipv4Addr::LOCALHOST));
        assert_eq!(
            classify_hard_local_zone("badlocalhost.", RecordType::A),
            PreflightDecision::Continue
        );
    }

    #[test]
    fn local_mdns_zone_gets_empty_local_answer() {
        let PreflightDecision::Respond { code, records, status } =
            classify_overrideable_local_zone("printer.local.")
        else {
            panic!(".local must be handled locally");
        };

        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(status, DnsResultStatus::Local);
        assert!(records.is_empty());
        assert_eq!(
            classify_overrideable_local_zone("printer.local.example."),
            PreflightDecision::Continue
        );
    }

    #[test]
    fn special_use_zones_are_negative_local_answers() {
        for domain in ["home.arpa.", "router.home.arpa.", "invalid.", "foo.test.", "site.onion."] {
            assert_eq!(
                response_code(classify_overrideable_local_zone(domain)),
                Some(ResponseCode::NXDomain)
            );
        }

        assert_eq!(classify_overrideable_local_zone("test.example."), PreflightDecision::Continue);
    }

    #[test]
    fn ipv4only_arpa_gets_empty_local_answer() {
        let PreflightDecision::Respond { code, records, status } =
            classify_overrideable_local_zone("ipv4only.arpa.")
        else {
            panic!("ipv4only.arpa must be handled locally");
        };

        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(status, DnsResultStatus::Local);
        assert!(records.is_empty());
    }

    #[test]
    fn private_ipv4_reverse_zones_are_not_forwarded() {
        for domain in [
            "1.0.0.10.in-addr.arpa.",
            "1.1.168.192.in-addr.arpa.",
            "1.0.0.127.in-addr.arpa.",
            "1.254.169.in-addr.arpa.",
            "1.2.16.172.in-addr.arpa.",
            "1.2.31.172.in-addr.arpa.",
            "1.2.64.100.in-addr.arpa.",
            "1.2.127.100.in-addr.arpa.",
            "1.255.255.0.in-addr.arpa.",
        ] {
            assert_eq!(
                response_code(classify_overrideable_local_zone(domain)),
                Some(ResponseCode::NXDomain),
                "domain = {domain}"
            );
        }

        assert_eq!(
            classify_overrideable_local_zone("1.2.15.172.in-addr.arpa."),
            PreflightDecision::Continue
        );
        assert_eq!(
            classify_overrideable_local_zone("1.2.128.100.in-addr.arpa."),
            PreflightDecision::Continue
        );
    }

    #[test]
    fn private_ipv6_reverse_zones_are_not_forwarded() {
        for domain in [
            "1.0.0.0.c.f.ip6.arpa.",
            "1.0.0.0.d.f.ip6.arpa.",
            "1.0.0.0.8.e.f.ip6.arpa.",
            "1.0.0.0.b.e.f.ip6.arpa.",
            "2.5.0.3.c.c.e.f.f.f.4.4.4.b.8.a.0.0.4.4.3.3.3.3.2.2.2.2.2.2.d.f.ip6.arpa.",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        ] {
            assert_eq!(
                response_code(classify_overrideable_local_zone(domain)),
                Some(ResponseCode::NXDomain),
                "domain = {domain}"
            );
        }

        assert_eq!(
            classify_overrideable_local_zone("1.0.0.0.c.e.f.ip6.arpa."),
            PreflightDecision::Continue
        );
    }
}
