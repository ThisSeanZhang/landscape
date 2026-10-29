use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    str::FromStr,
    sync::Arc,
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{DNSClass, Name, RData, Record, RecordType, rdata::A},
};
use nix::sys::socket::SockaddrIn;

use super::interface::{MdnsInterface, select_response_interfaces};
use super::packet::{
    MdnsFamily, MdnsSource, has_valid_mdns_hop_limit, normalize_name, parse_query_unicast_response,
};
use super::response::{MdnsResponseMode, build_response, select_response_mode};
use super::{LEGACY_UNICAST_TTL_SECS, MDNS_HOST_TTL_SECS, MDNS_HOSTNAME, MDNS_PORT};
use crate::resolve::LocalDnsAnswerProvider;
struct MockLocalAnswerProvider {
    addrs: Vec<IpAddr>,
    ifindexed: HashMap<u32, Vec<IpAddr>>,
}

impl LocalDnsAnswerProvider for MockLocalAnswerProvider {
    fn load_local_answer_addrs(&self, query_type: RecordType) -> Arc<Vec<IpAddr>> {
        Arc::new(
            self.addrs
                .iter()
                .copied()
                .filter(|ip| {
                    matches!(
                        (query_type, ip),
                        (RecordType::A, IpAddr::V4(_)) | (RecordType::AAAA, IpAddr::V6(_))
                    )
                })
                .collect(),
        )
    }

    fn load_local_answer_addrs_for_ifindex(
        &self,
        query_type: RecordType,
        ifindex: u32,
    ) -> Arc<Vec<IpAddr>> {
        Arc::new(
            self.ifindexed
                .iter()
                .filter(|(route_ifindex, _)| **route_ifindex == ifindex)
                .flat_map(|(_, addrs)| addrs.iter())
                .copied()
                .filter(|ip| {
                    matches!(
                        (query_type, ip),
                        (RecordType::A, IpAddr::V4(_)) | (RecordType::AAAA, IpAddr::V6(_))
                    )
                })
                .collect(),
        )
    }
}

fn query_packet(name: &str, record_type: RecordType) -> Vec<u8> {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
    message.to_vec().unwrap()
}

fn query_packet_with_id(name: &str, record_type: RecordType, id: u16) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
    message.to_vec().unwrap()
}

fn query_packet_with_class(name: &str, record_type: RecordType, class: DNSClass) -> Vec<u8> {
    let mut query = Query::query(Name::from_str(name).unwrap(), record_type);
    query.set_query_class(class);

    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(query);
    message.to_vec().unwrap()
}

fn query_packet_with_types(name: &str, record_types: &[RecordType]) -> Vec<u8> {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    for record_type in record_types {
        message.add_query(Query::query(Name::from_str(name).unwrap(), *record_type));
    }
    message.to_vec().unwrap()
}

fn query_packet_with_known_answer(name: &str, known_answer_ttl: u32) -> Vec<u8> {
    let name = Name::from_str(name).unwrap();
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name.clone(), RecordType::A));
    message.add_answer(Record::from_rdata(
        name,
        known_answer_ttl,
        RData::A(A(Ipv4Addr::new(192, 168, 1, 1))),
    ));
    message.to_vec().unwrap()
}

fn query_packet_with_unicast_response(name: &str, record_type: RecordType) -> Vec<u8> {
    let mut query = Query::query(Name::from_str(name).unwrap(), record_type);
    query.set_mdns_unicast_response(true);

    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(query);
    message.to_vec().unwrap()
}

#[test]
fn normalize_name_adds_trailing_dot_and_lowercases() {
    assert_eq!(normalize_name("Landscape.LOCAL"), "landscape.local.");
    assert_eq!(normalize_name("landscape.local."), "landscape.local.");
}

#[test]
fn response_answers_landscape_local_a() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        ifindexed: HashMap::new(),
    };
    let response = build_response(
        &query_packet("landscape.local.", RecordType::A),
        0,
        Some(&provider),
        MdnsResponseMode::MulticastMdns,
    )
    .expect("landscape.local A query must be answered");
    let response = Message::from_vec(&response).unwrap();

    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].name.to_string(), MDNS_HOSTNAME);
    assert_eq!(response.answers[0].record_type(), RecordType::A);
    assert_eq!(response.answers[0].ttl, MDNS_HOST_TTL_SECS);
    assert!(response.answers[0].mdns_cache_flush);
}

#[test]
fn response_ignores_other_local_names() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        ifindexed: HashMap::new(),
    };

    assert!(
        build_response(
            &query_packet("printer.local.", RecordType::A),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .is_none()
    );
}

#[test]
fn response_requires_available_address_family() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        ifindexed: HashMap::new(),
    };

    assert!(
        build_response(
            &query_packet("landscape.local.", RecordType::AAAA),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .is_none()
    );
}

#[test]
fn response_ignores_unsupported_query_class() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        ifindexed: HashMap::new(),
    };

    assert!(
        build_response(
            &query_packet_with_class("landscape.local.", RecordType::A, DNSClass::CH),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .is_none()
    );
}

#[test]
fn response_deduplicates_answers_across_queries() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        ifindexed: HashMap::new(),
    };

    let response = build_response(
        &query_packet_with_types("landscape.local.", &[RecordType::A, RecordType::ANY]),
        0,
        Some(&provider),
        MdnsResponseMode::MulticastMdns,
    )
    .expect("landscape.local A/ANY query must be answered");
    let response = Message::from_vec(&response).unwrap();

    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].record_type(), RecordType::A);
}

#[test]
fn response_suppresses_known_answers_with_sufficient_ttl() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        ifindexed: HashMap::new(),
    };

    assert!(
        build_response(
            &query_packet_with_known_answer("landscape.local.", MDNS_HOST_TTL_SECS / 2),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .is_none()
    );
}

#[test]
fn response_does_not_suppress_known_answers_with_low_ttl() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        ifindexed: HashMap::new(),
    };

    let response = build_response(
        &query_packet_with_known_answer("landscape.local.", MDNS_HOST_TTL_SECS / 2 - 1),
        0,
        Some(&provider),
        MdnsResponseMode::MulticastMdns,
    )
    .expect("low-TTL known answer should not suppress response");
    let response = Message::from_vec(&response).unwrap();

    assert_eq!(response.answers.len(), 1);
}

#[test]
fn query_with_unicast_response_is_detected() {
    assert!(parse_query_unicast_response(&query_packet_with_unicast_response(
        "landscape.local.",
        RecordType::A,
    )));
}

#[test]
fn ipv4_mdns_packets_accept_legacy_link_ttl() {
    assert!(has_valid_mdns_hop_limit(MdnsFamily::V4, Some(255)));
    assert!(has_valid_mdns_hop_limit(MdnsFamily::V4, Some(1)));
    assert!(!has_valid_mdns_hop_limit(MdnsFamily::V4, Some(254)));
    assert!(!has_valid_mdns_hop_limit(MdnsFamily::V4, None));
}

#[test]
fn ipv6_mdns_packets_require_link_local_hop_limit() {
    assert!(has_valid_mdns_hop_limit(MdnsFamily::V6, Some(255)));
    assert!(!has_valid_mdns_hop_limit(MdnsFamily::V6, Some(1)));
    assert!(!has_valid_mdns_hop_limit(MdnsFamily::V6, Some(254)));
    assert!(!has_valid_mdns_hop_limit(MdnsFamily::V6, None));
}

#[test]
fn response_interfaces_use_all_for_missing_packet_ifindex() {
    let interfaces = vec![
        MdnsInterface {
            ifindex: 3,
            name: "lan0".to_string(),
            has_ipv4: true,
            has_ipv6: false,
        },
        MdnsInterface {
            ifindex: 7,
            name: "lan1".to_string(),
            has_ipv4: false,
            has_ipv6: true,
        },
    ];

    assert_eq!(select_response_interfaces(&interfaces, 0), interfaces);
}

#[test]
fn response_interfaces_match_packet_ifindex() {
    let interfaces = vec![
        MdnsInterface {
            ifindex: 3,
            name: "lan0".to_string(),
            has_ipv4: true,
            has_ipv6: false,
        },
        MdnsInterface {
            ifindex: 7,
            name: "lan1".to_string(),
            has_ipv4: false,
            has_ipv6: true,
        },
    ];

    assert_eq!(
        select_response_interfaces(&interfaces, 7),
        vec![MdnsInterface {
            ifindex: 7,
            name: "lan1".to_string(),
            has_ipv4: false,
            has_ipv6: true,
        }]
    );
}

#[test]
fn response_interfaces_fallback_to_packet_ifindex_when_cache_misses() {
    let interfaces = vec![MdnsInterface {
        ifindex: 3,
        name: "lan0".to_string(),
        has_ipv4: true,
        has_ipv6: true,
    }];

    assert_eq!(
        select_response_interfaces(&interfaces, 9),
        vec![MdnsInterface {
            ifindex: 9,
            name: "ifindex 9".to_string(),
            has_ipv4: true,
            has_ipv6: true,
        }]
    );
}

#[test]
fn response_mode_uses_legacy_unicast_for_non_mdns_source_port() {
    let src =
        MdnsSource::V4(SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), 49_152)));

    assert_eq!(select_response_mode(&src, false, true), MdnsResponseMode::LegacyUnicast);
}

#[test]
fn response_mode_uses_unicast_for_qu_or_direct_unicast_queries() {
    let src = MdnsSource::V4(SockaddrIn::from(SocketAddrV4::new(
        Ipv4Addr::new(192, 168, 1, 2),
        MDNS_PORT,
    )));

    assert_eq!(select_response_mode(&src, true, true), MdnsResponseMode::UnicastMdns);
    assert_eq!(select_response_mode(&src, false, false), MdnsResponseMode::UnicastMdns);
    assert_eq!(select_response_mode(&src, false, true), MdnsResponseMode::MulticastMdns);
}

#[test]
fn legacy_response_keeps_id_query_and_omits_cache_flush() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        ifindexed: HashMap::new(),
    };
    let response = build_response(
        &query_packet_with_id("landscape.local.", RecordType::A, 0x1234),
        0,
        Some(&provider),
        MdnsResponseMode::LegacyUnicast,
    )
    .expect("legacy landscape.local A query must be answered");
    let response = Message::from_vec(&response).unwrap();

    assert_eq!(response.metadata.id, 0x1234);
    assert_eq!(response.queries.len(), 1);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].ttl, LEGACY_UNICAST_TTL_SECS);
    assert!(!response.answers[0].mdns_cache_flush);
}
#[test]
fn response_uses_ifindex_specific_addresses_when_available() {
    let provider = MockLocalAnswerProvider {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
        ifindexed: HashMap::from([
            (3, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))]),
            (7, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 2, 10))]),
        ]),
    };

    let response = build_response(
        &query_packet("landscape.local.", RecordType::A),
        7,
        Some(&provider),
        MdnsResponseMode::MulticastMdns,
    )
    .expect("landscape.local A query must be answered");
    let response = Message::from_vec(&response).unwrap();

    assert_eq!(response.answers.len(), 1);
    assert_eq!(&response.answers[0].data, &RData::A(A(Ipv4Addr::new(192, 168, 2, 10))));
}
