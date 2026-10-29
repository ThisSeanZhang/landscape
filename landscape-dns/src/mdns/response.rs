use std::{net::IpAddr, str::FromStr};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};

use crate::resolve::LocalDnsAnswerProvider;

use super::packet::{MdnsSource, normalize_name};
use super::{LEGACY_UNICAST_TTL_SECS, MDNS_HOST_TTL_SECS, MDNS_HOSTNAME, MDNS_PORT};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MdnsResponseMode {
    MulticastMdns,
    UnicastMdns,
    LegacyUnicast,
}

pub(super) fn build_response(
    packet: &[u8],
    ifindex: u32,
    local_answer_provider: Option<&dyn LocalDnsAnswerProvider>,
    mode: MdnsResponseMode,
) -> Option<Vec<u8>> {
    let Ok(message) = Message::from_vec(packet) else {
        return None;
    };
    if message.metadata.message_type != MessageType::Query
        || message.metadata.op_code != OpCode::Query
    {
        return None;
    }

    let ttl = mode.answer_ttl();
    let cache_flush = mode.uses_cache_flush();
    let answers = message
        .queries
        .iter()
        .flat_map(|query| {
            answer_records_for_query(query, ifindex, local_answer_provider, ttl, cache_flush)
        })
        .fold(Vec::new(), dedup_answer_record)
        .into_iter()
        .filter(|answer| !is_suppressed_by_known_answers(answer, &message.answers))
        .collect::<Vec<_>>();
    if answers.is_empty() {
        return None;
    }

    let mut response = Message::new(0, MessageType::Query, OpCode::Query);
    response.metadata.id =
        if mode == MdnsResponseMode::LegacyUnicast { message.metadata.id } else { 0 };
    response.metadata.message_type = MessageType::Response;
    response.metadata.op_code = OpCode::Query;
    response.metadata.authoritative = true;
    if mode == MdnsResponseMode::LegacyUnicast {
        for query in &message.queries {
            response.add_query(query.clone());
        }
    }
    for answer in answers {
        response.add_answer(answer);
    }

    response.to_vec().ok()
}

fn answer_records_for_query(
    query: &Query,
    ifindex: u32,
    local_answer_provider: Option<&dyn LocalDnsAnswerProvider>,
    ttl: u32,
    cache_flush: bool,
) -> Vec<Record> {
    if !normalize_name(&query.name().to_string()).eq_ignore_ascii_case(MDNS_HOSTNAME) {
        return Vec::new();
    }
    if !matches!(query.query_class(), DNSClass::IN | DNSClass::ANY) {
        return Vec::new();
    }

    let mut answers = Vec::new();
    let name = match Name::from_str(MDNS_HOSTNAME) {
        Ok(name) => name,
        Err(_) => return answers,
    };

    if matches!(query.query_type(), RecordType::A | RecordType::ANY) {
        for ip in load_answer_addrs(local_answer_provider, RecordType::A, ifindex) {
            if let IpAddr::V4(ip) = ip {
                let mut record = Record::from_rdata(name.clone(), ttl, RData::A(A(ip)));
                record.mdns_cache_flush = cache_flush;
                answers.push(record);
            }
        }
    }

    if matches!(query.query_type(), RecordType::AAAA | RecordType::ANY) {
        for ip in load_answer_addrs(local_answer_provider, RecordType::AAAA, ifindex) {
            if let IpAddr::V6(ip) = ip {
                let mut record = Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(ip)));
                record.mdns_cache_flush = cache_flush;
                answers.push(record);
            }
        }
    }

    answers
}

fn dedup_answer_record(mut answers: Vec<Record>, answer: Record) -> Vec<Record> {
    if !answers.iter().any(|existing| {
        existing.record_type() == answer.record_type() && existing.data == answer.data
    }) {
        answers.push(answer);
    }

    answers
}

fn is_suppressed_by_known_answers(answer: &Record, known_answers: &[Record]) -> bool {
    known_answers.iter().any(|known_answer| {
        known_answer.name == answer.name
            && known_answer.record_type() == answer.record_type()
            && known_answer.dns_class == answer.dns_class
            && known_answer.data == answer.data
            && known_answer.ttl >= answer.ttl / 2
    })
}

impl MdnsResponseMode {
    pub(super) fn is_unicast(self) -> bool {
        matches!(self, Self::UnicastMdns | Self::LegacyUnicast)
    }

    fn answer_ttl(self) -> u32 {
        match self {
            Self::LegacyUnicast => LEGACY_UNICAST_TTL_SECS,
            Self::MulticastMdns | Self::UnicastMdns => MDNS_HOST_TTL_SECS,
        }
    }

    fn uses_cache_flush(self) -> bool {
        !matches!(self, Self::LegacyUnicast)
    }
}

pub(super) fn select_response_mode(
    src: &MdnsSource,
    query_unicast_response: bool,
    destination_is_multicast: bool,
) -> MdnsResponseMode {
    if src.port() != MDNS_PORT {
        MdnsResponseMode::LegacyUnicast
    } else if query_unicast_response || !destination_is_multicast {
        MdnsResponseMode::UnicastMdns
    } else {
        MdnsResponseMode::MulticastMdns
    }
}

fn load_answer_addrs(
    local_answer_provider: Option<&dyn LocalDnsAnswerProvider>,
    query_type: RecordType,
    ifindex: u32,
) -> Vec<IpAddr> {
    local_answer_provider
        .map(|provider| {
            if ifindex == 0 {
                provider.load_local_answer_addrs(query_type)
            } else {
                provider.load_local_answer_addrs_for_ifindex(query_type, ifindex)
            }
        })
        .unwrap_or_default()
        .iter()
        .copied()
        .collect()
}
