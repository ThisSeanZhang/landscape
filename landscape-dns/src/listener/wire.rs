use std::net::SocketAddr;

use hickory_proto::{
    op::{Edns, Header, Message, MessageType, Metadata, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, Record, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};

use crate::domain::ParsedDomain;

pub(crate) const MAX_EDNS_PAYLOAD: u16 = 65535;
const DEFAULT_PAYLOAD: u16 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Protocol {
    Udp,
    Tcp,
    Https,
}

pub(crate) struct DnsRequest {
    pub(crate) id: u16,
    pub(crate) op_code: OpCode,
    pub(crate) recursion_desired: bool,
    pub(crate) checking_disabled: bool,
    pub(crate) name: Name,
    pub(crate) domain: ParsedDomain,
    pub(crate) query_type: RecordType,
    pub(crate) edns_max_size: u16,
    /// Requester's EDNS, kept to echo the OPT record in responses.
    pub(crate) edns: Option<Edns>,
    pub(crate) src: SocketAddr,
    #[allow(dead_code)]
    pub(crate) protocol: Protocol,
}

pub(crate) enum DecodeOutcome {
    Request(DnsRequest),
    /// Silently drop: response-type messages and unusable source addresses.
    Ignore,
    /// Unparseable bytes without a usable DNS header. UDP drops these
    /// silently (no request id to answer with); DoH answers HTTP 400.
    Malformed,
    Reply {
        message: Message,
        max_size: u16,
    },
}

pub(crate) fn decode(buffer: &[u8], src: SocketAddr, protocol: Protocol) -> DecodeOutcome {
    if src.port() == 0 || src.ip().is_unspecified() {
        return DecodeOutcome::Ignore;
    }

    let message = match Message::from_vec(buffer) {
        Ok(message) => message,
        Err(e) => {
            tracing::debug!("failed to parse DNS message from {src}: {e}");
            return malformed_outcome(buffer);
        }
    };

    if message.message_type == MessageType::Response {
        return DecodeOutcome::Ignore;
    }

    if let Some(code) = validate(&message) {
        let max_size = request_max_size(&message);
        return DecodeOutcome::Reply { message: error_response(&message, code), max_size };
    }

    let edns_max_size = request_max_size(&message);
    let edns = message.edns.clone();
    let query = message.queries.into_iter().next().expect("validated single query");
    let Query { name, query_type, .. } = query;
    let domain = ParsedDomain::from_wire_name(name.to_lowercase());

    DecodeOutcome::Request(DnsRequest {
        id: message.metadata.id,
        op_code: message.metadata.op_code,
        recursion_desired: message.metadata.recursion_desired,
        checking_disabled: message.metadata.checking_disabled,
        edns_max_size,
        edns,
        domain,
        name,
        query_type,
        src,
        protocol,
    })
}

fn validate(message: &Message) -> Option<ResponseCode> {
    if message.queries.len() != 1 {
        return Some(ResponseCode::FormErr);
    }
    if message.op_code != OpCode::Query {
        return Some(ResponseCode::NotImp);
    }
    let query = &message.queries[0];
    if query.query_class != DNSClass::IN {
        return Some(ResponseCode::Refused);
    }
    match query.query_type {
        RecordType::ANY | RecordType::AXFR | RecordType::IXFR => Some(ResponseCode::Refused),
        RecordType::OPT | RecordType::ZERO => Some(ResponseCode::FormErr),
        RecordType::TSIG | RecordType::Unknown(249) => Some(ResponseCode::NotImp),
        _ => None,
    }
}

fn request_max_size(message: &Message) -> u16 {
    match message.edns.as_ref() {
        Some(edns) => edns.max_payload().clamp(DEFAULT_PAYLOAD, MAX_EDNS_PAYLOAD),
        None => DEFAULT_PAYLOAD,
    }
}

pub(crate) fn build_response(
    req: &DnsRequest,
    code: ResponseCode,
    records: Vec<Record>,
) -> Message {
    let mut response = Message::response(req.id, req.op_code);
    response.metadata.recursion_desired = req.recursion_desired;
    response.metadata.checking_disabled = req.checking_disabled;
    response.metadata.recursion_available = true;
    response.metadata.authoritative = true;
    response.metadata.response_code = code;
    response.add_query(Query::query(req.name.clone(), req.query_type));
    response.answers = records;
    if let Some(req_edns) = &req.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(req.edns_max_size);
        edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
        response.set_edns(edns);
    }
    response
}

fn error_response(message: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(message.id, message.op_code);
    response.metadata.recursion_desired = message.recursion_desired;
    response.metadata.checking_disabled = message.checking_disabled;
    response.metadata.recursion_available = true;
    response.metadata.authoritative = true;
    response.metadata.response_code = code;
    response.queries = message.queries.clone();
    response
}

fn malformed_outcome(buffer: &[u8]) -> DecodeOutcome {
    let Ok(header) = Header::read(&mut BinDecoder::new(buffer)) else {
        return DecodeOutcome::Malformed;
    };
    if header.metadata.message_type == MessageType::Response {
        return DecodeOutcome::Ignore;
    }
    let mut metadata = Metadata::response_from_request(&header.metadata);
    metadata.response_code = ResponseCode::FormErr;
    let mut message = Message::new(metadata.id, MessageType::Response, metadata.op_code);
    message.metadata = metadata;
    DecodeOutcome::Reply { message, max_size: DEFAULT_PAYLOAD }
}

pub(crate) fn encode_response(message: &Message, max_size: u16) -> Vec<u8> {
    if let Some(buffer) = try_encode(message, max_size) {
        return buffer;
    }
    if let Some(buffer) = try_encode(&message.truncate(), max_size) {
        return buffer;
    }
    servfail_bytes(message.id)
}

fn try_encode(message: &Message, max_size: u16) -> Option<Vec<u8>> {
    let mut buffer = Vec::with_capacity(usize::from(DEFAULT_PAYLOAD));
    let mut encoder = BinEncoder::new(&mut buffer);
    encoder.set_max_size(max_size);
    message.emit(&mut encoder).ok()?;
    Some(buffer)
}

fn servfail_bytes(id: u16) -> Vec<u8> {
    let message = Message::error_msg(id, OpCode::Query, ResponseCode::ServFail);
    try_encode(&message, MAX_EDNS_PAYLOAD).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::{
        op::{Edns, Message},
        rr::{Name, RData, Record, rdata::A},
    };

    use super::*;

    fn query_message() -> Message {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message
            .add_query(Query::query(Name::from_ascii("WWW.Example.COM.").unwrap(), RecordType::A));
        message
    }

    fn test_src() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 5300)
    }

    fn encoded(message: &Message) -> Vec<u8> {
        message.to_vec().unwrap()
    }

    #[test]
    fn decodes_valid_query_into_request() {
        let buffer = encoded(&query_message());

        let DecodeOutcome::Request(req) = decode(&buffer, test_src(), Protocol::Udp) else {
            panic!("expected request");
        };

        assert_eq!(req.id, 0x1234);
        assert_eq!(req.query_type, RecordType::A);
        assert_eq!(req.domain.raw(), "www.example.com.");
        assert_eq!(req.name.to_string(), "WWW.Example.COM.");
        assert_eq!(req.edns_max_size, DEFAULT_PAYLOAD);
    }

    #[test]
    fn decodes_edns_max_size() {
        let mut message = query_message();
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        message.set_edns(edns);
        let buffer = encoded(&message);

        let DecodeOutcome::Request(req) = decode(&buffer, test_src(), Protocol::Udp) else {
            panic!("expected request");
        };

        assert_eq!(req.edns_max_size, 1232);
    }

    #[test]
    fn drops_response_messages() {
        let mut message = query_message();
        message.metadata.message_type = MessageType::Response;
        let buffer = encoded(&message);

        assert!(matches!(decode(&buffer, test_src(), Protocol::Udp), DecodeOutcome::Ignore));
    }

    #[test]
    fn drops_zero_port_sources() {
        let buffer = encoded(&query_message());
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 0);

        assert!(matches!(decode(&buffer, src, Protocol::Udp), DecodeOutcome::Ignore));
    }

    #[test]
    fn rejects_multiple_queries_with_formerr() {
        let mut message = query_message();
        message.add_query(Query::query(Name::from_ascii("other.com.").unwrap(), RecordType::AAAA));
        let buffer = encoded(&message);

        let DecodeOutcome::Reply { message, .. } = decode(&buffer, test_src(), Protocol::Udp)
        else {
            panic!("expected reply");
        };

        assert_eq!(message.response_code, ResponseCode::FormErr);
        assert_eq!(message.queries.len(), 2);
    }

    #[test]
    fn rejects_non_query_opcode_with_notimp() {
        let mut message = query_message();
        message.metadata.op_code = OpCode::Status;
        let buffer = encoded(&message);

        let DecodeOutcome::Reply { message, .. } = decode(&buffer, test_src(), Protocol::Udp)
        else {
            panic!("expected reply");
        };

        assert_eq!(message.response_code, ResponseCode::NotImp);
    }

    #[test]
    fn rejects_non_in_class_with_refused() {
        let mut message = query_message();
        message.queries[0].query_class = DNSClass::CH;
        let buffer = encoded(&message);

        let DecodeOutcome::Reply { message, .. } = decode(&buffer, test_src(), Protocol::Udp)
        else {
            panic!("expected reply");
        };

        assert_eq!(message.response_code, ResponseCode::Refused);
    }

    #[test]
    fn rejects_any_type_with_refused() {
        let mut message = query_message();
        message.queries[0].query_type = RecordType::ANY;
        let buffer = encoded(&message);

        let DecodeOutcome::Reply { message, .. } = decode(&buffer, test_src(), Protocol::Udp)
        else {
            panic!("expected reply");
        };

        assert_eq!(message.response_code, ResponseCode::Refused);
    }

    #[test]
    fn replies_formerr_for_unparseable_message_with_header() {
        let buffer = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

        let DecodeOutcome::Reply { message, .. } = decode(&buffer, test_src(), Protocol::Udp)
        else {
            panic!("expected reply");
        };

        assert_eq!(message.id, 0x1234);
        assert_eq!(message.response_code, ResponseCode::FormErr);
    }

    #[test]
    fn reports_malformed_for_unparseable_message_without_header() {
        assert!(matches!(decode(&[0; 11], test_src(), Protocol::Udp), DecodeOutcome::Malformed));
    }

    #[test]
    fn ignores_unparseable_response_message() {
        let buffer = [0xab, 0xcd, 0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

        assert!(matches!(decode(&buffer, test_src(), Protocol::Udp), DecodeOutcome::Ignore));
    }

    #[test]
    fn build_response_sets_recursion_and_authoritative_flags() {
        let buffer = encoded(&query_message());
        let DecodeOutcome::Request(req) = decode(&buffer, test_src(), Protocol::Udp) else {
            panic!("expected request");
        };

        let response = build_response(&req, ResponseCode::NoError, vec![]);

        assert_eq!(response.id, 0x1234);
        assert_eq!(response.message_type, MessageType::Response);
        assert!(response.recursion_available);
        assert!(response.authoritative);
        assert_eq!(response.queries.len(), 1);
        assert_eq!(response.queries[0].name.to_string(), "WWW.Example.COM.");
    }

    #[test]
    fn build_response_echoes_edns_with_client_payload_and_do_bit() {
        let mut message = query_message();
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(true);
        message.set_edns(edns);
        let buffer = encoded(&message);

        let DecodeOutcome::Request(req) = decode(&buffer, test_src(), Protocol::Udp) else {
            panic!("expected request");
        };

        let response = build_response(&req, ResponseCode::NoError, vec![]);

        let resp_edns = response.edns.expect("response should echo EDNS");
        assert_eq!(resp_edns.max_payload(), 1232);
        assert!(resp_edns.flags().dnssec_ok);
        assert!(resp_edns.options().as_ref().is_empty());
    }

    #[test]
    fn build_response_omits_edns_without_request_edns() {
        let buffer = encoded(&query_message());
        let DecodeOutcome::Request(req) = decode(&buffer, test_src(), Protocol::Udp) else {
            panic!("expected request");
        };

        let response = build_response(&req, ResponseCode::NoError, vec![]);

        assert!(response.edns.is_none());
    }

    #[test]
    fn encode_response_truncates_with_tc_bit_on_overflow() {
        let buffer = encoded(&query_message());
        let DecodeOutcome::Request(req) = decode(&buffer, test_src(), Protocol::Udp) else {
            panic!("expected request");
        };

        let answers: Vec<Record> = (0..60)
            .map(|i| {
                Record::from_rdata(
                    Name::from_ascii("www.example.com.").unwrap(),
                    300,
                    RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, i as u8))),
                )
            })
            .collect();
        let response = build_response(&req, ResponseCode::NoError, answers);

        let bytes = encode_response(&response, DEFAULT_PAYLOAD);
        let decoded = Message::from_vec(&bytes).unwrap();

        assert!(decoded.truncation);
        assert!(decoded.answers.len() < 60);
        assert_eq!(decoded.queries.len(), 1);
        assert!(bytes.len() <= usize::from(DEFAULT_PAYLOAD));
    }

    #[test]
    fn encode_response_keeps_small_messages() {
        let buffer = encoded(&query_message());
        let DecodeOutcome::Request(req) = decode(&buffer, test_src(), Protocol::Udp) else {
            panic!("expected request");
        };
        let answer = Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        );
        let response = build_response(&req, ResponseCode::NoError, vec![answer]);

        let bytes = encode_response(&response, DEFAULT_PAYLOAD);
        let decoded = Message::from_vec(&bytes).unwrap();

        assert!(!decoded.truncation);
        assert_eq!(decoded.answers.len(), 1);
    }
}
