use hickory_proto::op::Message;
use nix::sys::socket::{SockaddrIn, SockaddrIn6};

use super::MDNS_LINK_HOP_LIMIT;

#[derive(Clone, Copy)]
pub(super) enum MdnsFamily {
    V4,
    V6,
}

pub(super) struct MdnsPacket {
    pub(super) bytes: Vec<u8>,
    pub(super) ifindex: u32,
    pub(super) hop_limit: Option<u32>,
    pub(super) destination_is_multicast: bool,
    pub(super) family: MdnsFamily,
    pub(super) src: MdnsSource,
    pub(super) query_unicast_response: bool,
}

#[derive(Clone)]
pub(super) enum MdnsSource {
    V4(SockaddrIn),
    V6(SockaddrIn6),
}

impl MdnsSource {
    pub(super) fn port(&self) -> u16 {
        match self {
            MdnsSource::V4(addr) => addr.port(),
            MdnsSource::V6(addr) => addr.port(),
        }
    }
}

pub(super) fn parse_query_unicast_response(packet: &[u8]) -> bool {
    let Ok(message) = Message::from_vec(packet) else {
        return false;
    };

    message.queries.iter().any(|query| query.mdns_unicast_response())
}

pub(super) fn has_valid_mdns_hop_limit(family: MdnsFamily, hop_limit: Option<u32>) -> bool {
    match family {
        MdnsFamily::V4 => matches!(hop_limit, Some(MDNS_LINK_HOP_LIMIT) | Some(1)),
        MdnsFamily::V6 => hop_limit == Some(MDNS_LINK_HOP_LIMIT),
    }
}

pub(super) fn normalize_name(name: &str) -> String {
    let mut name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    name.push('.');
    name
}
