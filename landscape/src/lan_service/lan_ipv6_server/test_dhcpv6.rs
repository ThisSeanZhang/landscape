use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use landscape_common::lan_service::lan_ipv6::{
    DHCPv6IANAConfig, LanPrefixGroupConfig, NaPrefixConfig, PrefixParentSource, RaPrefixConfig,
};
use landscape_common::net::MacAddr;
use landscape_common::net_proto::udp::dhcp::v6::{
    self, Authentication, DhcpOption, DhcpOptions, IANA, MessageType, OptionCode,
};
use landscape_common::net_proto::udp::dhcp::{Decodable, Decoder, Encodable, Encoder};
use landscape_common::wan_service::ipv6_pd::IAPrefixMap;

use super::dhcpv6::{Dhcpv6Result, process_dhcpv6_msg};
use super::{Ipv6LanReplyParams, Ipv6ServerStatus, compute_subnets, mpsc};
use crate::lan_service::lan_ipv6_service::MacLinkMapCache;

const CLIENT_MAC: MacAddr = MacAddr(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
const SERVER_DUID: &[u8] = &[0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

/// DUID-LLT (type 1, hwtype ethernet) carrying the client MAC, so
/// `resolve_mac` succeeds without any link-layer cache entry.
fn client_duid() -> Vec<u8> {
    let mut duid = vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    duid.extend_from_slice(&CLIENT_MAC.octets());
    duid
}

fn make_status() -> Ipv6ServerStatus {
    let na_config = DHCPv6IANAConfig {
        max_prefix_len: 64,
        pool_start: 0x100,
        pool_end: Some(0x1FF),
        preferred_lifetime: 3600,
        valid_lifetime: 7200,
    };

    let mut status =
        Ipv6ServerStatus::new(Some(na_config), None, vec![], mpsc::unbounded_channel().0);

    let groups = vec![LanPrefixGroupConfig {
        group_id: "default".into(),
        parent: PrefixParentSource::Static {
            base_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            parent_prefix_len: 60,
        },
        ra: Some(RaPrefixConfig {
            pool_index: 1,
            preferred_lifetime: 1800,
            valid_lifetime: 3600,
        }),
        na: Some(NaPrefixConfig { pool_index: 1 }),
        pd: None,
    }];

    let subnets = compute_subnets(&groups, &IAPrefixMap::new(), 300);
    status.update_prefix(&subnets);
    status
}

fn reply_params() -> Ipv6LanReplyParams {
    Ipv6LanReplyParams {
        preferred_lifetime: 300,
        valid_lifetime: 600,
        ra_flags: 0x80,
        ra_autonomous: true,
    }
}

fn run(status: &mut Ipv6ServerStatus, msg: &v6::Message) -> Dhcpv6Result {
    let mut buf = Vec::new();
    msg.encode(&mut Encoder::new(&mut buf)).unwrap();
    process_dhcpv6_msg(
        status,
        &buf,
        SocketAddr::new(IpAddr::V6("fe80::1".parse().unwrap()), 546),
        SERVER_DUID,
        &reply_params(),
        &[],
        &Arc::new(MacLinkMapCache::new()),
        1,
    )
}

fn decode_reply(result: &Dhcpv6Result) -> v6::Message {
    v6::Message::decode(&mut Decoder::new(result.reply_bytes.as_deref().unwrap())).unwrap()
}

fn auth_option(msg: &v6::Message) -> Option<&Authentication> {
    match msg.opts().get(OptionCode::Authentication) {
        Some(DhcpOption::Authentication(auth)) => Some(auth),
        _ => None,
    }
}

fn with_iana(mut msg: v6::Message, reconf: bool) -> v6::Message {
    msg.opts_mut().insert(DhcpOption::IANA(IANA { id: 1, t1: 0, t2: 0, opts: DhcpOptions::new() }));
    if reconf {
        msg.opts_mut().insert(DhcpOption::ReconfAccept);
    }
    msg
}

fn solicit(reconf: bool) -> v6::Message {
    let mut msg = with_iana(v6::Message::new(MessageType::Solicit), reconf);
    msg.opts_mut().insert(DhcpOption::ClientId(client_duid()));
    msg
}

fn request(reconf: bool) -> v6::Message {
    let mut msg = with_iana(v6::Message::new(MessageType::Request), reconf);
    msg.opts_mut().insert(DhcpOption::ClientId(client_duid()));
    msg.opts_mut().insert(DhcpOption::ServerId(SERVER_DUID.to_vec()));
    msg
}

#[test]
fn solicit_advertise_has_no_authentication_option() {
    let mut status = make_status();
    let result = run(&mut status, &solicit(true));
    let reply = decode_reply(&result);

    assert_eq!(reply.msg_type(), MessageType::Advertise);
    assert!(reply.opts().get(OptionCode::IANA).is_some());
    assert!(
        auth_option(&reply).is_none(),
        "RFC 8415 §20.4.2: reconfigure key must only be delivered in Reply"
    );
}

#[test]
fn request_reply_carries_rkap_key() {
    let mut status = make_status();
    let result = run(&mut status, &request(true));
    let reply = decode_reply(&result);

    assert_eq!(reply.msg_type(), MessageType::Reply);
    let auth = auth_option(&reply).expect("Reply should carry the reconfigure key");
    assert_eq!(auth.proto, 3);
    assert_eq!(auth.algo, 1);
    assert_eq!(auth.rdm, 0);
    assert_eq!(auth.info.len(), 17);
    assert_eq!(auth.info[0], 1);
    assert!(!result.allocated_ips.is_empty());
}

#[test]
fn request_without_reconf_accept_omits_auth() {
    let mut status = make_status();
    let result = run(&mut status, &request(false));

    assert!(auth_option(&decode_reply(&result)).is_none());
}

#[test]
fn info_request_reply_auth_depends_on_reconf_accept() {
    let mut status = make_status();
    run(&mut status, &request(true));

    let mut info = v6::Message::new(MessageType::InformationRequest);
    info.opts_mut().insert(DhcpOption::ClientId(client_duid()));
    info.opts_mut().insert(DhcpOption::ReconfAccept);
    assert!(auth_option(&decode_reply(&run(&mut status, &info))).is_some());

    let mut info = v6::Message::new(MessageType::InformationRequest);
    info.opts_mut().insert(DhcpOption::ClientId(client_duid()));
    assert!(auth_option(&decode_reply(&run(&mut status, &info))).is_none());
}

#[test]
fn release_and_confirm_replies_have_no_auth() {
    let mut status = make_status();
    run(&mut status, &request(true));

    let mut release = v6::Message::new(MessageType::Release);
    release.opts_mut().insert(DhcpOption::ClientId(client_duid()));
    release.opts_mut().insert(DhcpOption::ServerId(SERVER_DUID.to_vec()));
    release.opts_mut().insert(DhcpOption::ReconfAccept);
    let reply = decode_reply(&run(&mut status, &release));
    assert_eq!(reply.msg_type(), MessageType::Reply);
    assert!(auth_option(&reply).is_none());

    let mut confirm = with_iana(v6::Message::new(MessageType::Confirm), true);
    confirm.opts_mut().insert(DhcpOption::ClientId(client_duid()));
    let reply = decode_reply(&run(&mut status, &confirm));
    assert_eq!(reply.msg_type(), MessageType::Reply);
    assert!(auth_option(&reply).is_none());
}
