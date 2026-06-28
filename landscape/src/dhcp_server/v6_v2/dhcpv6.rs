use std::net::{Ipv6Addr, SocketAddr};

use dhcproto::v6::{self, Authentication, IAAddr, IAPrefix, Status, StatusCode, IANA, IAPD};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use landscape_common::net::MacAddr;
use landscape_common::net_proto::udp::dhcp::DhcpV6MessageType;

use super::{Ipv6LanReplyParams, Ipv6ServerStatus};

// ── Result types ───────────────────────────────────────────────────────────

pub struct Dhcpv6Result {
    pub reply_bytes: Option<Vec<u8>>,
    pub reply_dst: SocketAddr,
    pub allocated_ips: Vec<(MacAddr, Ipv6Addr)>,
    pub expired_ips: Vec<(MacAddr, Ipv6Addr)>,
    pub pd_route_changes: Vec<PdRouteChange>,
}

pub struct PdRouteChange {
    pub duid: Vec<u8>,
    pub old_routes: Vec<(Ipv6Addr, u8)>,
    pub new_routes: Vec<(Ipv6Addr, u8)>,
    pub sub_index: u32,
    pub valid_time: u32,
}

// ── Main entry ─────────────────────────────────────────────────────────────

pub fn process_dhcpv6_msg(
    status: &mut Ipv6ServerStatus,
    msg_bytes: &[u8],
    client_addr: SocketAddr,
    server_duid: &[u8],
    params: &Ipv6LanReplyParams,
    dns_servers: &[Ipv6Addr],
) -> Dhcpv6Result {
    let empty = || Dhcpv6Result {
        reply_bytes: None,
        reply_dst: client_addr,
        allocated_ips: Vec::new(),
        expired_ips: Vec::new(),
        pd_route_changes: Vec::new(),
    };

    let msg = match v6::Message::decode(&mut Decoder::new(msg_bytes)) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("DHCPv6 decode error: {e:?}");
            return empty();
        }
    };

    let client_duid = match extract_duid(&msg) {
        Some(d) => d,
        None => {
            tracing::warn!("DHCPv6 message without ClientId");
            return empty();
        }
    };

    let mac = extract_mac_from_duid(&client_duid).or_else(|| match client_addr {
        SocketAddr::V6(ref v6) => status.lookup_mac_by_link_local(*v6.ip()),
        _ => None,
    });
    let iana_id = extract_iana_id(&msg);
    let iapd_id = extract_iapd_id(&msg);

    match msg.msg_type() {
        DhcpV6MessageType::Solicit => handle_solicit(
            status,
            &msg,
            &client_duid,
            iana_id,
            iapd_id,
            mac,
            server_duid,
            params,
            dns_servers,
            client_addr,
        ),

        DhcpV6MessageType::Request | DhcpV6MessageType::Renew | DhcpV6MessageType::Rebind => {
            handle_request_or_renew(
                status,
                &msg,
                &client_duid,
                iana_id,
                iapd_id,
                mac,
                server_duid,
                client_addr,
                params,
                dns_servers,
            )
        }

        DhcpV6MessageType::Release => {
            handle_release(status, &msg, &client_duid, mac, server_duid, client_addr)
        }

        DhcpV6MessageType::Decline => handle_decline(status, &client_duid, mac, client_addr),

        DhcpV6MessageType::Confirm => {
            handle_confirm(status, &msg, &client_duid, mac, server_duid, client_addr)
        }

        DhcpV6MessageType::InformationRequest => {
            handle_info_request(status, &msg, &client_duid, server_duid, dns_servers, client_addr)
        }

        other => {
            tracing::debug!("DHCPv6 ignoring message type: {:?}", other);
            empty()
        }
    }
}

// ── Solicit → Advertise ─────────────────────────────────────────────────────

fn handle_solicit(
    status: &mut Ipv6ServerStatus,
    msg: &v6::Message,
    client_duid: &[u8],
    iana_id: Option<u32>,
    iapd_id: Option<u32>,
    mac: Option<MacAddr>,
    server_duid: &[u8],
    params: &Ipv6LanReplyParams,
    dns_servers: &[Ipv6Addr],
    client_addr: SocketAddr,
) -> Dhcpv6Result {
    if iana_id.is_some() {
        status.offer_na(client_duid, mac, None);
    }
    if iapd_id.is_some() {
        status.offer_pd(client_duid);
    }

    let mut reply = v6::Message::new(DhcpV6MessageType::Advertise);
    reply.set_xid(msg.xid());
    reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid.to_vec()));
    reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));
    reply.opts_mut().insert(v6::DhcpOption::Preference(255));

    if let Some(id) = iana_id {
        reply.opts_mut().insert(v6::DhcpOption::IANA(build_iana_options(
            status,
            client_duid,
            id,
            params,
            true,
        )));
    }

    if let Some(id) = iapd_id {
        reply.opts_mut().insert(v6::DhcpOption::IAPD(build_iapd_options(
            status,
            client_duid,
            id,
            params,
            true,
        )));
    }

    if !dns_servers.is_empty() {
        reply.opts_mut().insert(v6::DhcpOption::DomainNameServers(dns_servers.to_vec()));
    }

    // RFC 8415 §20.4.2: include reconfigure key in Reply/Advertise
    if let Some(key) = status.get_reconfigure_key(client_duid) {
        let mut info = vec![1u8];
        info.extend_from_slice(&key);
        reply.opts_mut().insert(v6::DhcpOption::Authentication(Authentication {
            proto: 3,
            algo: 0,
            rdm: 0,
            replay_detection: 0,
            info,
        }));
    }

    let reply_bytes = encode_reply(&reply);

    Dhcpv6Result {
        reply_bytes,
        reply_dst: client_addr,
        allocated_ips: Vec::new(),
        expired_ips: Vec::new(),
        pd_route_changes: Vec::new(),
    }
}

// ── Request / Renew / Rebind → Reply ────────────────────────────────────────

fn handle_request_or_renew(
    status: &mut Ipv6ServerStatus,
    msg: &v6::Message,
    client_duid: &[u8],
    iana_id: Option<u32>,
    iapd_id: Option<u32>,
    mac: Option<MacAddr>,
    server_duid: &[u8],
    client_addr: SocketAddr,
    params: &Ipv6LanReplyParams,
    dns_servers: &[Ipv6Addr],
) -> Dhcpv6Result {
    // Verify ServerId (skip for Rebind per RFC 8415)
    if msg.msg_type() != DhcpV6MessageType::Rebind {
        if !verify_server_id(msg, server_duid) {
            return Dhcpv6Result {
                reply_bytes: None,
                reply_dst: client_addr,
                allocated_ips: Vec::new(),
                expired_ips: Vec::new(),
                pd_route_changes: Vec::new(),
            };
        }
    }

    let mut allocated_ips: Vec<(MacAddr, Ipv6Addr)> = Vec::new();
    let mut pd_route_changes: Vec<PdRouteChange> = Vec::new();

    // ── IA_NA ──
    if iana_id.is_some() {
        let prev_ips = status.get_na_addresses(client_duid);

        // Always call to pick up potential static binding changes
        status.offer_na(client_duid, mac, None);
        status.confirm_na(client_duid);

        if let Some(client_mac) = mac {
            for ip in &status.get_na_addresses(client_duid) {
                if !prev_ips.contains(ip) {
                    allocated_ips.push((client_mac, *ip));
                }
            }
        }
    }

    // ── IA_PD ──
    if iapd_id.is_some() {
        let prev_prefix = status.get_pd_prefix(client_duid);
        let prev_routes: Vec<(Ipv6Addr, u8)> = prev_prefix.iter().map(|(p, l)| (*p, *l)).collect();

        status.offer_pd(client_duid);
        status.confirm_pd(client_duid);

        let new_prefix = status.get_pd_prefix(client_duid);
        if new_prefix != prev_prefix {
            // Old routes to remove, new routes to add
            let client_ll = match client_addr {
                SocketAddr::V6(v6) => *v6.ip(),
                _ => Ipv6Addr::UNSPECIFIED,
            };

            let new_routes: Vec<(Ipv6Addr, u8)> =
                new_prefix.iter().map(|(p, l)| (*p, *l)).collect();

            pd_route_changes.push(PdRouteChange {
                duid: client_duid.to_vec(),
                old_routes: prev_routes.clone(),
                new_routes: new_routes.clone(),
                sub_index: status.pd_lease_sub_index(client_duid).unwrap_or(0),
                valid_time: params.pd_valid_lifetime,
            });

            // Update lease's active_routes and client_addr
            let _ = status.update_pd_routes(client_duid, client_ll, new_routes.clone());
        }
    }

    // ── Build Reply ──
    let mut reply = v6::Message::new(DhcpV6MessageType::Reply);
    reply.set_xid(msg.xid());
    reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid.to_vec()));
    reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));

    if let Some(id) = iana_id {
        let mut iana = build_iana_options(status, client_duid, id, params, false);

        // RFC 8415 §18.4.3: deprecate old addresses on prefix change (Rebind/Renew)
        if msg.msg_type() == DhcpV6MessageType::Rebind || msg.msg_type() == DhcpV6MessageType::Renew
        {
            let server_addrs = status.get_na_addresses(client_duid);
            if let Some(v6::DhcpOption::IANA(client_iana)) = msg.opts().get(v6::OptionCode::IANA) {
                if let Some(ia_addrs) = client_iana.opts.get_all(v6::OptionCode::IAAddr) {
                    for ia_opt in ia_addrs {
                        if let v6::DhcpOption::IAAddr(ia_addr) = ia_opt {
                            if !server_addrs.contains(&ia_addr.addr) {
                                iana.opts.insert(v6::DhcpOption::IAAddr(IAAddr {
                                    addr: ia_addr.addr,
                                    preferred_life: 0,
                                    valid_life: 0,
                                    opts: v6::DhcpOptions::new(),
                                }));
                            }
                        }
                    }
                }
            }
        }

        reply.opts_mut().insert(v6::DhcpOption::IANA(iana));
    }

    if let Some(id) = iapd_id {
        let mut iapd = build_iapd_options(status, client_duid, id, params, false);

        // RFC 8415 §18.4.3: deprecate old prefixes on prefix change
        if msg.msg_type() == DhcpV6MessageType::Rebind || msg.msg_type() == DhcpV6MessageType::Renew
        {
            let server_prefix = status.get_pd_prefix(client_duid);
            if let Some(v6::DhcpOption::IAPD(client_iapd)) = msg.opts().get(v6::OptionCode::IAPD) {
                if let Some(ia_prefixes) = client_iapd.opts.get_all(v6::OptionCode::IAPrefix) {
                    for ia_opt in ia_prefixes {
                        if let v6::DhcpOption::IAPrefix(ia_prefix) = ia_opt {
                            let still_valid = server_prefix
                                .map(|(p, l)| p == ia_prefix.prefix_ip && l == ia_prefix.prefix_len)
                                .unwrap_or(false);
                            if !still_valid {
                                iapd.opts.insert(v6::DhcpOption::IAPrefix(IAPrefix {
                                    preferred_lifetime: 0,
                                    valid_lifetime: 0,
                                    prefix_len: ia_prefix.prefix_len,
                                    prefix_ip: ia_prefix.prefix_ip,
                                    opts: v6::DhcpOptions::new(),
                                }));
                            }
                        }
                    }
                }
            }
        }

        reply.opts_mut().insert(v6::DhcpOption::IAPD(iapd));
    }

    if !dns_servers.is_empty() {
        reply.opts_mut().insert(v6::DhcpOption::DomainNameServers(dns_servers.to_vec()));
    }

    status.consume_prev_suffix(client_duid);

    // RFC 8415 §20.4.2: include reconfigure key in Reply
    if let Some(key) = status.get_reconfigure_key(client_duid) {
        let mut info = vec![1u8];
        info.extend_from_slice(&key);
        reply.opts_mut().insert(v6::DhcpOption::Authentication(Authentication {
            proto: 3,
            algo: 0,
            rdm: 0,
            replay_detection: 0,
            info,
        }));
    }

    let reply_bytes = encode_reply(&reply);

    Dhcpv6Result {
        reply_bytes,
        reply_dst: client_addr,
        allocated_ips,
        expired_ips: Vec::new(),
        pd_route_changes,
    }
}

// ── Release ─────────────────────────────────────────────────────────────────

fn handle_release(
    status: &mut Ipv6ServerStatus,
    msg: &v6::Message,
    client_duid: &[u8],
    mac: Option<MacAddr>,
    server_duid: &[u8],
    client_addr: SocketAddr,
) -> Dhcpv6Result {
    if !verify_server_id(msg, server_duid) {
        return empty_result(client_addr);
    }

    let mut expired_ips: Vec<(MacAddr, Ipv6Addr)> = Vec::new();
    let mut pd_route_changes: Vec<PdRouteChange> = Vec::new();

    if let Some(expired_na) = status.release_na(client_duid) {
        if let Some(m) = mac.or(expired_na.mac) {
            for ip in status.suffix_to_addrs(expired_na.suffix) {
                expired_ips.push((m, ip));
            }
        }
    }

    if let Some(released) = status.release_pd(client_duid) {
        pd_route_changes.push(PdRouteChange {
            duid: client_duid.to_vec(),
            old_routes: released.active_routes,
            new_routes: Vec::new(),
            sub_index: released.sub_index,
            valid_time: 0,
        });
    }

    let mut reply = v6::Message::new(DhcpV6MessageType::Reply);
    reply.set_xid(msg.xid());
    reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid.to_vec()));
    reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));
    reply.opts_mut().insert(v6::DhcpOption::StatusCode(StatusCode {
        status: Status::Success,
        msg: String::new(),
    }));

    // RFC 8415 §20.4.2: include reconfigure key in Reply
    if let Some(key) = status.get_reconfigure_key(client_duid) {
        let mut info = vec![1u8];
        info.extend_from_slice(&key);
        reply.opts_mut().insert(v6::DhcpOption::Authentication(Authentication {
            proto: 3,
            algo: 0,
            rdm: 0,
            replay_detection: 0,
            info,
        }));
    }

    Dhcpv6Result {
        reply_bytes: encode_reply(&reply),
        reply_dst: client_addr,
        allocated_ips: Vec::new(),
        expired_ips,
        pd_route_changes,
    }
}

// ── Decline ─────────────────────────────────────────────────────────────────

fn handle_decline(
    status: &mut Ipv6ServerStatus,
    client_duid: &[u8],
    mac: Option<MacAddr>,
    client_addr: SocketAddr,
) -> Dhcpv6Result {
    let mut expired_ips: Vec<(MacAddr, Ipv6Addr)> = Vec::new();

    if let Some(expired_na) = status.release_na(client_duid) {
        if let Some(m) = mac.or(expired_na.mac) {
            for ip in status.suffix_to_addrs(expired_na.suffix) {
                expired_ips.push((m, ip));
            }
        }
    }

    Dhcpv6Result {
        reply_bytes: None,
        reply_dst: client_addr,
        allocated_ips: Vec::new(),
        expired_ips,
        pd_route_changes: Vec::new(),
    }
}

// ── Confirm ─────────────────────────────────────────────────────────────────

fn handle_confirm(
    status: &Ipv6ServerStatus,
    msg: &v6::Message,
    client_duid: &[u8],
    mac: Option<MacAddr>,
    server_duid: &[u8],
    client_addr: SocketAddr,
) -> Dhcpv6Result {
    let mut all_on_link = true;

    if let Some(v6::DhcpOption::IANA(client_iana)) = msg.opts().get(v6::OptionCode::IANA) {
        if let Some(ia_addrs) = client_iana.opts.get_all(v6::OptionCode::IAAddr) {
            for ia_opt in ia_addrs {
                if let v6::DhcpOption::IAAddr(ia_addr) = ia_opt {
                    match status.check_address_owner(ia_addr.addr, client_duid, mac) {
                        super::NaAddressCheck::Owned => {}
                        _ => {
                            all_on_link = false;
                            break;
                        }
                    }
                }
            }
        }
    }

    let status_code = if all_on_link {
        StatusCode { status: Status::Success, msg: String::new() }
    } else {
        StatusCode {
            status: Status::NotOnLink,
            msg: "Address not appropriate for link".to_string(),
        }
    };

    let mut reply = v6::Message::new(DhcpV6MessageType::Reply);
    reply.set_xid(msg.xid());
    reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid.to_vec()));
    reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));
    reply.opts_mut().insert(v6::DhcpOption::StatusCode(status_code));

    // RFC 8415 §20.4.2: include reconfigure key in Reply
    if let Some(key) = status.get_reconfigure_key(client_duid) {
        let mut info = vec![1u8];
        info.extend_from_slice(&key);
        reply.opts_mut().insert(v6::DhcpOption::Authentication(Authentication {
            proto: 3,
            algo: 0,
            rdm: 0,
            replay_detection: 0,
            info,
        }));
    }

    Dhcpv6Result {
        reply_bytes: encode_reply(&reply),
        reply_dst: client_addr,
        allocated_ips: Vec::new(),
        expired_ips: Vec::new(),
        pd_route_changes: Vec::new(),
    }
}

// ── Information-request ─────────────────────────────────────────────────────

fn handle_info_request(
    status: &Ipv6ServerStatus,
    msg: &v6::Message,
    client_duid: &[u8],
    server_duid: &[u8],
    dns_servers: &[Ipv6Addr],
    client_addr: SocketAddr,
) -> Dhcpv6Result {
    let mut reply = v6::Message::new(DhcpV6MessageType::Reply);
    reply.set_xid(msg.xid());
    reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid.to_vec()));
    reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));

    if !dns_servers.is_empty() {
        reply.opts_mut().insert(v6::DhcpOption::DomainNameServers(dns_servers.to_vec()));
    }

    // RFC 8415 §20.4.2: include reconfigure key in Reply
    if let Some(key) = status.get_reconfigure_key(client_duid) {
        let mut info = vec![1u8];
        info.extend_from_slice(&key);
        reply.opts_mut().insert(v6::DhcpOption::Authentication(Authentication {
            proto: 3,
            algo: 0,
            rdm: 0,
            replay_detection: 0,
            info,
        }));
    }

    Dhcpv6Result {
        reply_bytes: encode_reply(&reply),
        reply_dst: client_addr,
        allocated_ips: Vec::new(),
        expired_ips: Vec::new(),
        pd_route_changes: Vec::new(),
    }
}

// ── IANA / IAPD builders ────────────────────────────────────────────────────

fn build_iana_options(
    status: &Ipv6ServerStatus,
    client_duid: &[u8],
    iana_id: u32,
    params: &Ipv6LanReplyParams,
    is_offer: bool,
) -> IANA {
    let mut iana_opts = v6::DhcpOptions::new();
    let addrs = status.get_na_addresses(client_duid);

    if addrs.is_empty() {
        iana_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
            status: Status::NoAddrsAvail,
            msg: "IA_NA not configured or allocation failed".to_string(),
        }));
    } else {
        let (pref, valid) = if is_offer {
            (params.na_preferred_lifetime.min(120), 120)
        } else {
            (params.na_preferred_lifetime, params.na_valid_lifetime)
        };

        for ip in &addrs {
            iana_opts.insert(v6::DhcpOption::IAAddr(IAAddr {
                addr: *ip,
                preferred_life: pref,
                valid_life: valid,
                opts: v6::DhcpOptions::new(),
            }));
        }
        iana_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
            status: Status::Success,
            msg: String::new(),
        }));
    }

    IANA {
        id: iana_id,
        t1: params.na_preferred_lifetime / 2,
        t2: (params.na_preferred_lifetime * 4) / 5,
        opts: iana_opts,
    }
}

fn build_iapd_options(
    status: &Ipv6ServerStatus,
    client_duid: &[u8],
    iapd_id: u32,
    params: &Ipv6LanReplyParams,
    is_offer: bool,
) -> IAPD {
    let mut iapd_opts = v6::DhcpOptions::new();

    if let Some((prefix, prefix_len)) = status.get_pd_prefix(client_duid) {
        let (pref, valid) = if is_offer {
            (params.pd_preferred_lifetime.min(120), 120)
        } else {
            (params.pd_preferred_lifetime, params.pd_valid_lifetime)
        };

        iapd_opts.insert(v6::DhcpOption::IAPrefix(IAPrefix {
            preferred_lifetime: pref,
            valid_lifetime: valid,
            prefix_len,
            prefix_ip: prefix,
            opts: v6::DhcpOptions::new(),
        }));
        iapd_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
            status: Status::Success,
            msg: String::new(),
        }));
    } else {
        iapd_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
            status: Status::NoPrefixAvail,
            msg: "IA_PD not configured or no prefix available".to_string(),
        }));
    }

    IAPD {
        id: iapd_id,
        t1: params.pd_preferred_lifetime / 2,
        t2: (params.pd_preferred_lifetime * 4) / 5,
        opts: iapd_opts,
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn extract_duid(msg: &v6::Message) -> Option<Vec<u8>> {
    match msg.opts().get(v6::OptionCode::ClientId) {
        Some(v6::DhcpOption::ClientId(duid)) => Some(duid.clone()),
        _ => None,
    }
}

fn extract_iana_id(msg: &v6::Message) -> Option<u32> {
    msg.opts().get(v6::OptionCode::IANA).and_then(|opt| {
        if let v6::DhcpOption::IANA(iana) = opt {
            Some(iana.id)
        } else {
            None
        }
    })
}

fn extract_iapd_id(msg: &v6::Message) -> Option<u32> {
    msg.opts().get(v6::OptionCode::IAPD).and_then(|opt| {
        if let v6::DhcpOption::IAPD(iapd) = opt {
            Some(iapd.id)
        } else {
            None
        }
    })
}

fn extract_mac_from_duid(duid: &[u8]) -> Option<MacAddr> {
    if duid.len() < 4 {
        return None;
    }
    let duid_type = u16::from_be_bytes([duid[0], duid[1]]);
    match duid_type {
        // DUID-LLT (type 1): 2B type + 2B hw + 4B time + 6B MAC
        1 => {
            if duid.len() >= 14 {
                let mac_bytes: [u8; 6] = duid[8..14].try_into().ok()?;
                Some(MacAddr::from(mac_bytes))
            } else {
                None
            }
        }
        // DUID-LL (type 3): 2B type + 2B hw + 6B MAC
        3 => {
            if duid.len() >= 10 {
                let mac_bytes: [u8; 6] = duid[4..10].try_into().ok()?;
                Some(MacAddr::from(mac_bytes))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn verify_server_id(msg: &v6::Message, server_duid: &[u8]) -> bool {
    match msg.opts().get(v6::OptionCode::ServerId) {
        Some(v6::DhcpOption::ServerId(sid)) => sid == server_duid,
        _ => false,
    }
}

fn encode_reply(msg: &v6::Message) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    match msg.encode(&mut e) {
        Ok(()) => Some(buf),
        Err(e) => {
            tracing::error!("DHCPv6 encode error: {e:?}");
            None
        }
    }
}

fn empty_result(dst: SocketAddr) -> Dhcpv6Result {
    Dhcpv6Result {
        reply_bytes: None,
        reply_dst: dst,
        allocated_ips: Vec::new(),
        expired_ips: Vec::new(),
        pd_route_changes: Vec::new(),
    }
}
