use bytes::BytesMut;
use landscape_common::net::MacAddr;
use landscape_common::net_proto::icmpv6::messages::{Icmpv6Message, RouterAdvertisement};
use landscape_common::net_proto::icmpv6::options::{IcmpV6Option, IcmpV6Options};
use landscape_common::net_proto::NetProtoCodec;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

use super::{Ipv6LanReplyParams, Ipv6ServerStatus, SlaacResult};

pub static ICMPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1);

// TODO(Plan B): handle_ns_msg() — parse NeighborSolicitation, check na_owners_by_suffix,
// reply with solicited NA for DAD defense. NeighborSolicitation is currently
// Unassigned in Icmpv6Message; needs a variant in landscape-common.

pub fn parse(bytes: &[u8]) -> Option<Icmpv6Message> {
    let mut buf = BytesMut::from(bytes);
    match Icmpv6Message::decode(&mut buf) {
        Ok(Some(msg)) => Some(msg),
        Ok(None) => None,
        Err(e) => {
            tracing::error!("ICMPv6 decode error: {e:?}");
            None
        }
    }
}

pub fn build_ra(
    status: &Ipv6ServerStatus,
    params: &Ipv6LanReplyParams,
    mac_addr: &MacAddr,
    icmp_ad_interval_ms: u32,
) -> Icmpv6Message {
    let mut opts = IcmpV6Options::new();
    opts.insert(IcmpV6Option::source_link_layer_address(&mac_addr.octets()));

    // RA-eligible prefixes with autonomous flag from params
    let autonomous = params.ra_autonomous;
    for entry in status.ra_entries() {
        opts.insert(IcmpV6Option::prefix_information(
            entry.prefix_len,
            entry.valid_lifetime,
            entry.preferred_lifetime,
            entry.prefix,
            autonomous,
        ));
        opts.insert(IcmpV6Option::route_information(entry.prefix_len, entry.prefix));
    }

    // A=0: on-link only prefixes (na_entries not in ra_entries)
    // RFC 4861 4.6.2: preferred_lifetime MUST be zero when A=0
    for (prefix, prefix_len) in onlink_only_prefixes(status) {
        opts.insert(IcmpV6Option::prefix_information(
            prefix_len,
            params.ra_valid_lifetime,
            0,
            prefix,
            false,
        ));
        opts.insert(IcmpV6Option::route_information(prefix_len, prefix));
    }

    // DNS servers: link-local + static + dynamic
    opts.insert(IcmpV6Option::recursive_dns_server(600, mac_addr.to_ipv6_link_local()));
    for ip in status.dns_servers().iter() {
        opts.insert(IcmpV6Option::recursive_dns_server(600, ip));
    }

    opts.insert(IcmpV6Option::mtu(1500));
    opts.insert(IcmpV6Option::advertisement_interval(icmp_ad_interval_ms));

    Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(params.ra_flags, opts))
}

fn onlink_only_prefixes(status: &Ipv6ServerStatus) -> Vec<(Ipv6Addr, u8)> {
    status
        .na_entries()
        .iter()
        .filter(|na| {
            !status
                .ra_entries()
                .iter()
                .any(|ra| ra.prefix == na.prefix && ra.prefix_len == na.prefix_len)
        })
        .map(|e| (e.prefix, e.prefix_len))
        .collect()
}

pub enum SlaacActionResult {
    None,
    Allocated { mac: MacAddr, ip: Ipv6Addr },
    Conflict { mac: MacAddr, ip: Ipv6Addr },
}

pub fn handle_na(data: &[u8], status: &mut Ipv6ServerStatus) -> SlaacActionResult {
    // TODO(Plan B): active DAD defense — send solicited NA upon NA address conflict
    let msg = match parse(data) {
        Some(Icmpv6Message::NeighborAdvertisement(na)) => na,
        _ => return SlaacActionResult::None,
    };

    let mac = match msg.opts.get(2) {
        Some(IcmpV6Option::TargetLinkLayerAddress { addr, .. }) => MacAddr::from(*addr),
        _ => {
            tracing::warn!("NeighborAdvertisement without TargetLinkLayerAddress");
            return SlaacActionResult::None;
        }
    };

    let ip = msg.target_addr();

    match status.record_slaac_addr(mac, ip) {
        SlaacResult::Recorded => SlaacActionResult::Allocated { mac, ip },
        SlaacResult::Conflict => {
            tracing::warn!("SLAAC conflict: ip={ip} mac={mac} suffix already NA-owned",);
            SlaacActionResult::Conflict { mac, ip }
        }
    }
}

/// Build a deprecation RA with all prefix lifetimes set to zero.
pub fn build_deprecation_ra(
    status: &Ipv6ServerStatus,
    mac_addr: &MacAddr,
    ra_flags: u8,
) -> Icmpv6Message {
    let mut opts = IcmpV6Options::new();
    opts.insert(IcmpV6Option::source_link_layer_address(&mac_addr.octets()));

    let mut has_prefix = false;

    for entry in status.ra_entries() {
        opts.insert(IcmpV6Option::prefix_information(entry.prefix_len, 0, 0, entry.prefix, false));
        has_prefix = true;
    }

    for (prefix, prefix_len) in onlink_only_prefixes(status) {
        opts.insert(IcmpV6Option::prefix_information(prefix_len, 0, 0, prefix, false));
        has_prefix = true;
    }

    if !has_prefix {
        return Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(ra_flags, opts));
    }

    opts.insert(IcmpV6Option::recursive_dns_server(600, mac_addr.to_ipv6_link_local()));
    opts.insert(IcmpV6Option::mtu(1500));

    Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(ra_flags, opts))
}

pub async fn send_msg(sender: &Arc<UdpSocket>, msg: &Icmpv6Message, dst: SocketAddr) -> bool {
    let mut buf = BytesMut::new();
    if let Err(e) = NetProtoCodec::encode(msg, &mut buf) {
        tracing::error!("ICMPv6 encode error: {e:?}");
        return false;
    }
    match sender.send_to(&buf, &dst).await {
        Ok(len) => {
            tracing::debug!("ICMPv6 sent {len} bytes to {dst}");
            true
        }
        Err(e) => {
            tracing::error!("ICMPv6 send error: {e:?}");
            false
        }
    }
}
