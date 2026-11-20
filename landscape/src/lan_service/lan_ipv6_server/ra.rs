use std::collections::HashSet;
use std::net::Ipv6Addr;

use landscape_common::{
    net::MacAddr,
    net_proto::icmpv6::{
        messages::{Icmpv6Message, RouterAdvertisement},
        options::{IcmpV6Option, IcmpV6Options},
    },
};

use super::{Ipv6LanReplyParams, SubnetState};

/// Build a deprecation RA for removed subnets (e.g. during PPPoE PD rotation),
/// withdrawing their PIO (`valid=0, preferred=0`), RIO (`route_lifetime=0`),
/// and — when GUA RDNSS advertising is enabled — any removed GUA RDNSS servers
/// (`lifetime=0`) while keeping the router's stable link-local RDNSS active.
pub fn build_deprecation_ra_from_subnets(
    removed: &[SubnetState],
    removed_dns: &[Ipv6Addr],
    mac_addr: &MacAddr,
    params: &Ipv6LanReplyParams,
) -> Icmpv6Message {
    let mut opts = IcmpV6Options::new();
    opts.insert(IcmpV6Option::source_link_layer_address(&mac_addr.octets()));

    let mut has_prefix = false;

    for sn in removed {
        if sn.has_ra {
            opts.insert(IcmpV6Option::prefix_information(
                sn.sub_prefix_len,
                0,
                0,
                sn.sub_prefix,
                params.ra_autonomous,
            ));
            opts.insert(IcmpV6Option::route_information_with_lifetime(
                sn.sub_prefix_len,
                0,
                sn.sub_prefix,
            ));
            has_prefix = true;
        } else if sn.is_na {
            opts.insert(IcmpV6Option::prefix_information(
                sn.sub_prefix_len,
                0,
                0,
                sn.sub_prefix,
                false,
            ));
            opts.insert(IcmpV6Option::route_information_with_lifetime(
                sn.sub_prefix_len,
                0,
                sn.sub_prefix,
            ));
            has_prefix = true;
        }
    }

    let link_local = mac_addr.to_ipv6_link_local();
    let mut withdrawn_dns: Vec<Ipv6Addr> = Vec::new();
    if !params.rdnss_link_local_only {
        let mut seen = HashSet::new();
        seen.insert(link_local);
        for &ip in removed_dns {
            if seen.insert(ip) {
                withdrawn_dns.push(ip);
            }
        }
        for sn in removed {
            if sn.has_router() && seen.insert(sn.sub_router) {
                withdrawn_dns.push(sn.sub_router);
            }
        }
    }

    if !has_prefix && withdrawn_dns.is_empty() {
        return Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(params.ra_flags, opts));
    }

    let rdnss_lifetime = params.valid_lifetime.max(600);
    opts.insert(IcmpV6Option::recursive_dns_server(rdnss_lifetime, link_local));
    for ip in withdrawn_dns {
        opts.insert(IcmpV6Option::recursive_dns_server(0, ip));
    }
    opts.insert(IcmpV6Option::mtu(1500));

    Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(params.ra_flags, opts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan_service::lan_ipv6_server::SubnetSource;
    use bytes::BytesMut;
    use landscape_common::net_proto::NetProtoCodec;
    use uuid::Uuid;

    fn sample_pd_subnet(prefix: &str, router: &str) -> SubnetState {
        SubnetState {
            group_id: "lan-v6".to_string(),
            sub_prefix: prefix.parse().unwrap(),
            sub_prefix_len: 64,
            sub_router: router.parse().unwrap(),
            pool_index: 1,
            ra_preferred_lifetime: 300,
            ra_valid_lifetime: 600,
            is_na: false,
            has_ra: true,
            source: SubnetSource::Pd { link_id: Uuid::nil() },
            pd_config: None,
        }
    }

    fn decode_ra(msg: &Icmpv6Message) -> RouterAdvertisement {
        let mut buf = BytesMut::new();
        NetProtoCodec::encode(msg, &mut buf).expect("encode RA");
        RouterAdvertisement::from_wire_bytes(&buf).expect("decode wire RA")
    }

    #[test]
    fn pd_rotation_deprecation_link_local_only_withdraws_pio_and_rio_without_gua_rdnss() {
        let mac = MacAddr::from([0x02, 0x00, 0x00, 0x12, 0x34, 0x56]);
        let link_local = mac.to_ipv6_link_local();
        let old_prefix: Ipv6Addr = "2001:db8:1:1::".parse().unwrap();
        let removed = vec![sample_pd_subnet("2001:db8:1:1::", "2001:db8:1:1::1")];
        let params = Ipv6LanReplyParams {
            preferred_lifetime: 300,
            valid_lifetime: 600,
            ra_flags: 0,
            ra_autonomous: true,
            rdnss_link_local_only: true,
        };

        let msg = build_deprecation_ra_from_subnets(
            &removed,
            &["2001:db8:1:1::1".parse().unwrap()],
            &mac,
            &params,
        );
        let ra = decode_ra(&msg);

        assert_eq!(ra.router_lifetime, 1800, "router stays active on PD rotation");

        let pios = ra.opts.get_all(3);
        assert_eq!(pios.len(), 1);
        assert!(matches!(
            pios[0],
            IcmpV6Option::PrefixInformation {
                prefix_length: 64,
                valid_lifetime: 0,
                preferred_lifetime: 0,
                prefix,
                ..
            } if *prefix == old_prefix.octets()
        ));

        let rios = ra.opts.get_all(24);
        assert_eq!(rios.len(), 1);
        assert!(matches!(
            rios[0],
            IcmpV6Option::RouteInformation {
                prefix_length: 64,
                route_lifetime: 0,
                prefix,
                ..
            } if prefix.as_slice() == old_prefix.octets()
        ));

        let rdnss = ra.opts.get_all(25);
        assert_eq!(rdnss.len(), 1, "link-local-only mode must not emit GUA RDNSS");
        assert!(matches!(
            rdnss[0],
            IcmpV6Option::RecursiveDNSServer { lifetime: 600, addresses, .. }
                if addresses.as_slice() == link_local.octets()
        ));
    }

    #[test]
    fn pd_rotation_deprecation_dual_rdnss_withdraws_old_gua_rdnss_and_rio_with_zero_lifetime() {
        let mac = MacAddr::from([0x02, 0x00, 0x00, 0x12, 0x34, 0x56]);
        let link_local = mac.to_ipv6_link_local();
        let old_prefix: Ipv6Addr = "2001:db8:1:1::".parse().unwrap();
        let old_gua_dns: Ipv6Addr = "2001:db8:1:1::1".parse().unwrap();
        let removed = vec![sample_pd_subnet("2001:db8:1:1::", "2001:db8:1:1::1")];
        let params = Ipv6LanReplyParams {
            preferred_lifetime: 300,
            valid_lifetime: 600,
            ra_flags: 0,
            ra_autonomous: true,
            rdnss_link_local_only: false,
        };

        let msg = build_deprecation_ra_from_subnets(&removed, &[old_gua_dns], &mac, &params);
        let ra = decode_ra(&msg);

        assert_eq!(ra.router_lifetime, 1800);

        let rios = ra.opts.get_all(24);
        assert_eq!(rios.len(), 1);
        assert!(matches!(
            rios[0],
            IcmpV6Option::RouteInformation {
                prefix_length: 64,
                route_lifetime: 0,
                prefix,
                ..
            } if prefix.as_slice() == old_prefix.octets()
        ));

        let rdnss = ra.opts.get_all(25);
        assert_eq!(rdnss.len(), 2, "must keep link-local RDNSS and withdraw old GUA RDNSS");
        assert!(rdnss.iter().any(|opt| matches!(
            opt,
            IcmpV6Option::RecursiveDNSServer { lifetime: 600, addresses, .. }
                if addresses.as_slice() == link_local.octets()
        )));
        assert!(rdnss.iter().any(|opt| matches!(
            opt,
            IcmpV6Option::RecursiveDNSServer { lifetime: 0, addresses, .. }
                if addresses.as_slice() == old_gua_dns.octets()
        )));
    }
}
