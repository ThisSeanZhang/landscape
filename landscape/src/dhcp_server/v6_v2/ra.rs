use landscape_common::{
    net::MacAddr,
    net_proto::icmpv6::{
        messages::{Icmpv6Message, RouterAdvertisement},
        options::{IcmpV6Option, IcmpV6Options},
    },
};

use super::SubnetState;

/// Build a deprecation RA for removed subnets, announcing only the
/// prefixes being withdrawn with Valid Lifetime = 0.
pub fn build_deprecation_ra_from_subnets(
    removed: &[SubnetState],
    mac_addr: &MacAddr,
    ra_flags: u8,
    ra_autonomous: bool,
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
                ra_autonomous,
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
            has_prefix = true;
        }
    }

    if !has_prefix {
        return Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(ra_flags, opts));
    }

    opts.insert(IcmpV6Option::recursive_dns_server(600, mac_addr.to_ipv6_link_local()));
    opts.insert(IcmpV6Option::mtu(1500));

    Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(ra_flags, opts))
}
