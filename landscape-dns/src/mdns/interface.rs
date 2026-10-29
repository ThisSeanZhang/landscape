use nix::{
    ifaddrs::getifaddrs,
    net::if_::{InterfaceFlags, if_nametoindex},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MdnsInterface {
    pub(super) ifindex: u32,
    pub(super) name: String,
    pub(super) has_ipv4: bool,
    pub(super) has_ipv6: bool,
}

impl MdnsInterface {
    fn fallback(ifindex: u32) -> Self {
        Self {
            ifindex,
            name: format!("ifindex {ifindex}"),
            has_ipv4: true,
            has_ipv6: true,
        }
    }
}

pub(super) fn select_response_interfaces(
    interfaces: &[MdnsInterface],
    ifindex: u32,
) -> Vec<MdnsInterface> {
    if ifindex == 0 {
        return interfaces.to_vec();
    }

    let matched = interfaces
        .iter()
        .filter(|interface| interface.ifindex == ifindex)
        .cloned()
        .collect::<Vec<_>>();
    if matched.is_empty() { vec![MdnsInterface::fallback(ifindex)] } else { matched }
}

pub(super) fn load_mdns_interfaces() -> Vec<MdnsInterface> {
    let mut interfaces = std::collections::HashMap::<String, MdnsInterface>::new();
    let Ok(addrs) = getifaddrs() else {
        return Vec::new();
    };

    for addr in addrs {
        if !addr.flags.contains(InterfaceFlags::IFF_UP)
            || addr.flags.contains(InterfaceFlags::IFF_LOOPBACK)
            || !addr.flags.contains(InterfaceFlags::IFF_MULTICAST)
        {
            continue;
        }

        let Ok(ifindex) = if_nametoindex(addr.interface_name.as_str()) else {
            continue;
        };
        let entry =
            interfaces.entry(addr.interface_name.clone()).or_insert_with(|| MdnsInterface {
                ifindex,
                name: addr.interface_name.clone(),
                has_ipv4: false,
                has_ipv6: false,
            });

        let Some(sockaddr) = addr.address else {
            continue;
        };
        if sockaddr.as_sockaddr_in().is_some() {
            entry.has_ipv4 = true;
        }
        if sockaddr.as_sockaddr_in6().is_some() {
            entry.has_ipv6 = true;
        }
    }

    interfaces.into_values().collect()
}
