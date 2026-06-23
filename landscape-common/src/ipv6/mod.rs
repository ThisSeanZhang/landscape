pub mod lan;
pub mod ra;

use std::net::Ipv6Addr;

pub fn allocate_subnet(
    pd_ip: Ipv6Addr,
    pd_prefix_len: u8,
    sub_prefix_len: u8,
    subnet_index: u128,
) -> (Ipv6Addr, Ipv6Addr) {
    checked_allocate_subnet(pd_ip, pd_prefix_len, sub_prefix_len, subnet_index)
        .expect("invalid IPv6 subnet allocation")
}

pub fn checked_allocate_subnet(
    pd_ip: Ipv6Addr,
    pd_prefix_len: u8,
    sub_prefix_len: u8,
    subnet_index: u128,
) -> Option<(Ipv6Addr, Ipv6Addr)> {
    if pd_prefix_len > 128 || sub_prefix_len > 128 || sub_prefix_len < pd_prefix_len {
        return None;
    }

    let subnet_bits = sub_prefix_len - pd_prefix_len;
    if subnet_bits < 128 {
        let max_subnets = 1u128 << subnet_bits;
        if subnet_index >= max_subnets {
            return None;
        }
    }

    let prefix_u128 = u128::from(pd_ip);
    let parent_mask = ipv6_prefix_mask(pd_prefix_len)?;
    let parent_network = prefix_u128 & parent_mask;
    let sub_mask = ipv6_prefix_mask(sub_prefix_len)?;
    let base_network = parent_network & sub_mask;
    let subnet_network = if sub_prefix_len == 0 {
        base_network
    } else {
        let subnet_size = 1u128 << (128 - sub_prefix_len);
        base_network.checked_add(subnet_index.checked_mul(subnet_size)?)?
    };
    let router_address =
        if sub_prefix_len == 128 { subnet_network } else { subnet_network.checked_add(1)? };

    Some((Ipv6Addr::from(subnet_network), Ipv6Addr::from(router_address)))
}

pub fn combine_ipv6_prefix_suffix(prefix: Ipv6Addr, prefix_len: u8, suffix: Ipv6Addr) -> Ipv6Addr {
    checked_combine_ipv6_prefix_suffix(prefix, prefix_len, suffix)
        .expect("IPv6 prefix length must be <= 128")
}

pub fn checked_combine_ipv6_prefix_suffix(
    prefix: Ipv6Addr,
    prefix_len: u8,
    suffix: Ipv6Addr,
) -> Option<Ipv6Addr> {
    let prefix_value = u128::from(prefix);
    let suffix_value = u128::from(suffix);
    let prefix_mask = ipv6_prefix_mask(prefix_len)?;
    Some(Ipv6Addr::from((prefix_value & prefix_mask) | (suffix_value & !prefix_mask)))
}

fn ipv6_prefix_mask(prefix_len: u8) -> Option<u128> {
    match prefix_len {
        0 => Some(0),
        1..=128 => Some(!0u128 << (128 - prefix_len)),
        _ => None,
    }
}

pub fn checked_extract_ipv6_suffix(ip: Ipv6Addr, prefix_len: u8) -> Option<Ipv6Addr> {
    let mask = ipv6_prefix_mask(prefix_len)?;
    Some(Ipv6Addr::from(u128::from(ip) & !mask))
}

pub fn extract_ipv6_suffix(ip: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    checked_extract_ipv6_suffix(ip, prefix_len).expect("invalid IPv6 prefix_len")
}

#[cfg(test)]
mod tests {
    use super::{
        checked_allocate_subnet, checked_combine_ipv6_prefix_suffix, checked_extract_ipv6_suffix,
    };
    use std::net::Ipv6Addr;

    #[test]
    fn allocate_subnet_supports_128_prefixes() {
        let result = checked_allocate_subnet("2001:db8::1".parse().unwrap(), 128, 128, 0)
            .expect("/128 allocation should succeed");

        assert_eq!(result.0, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(result.1, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn extract_suffix_is_inverse_of_combine() {
        let prefix: Ipv6Addr = "2001:db8:1234:5600::".parse().unwrap();
        let prefix_len: u8 = 56;
        let addr: Ipv6Addr = "2001:db8:1234:5601:abcd:efff:fe12:3456".parse().unwrap();

        let suffix = checked_extract_ipv6_suffix(addr, prefix_len).unwrap();
        let reconstructed = checked_combine_ipv6_prefix_suffix(prefix, prefix_len, suffix).unwrap();

        assert_eq!(reconstructed, addr);
    }

    #[test]
    fn combine_and_extract_roundtrip() {
        let prefix: Ipv6Addr = "2001:4860:4860::".parse().unwrap();
        let prefix_len: u8 = 48;
        let suffix: Ipv6Addr = "::1".parse().unwrap();

        let combined = checked_combine_ipv6_prefix_suffix(prefix, prefix_len, suffix).unwrap();
        let extracted = checked_extract_ipv6_suffix(combined, prefix_len).unwrap();

        assert_eq!(extracted, suffix);
    }
}
