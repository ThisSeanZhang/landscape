use std::net::IpAddr;

pub(crate) fn mask_ip(ip: IpAddr, prefix: u32) -> IpAddr {
    match ip {
        IpAddr::V4(addr) => {
            let prefix = prefix.min(32);
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            IpAddr::V4((u32::from(addr) & mask).into())
        }
        IpAddr::V6(addr) => {
            let prefix = prefix.min(128);
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            IpAddr::V6((u128::from(addr) & mask).into())
        }
    }
}
