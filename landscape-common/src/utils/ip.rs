use std::net::{IpAddr, SocketAddr};

pub fn extract_real_ip(addr: SocketAddr) -> IpAddr {
    match addr.ip() {
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
        IpAddr::V6(ipv6) => {
            // 尝试解码 IPv4-mapped IPv6
            if let Some(mapped_v4) = ipv6.to_ipv4() {
                IpAddr::V4(mapped_v4)
            } else {
                IpAddr::V6(ipv6)
            }
        }
    }
}
