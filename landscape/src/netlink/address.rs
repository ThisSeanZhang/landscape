use std::net::{IpAddr, Ipv4Addr};

use futures::stream::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::Handle;
use serde::Serialize;

use super::handle::create_handle;

const NETLINK_EEXIST: i32 = -17;

fn is_netlink_file_exists(error: &rtnetlink::Error) -> bool {
    matches!(error, rtnetlink::Error::NetlinkError(msg) if msg.raw_code() == NETLINK_EEXIST)
}

#[derive(Serialize, Debug, Clone)]
pub struct LandscapeSingleIpInfo {
    pub address: IpAddr,
    pub is_permanent: bool,
    pub prefix_len: u8,
    pub ifindex: u32,
}

impl LandscapeSingleIpInfo {
    fn new(msg: AddressMessage) -> Option<Self> {
        // In newer versions, flags structure changed - check for IFA_F_PERMANENT bit
        let is_permanent =
            msg.header.flags.contains(netlink_packet_route::address::AddressHeaderFlags::Permanent);
        let mut address = None;
        let mut local = None;
        for each in msg.attributes.iter() {
            match each {
                AddressAttribute::Local(ip_addr) => local = Some(*ip_addr),
                AddressAttribute::Address(ip_addr) => address = Some(*ip_addr),
                _ => {}
            }
        }

        if let Some(address) = local.or(address) {
            Some(LandscapeSingleIpInfo {
                ifindex: msg.header.index,
                address,
                is_permanent,
                prefix_len: msg.header.prefix_len,
            })
        } else {
            None
        }
    }
}

pub async fn addresses_by_iface_name(link: String) -> Vec<LandscapeSingleIpInfo> {
    let mut result = vec![];

    let handle = match create_handle() {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("err info: {e:?}");
            return result;
        }
    };

    let mut links = handle.link().get().match_name(link.clone()).execute();
    let link_message = match links.try_next().await {
        Ok(Some(link)) => link,
        Ok(None) => {
            tracing::error!("link {link} not found");
            return result;
        }
        Err(e) => {
            tracing::error!("failed to query link {link}: {e:?}");
            return result;
        }
    };

    let mut addresses =
        handle.address().get().set_link_index_filter(link_message.header.index).execute();
    loop {
        match addresses.try_next().await {
            Ok(Some(msg)) => {
                if let Some(info) = LandscapeSingleIpInfo::new(msg) {
                    result.push(info);
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::error!("failed to read addresses for link {link}: {e:?}");
                break;
            }
        }
    }

    result
}

pub async fn addresses_by_iface_id(iface_id: u32) -> Vec<LandscapeSingleIpInfo> {
    let mut result = vec![];

    let handle = match create_handle() {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("err info: {e:?}");
            return result;
        }
    };

    let mut addresses = handle.address().get().set_link_index_filter(iface_id).execute();
    while let Some(msg) = addresses.try_next().await.unwrap() {
        if let Some(info) = LandscapeSingleIpInfo::new(msg) {
            result.push(info);
        }
    }

    result
}

pub async fn set_iface_ip(link_name: &str, ip: IpAddr, prefix_length: u8) -> bool {
    let handle = match create_handle() {
        Ok(h) => h,
        Err(_) => return false,
    };

    let mut links = handle.link().get().match_name(link_name.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(link)) => link,
        Ok(None) => {
            tracing::warn!("link {link_name} not found, skip setting {ip}/{prefix_length}");
            return false;
        }
        Err(e) => {
            tracing::warn!(
                "failed to query link {link_name}: {e:?}, skip setting {ip}/{prefix_length}"
            );
            return false;
        }
    };

    let mut addr_iter = handle.address().get().execute();

    let mut has_same_ip = false;
    'search_same_ip: loop {
        match addr_iter.try_next().await {
            Ok(Some(addr)) => {
                if addr.header.index == link.header.index && addr.header.prefix_len == prefix_length
                {
                    for nla in addr.attributes.iter() {
                        if let AddressAttribute::Address(bytes) = nla {
                            has_same_ip = *bytes == ip;
                            if has_same_ip {
                                break 'search_same_ip;
                            }
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(
                    "failed to read addresses for link {link_name}: {e:?}, skip setting {ip}/{prefix_length}"
                );
                return false;
            }
        }
    }

    if !has_same_ip {
        tracing::info!("without same ip, add it");
        if let Err(e) = handle.address().add(link.header.index, ip, prefix_length).execute().await
            && !is_netlink_file_exists(&e)
        {
            tracing::warn!("failed to add {ip}/{prefix_length} on {link_name}: {e:?}");
            return false;
        }
    }
    true
}

pub async fn get_ppp_address(
    iface_name: &str,
) -> Option<(u32, Option<Ipv4Addr>, Option<Ipv4Addr>)> {
    let handle = create_handle().ok()?;
    let mut links = handle.link().get().match_name(iface_name.to_string()).execute();

    if let Ok(Some(link)) = links.try_next().await {
        let mut out_addr: Option<Ipv4Addr> = None;
        let mut peer_addr: Option<Ipv4Addr> = None;
        let mut addresses =
            handle.address().get().set_link_index_filter(link.header.index).execute();
        while let Ok(Some(msg)) = addresses.try_next().await {
            if matches!(msg.header.family, AddressFamily::Inet) {
                for attr in msg.attributes.iter() {
                    match attr {
                        netlink_packet_route::address::AddressAttribute::Local(IpAddr::V4(
                            addr,
                        )) => {
                            out_addr = Some(*addr);
                        }
                        netlink_packet_route::address::AddressAttribute::Address(IpAddr::V4(
                            addr,
                        )) => {
                            peer_addr = Some(*addr);
                        }
                        _ => {}
                    }
                }
            }
        }

        Some((link.header.index, out_addr, peer_addr))
    } else {
        None
    }
}

pub async fn add_address_with_handle(
    link_name: &str,
    ip: IpAddr,
    prefix_length: u8,
    handle: Handle,
) {
    let mut links = handle.link().get().match_name(link_name.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(link)) => link,
        Ok(None) => {
            tracing::warn!("link {link_name} not found, skip adding {ip}/{prefix_length}");
            return;
        }
        Err(e) => {
            tracing::warn!(
                "failed to query link {link_name}: {e:?}, skip adding {ip}/{prefix_length}"
            );
            return;
        }
    };

    let mut addr_iter = handle.address().get().execute();
    // 与要添加的 ip 是否相同
    let mut need_create_ip = true;
    loop {
        match addr_iter.try_next().await {
            Ok(Some(addr)) => {
                let perfix_len_equal = addr.header.prefix_len == prefix_length;
                let mut link_name_equal = false;
                let mut ip_equal = false;

                for attr in addr.attributes.iter() {
                    match attr {
                        AddressAttribute::Address(addr) => {
                            if *addr == ip {
                                ip_equal = true;
                            }
                        }
                        AddressAttribute::Label(label) if *label == link_name => {
                            link_name_equal = true;
                        }
                        _ => {}
                    }
                }

                if link_name_equal {
                    if ip_equal && perfix_len_equal {
                        need_create_ip = false;
                    } else {
                        tracing::info!("stop dhcp v4 server and del: {addr:?}");
                        if let Err(e) = handle.address().del(addr).execute().await {
                            tracing::warn!("failed to del address on {link_name}: {e:?}");
                            return;
                        }
                        need_create_ip = true;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("failed to read addresses for link {link_name}: {e:?}");
                return;
            }
        }
    }

    if need_create_ip
        && let Err(e) = handle.address().add(link.header.index, ip, prefix_length).execute().await
        && !is_netlink_file_exists(&e)
    {
        tracing::warn!("failed to add {ip}/{prefix_length} on {link_name}: {e:?}");
    }
}

pub fn get_existing_linklocal(iface_name: &str) -> Option<std::net::Ipv6Addr> {
    let output = std::process::Command::new("ip")
        .args(["-6", "addr", "show", "dev", iface_name, "scope", "link"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let prefix = "inet6 fe80:";
    let line = stdout.lines().find(|l| l.trim().contains(prefix))?;
    let field = line.split_whitespace().find(|s| s.starts_with("fe80:"))?;
    let addr_str = field.split('/').next()?;
    addr_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::address::{AddressHeader, AddressHeaderFlags, AddressScope};

    fn message(
        prefix_len: u8,
        is_permanent: bool,
        attributes: Vec<AddressAttribute>,
    ) -> AddressMessage {
        let mut message = AddressMessage::default();
        message.header = AddressHeader {
            prefix_len,
            flags: if is_permanent {
                AddressHeaderFlags::Permanent
            } else {
                AddressHeaderFlags::empty()
            },
            scope: AddressScope::Universe,
            index: 7,
            ..Default::default()
        };
        message.attributes = attributes;
        message
    }

    #[test]
    fn prefers_local_attribute_over_address() {
        let local = "10.0.0.2".parse().unwrap();
        let peer = "10.0.0.1".parse().unwrap();
        let info = LandscapeSingleIpInfo::new(message(
            24,
            true,
            vec![AddressAttribute::Address(peer), AddressAttribute::Local(local)],
        ))
        .expect("address info");

        assert_eq!(info.address, local);
        assert_eq!(info.prefix_len, 24);
        assert!(info.is_permanent);
        assert_eq!(info.ifindex, 7);
    }

    #[test]
    fn falls_back_to_address_when_local_missing() {
        let addr = "192.168.1.10".parse().unwrap();
        let info =
            LandscapeSingleIpInfo::new(message(16, false, vec![AddressAttribute::Address(addr)]))
                .expect("address info");

        assert_eq!(info.address, addr);
        assert!(!info.is_permanent);
    }

    #[test]
    fn returns_none_without_address_attributes() {
        assert!(LandscapeSingleIpInfo::new(message(24, true, vec![])).is_none());
    }
}
