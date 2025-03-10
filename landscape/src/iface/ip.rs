use std::net::IpAddr;

use futures::stream::TryStreamExt;
use netlink_packet_route::address::{AddressHeaderFlag, AddressMessage};
use rtnetlink::new_connection;
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct LandscapeSingleIpInfo {
    pub address: IpAddr,
    pub is_permanent: bool,
    pub prefix_len: u8,
    pub ifindex: u32,
}

impl LandscapeSingleIpInfo {
    fn new(msg: AddressMessage) -> Option<Self> {
        let is_permanent =
            msg.header.flags.iter().find(|e| matches!(e, AddressHeaderFlag::Permanent)).is_some();
        let mut address = None;
        for each in msg.attributes.iter() {
            match each {
                netlink_packet_route::address::AddressAttribute::Address(ip_addr) => {
                    address = Some(ip_addr.clone())
                }
                _ => {}
            }
        }

        if let Some(address) = address {
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

    let (connection, handle, _) = match new_connection() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("err info: {e:?}");
            return result;
        }
    };

    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(link.clone()).execute();
    if let Some(link) = links.try_next().await.unwrap() {
        let mut addresses =
            handle.address().get().set_link_index_filter(link.header.index).execute();
        while let Some(msg) = addresses.try_next().await.unwrap() {
            if let Some(info) = LandscapeSingleIpInfo::new(msg) {
                result.push(info);
            }
        }
    } else {
        tracing::error!("link {link} not found");
    }

    result
}

pub async fn addresses_by_iface_id(iface_id: u32) -> Vec<LandscapeSingleIpInfo> {
    let mut result = vec![];

    let (connection, handle, _) = match new_connection() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("err info: {e:?}");
            return result;
        }
    };

    tokio::spawn(connection);

    let mut addresses = handle.address().get().set_link_index_filter(iface_id).execute();
    while let Some(msg) = addresses.try_next().await.unwrap() {
        if let Some(info) = LandscapeSingleIpInfo::new(msg) {
            result.push(info);
        }
    }

    result
}
