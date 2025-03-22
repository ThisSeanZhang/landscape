use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
};

use dev::{DevState, LandScapeInterface};
use iface::{
    config::{CreateDevType, NetworkIfaceConfig},
    get_iface_by_name,
};
pub use routerstatus::*;

pub mod boot;
pub mod config;
pub mod dev;
pub mod dhcp_client;
pub mod dhcp_server;
pub mod docker;
pub mod dump;
pub mod firewall;
pub mod icmp;
pub mod iface;
pub mod macaddr;
pub mod observer;
pub mod packet_mark;
pub mod pppd_client;
pub mod pppoe_client;
pub mod routerstatus;
pub mod service;
pub mod store;
pub mod wifi;

fn gen_default_config(
    interface_map: &HashMap<String, LandScapeInterface>,
) -> Vec<NetworkIfaceConfig> {
    let mut interfaces: Vec<&LandScapeInterface> = interface_map
        .values()
        .filter(|ifce| !ifce.is_lo())
        .filter(|d| !d.is_virtual_dev())
        .collect();
    interfaces.sort_by(|&a, &b| b.index.cmp(&a.index));
    if interfaces.len() < 2 {
        // 只有一个设备不支持
        return vec![];
    }
    let _wan_iface = interfaces.pop().unwrap();

    let br = NetworkIfaceConfig::crate_default_br_lan();
    let mut dev_configs = vec![];
    for other_eth in interfaces {
        // 如果已经有对应的 controller 了就不进行处理了
        if other_eth.controller_id.is_some() {
            continue;
        }
        let mut dev = NetworkIfaceConfig::from_phy_dev(other_eth);
        dev.controller_name = Some(br.name.clone());
        dev_configs.push(dev);
    }
    dev_configs.push(br);
    return dev_configs;
}

// 初始化配置
pub async fn init_devs(network_config: Vec<NetworkIfaceConfig>) -> Vec<NetworkIfaceConfig> {
    let mut need_store_config = vec![];
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut links = handle.link().get().execute();

    let mut interface_map: HashMap<String, LandScapeInterface> = HashMap::new();
    while let Some(msg) = links.try_next().await.unwrap() {
        if let Some(data) = LandScapeInterface::new(msg) {
            interface_map.insert(data.name.clone(), data);
        }
    }

    let network_config = if network_config.is_empty() {
        let tmp = gen_default_config(&interface_map);
        need_store_config = tmp.clone();
        tmp
    } else {
        network_config
    };

    if !network_config.is_empty() {
        let (dev_tx, mut dev_rx) =
            tokio::sync::mpsc::unbounded_channel::<(u8, NetworkIfaceConfig)>();

        for config in network_config.iter() {
            dev_tx.send((0, config.clone())).unwrap();
        }

        // 成功初始化的网卡列表
        while let Ok((time, ifconfig)) = dev_rx.try_recv() {
            if time >= 3 {
                // 超过三次, 可能是由初始化循环, 所以不进行处理了 也要进行记录
                continue;
            }

            let current_iface = if let Some(current_iface) = get_iface_by_name(&ifconfig.name).await
            {
                current_iface
            } else {
                // TODO 依据网卡类型创建网卡
                match &ifconfig.create_dev_type {
                    // 目前仅处理桥接设别的创建
                    CreateDevType::Bridge => {
                        let create_result =
                            handle.link().add().bridge(ifconfig.name.clone()).execute().await;
                    }
                    _ => (),
                }
                // 创建后重新进行获取, 如果获取不到 进行下一轮
                let Some(mut current_iface) = get_iface_by_name(&ifconfig.name).await else {
                    dev_tx.send((time + 1, ifconfig)).unwrap();
                    continue;
                };
                // 启动刚刚创建的 bridge
                if let Ok(_) = handle.link().set(current_iface.index).up().execute().await {
                    current_iface.dev_status = DevState::Up;
                }
                current_iface
            };

            // 先检查是否有 master 且 master 是否已经初始化
            if let Some(master_ifac_name) = ifconfig.controller_name.as_ref() {
                if let Some(master_iface) = get_iface_by_name(master_ifac_name).await {
                    let create_result = handle
                        .link()
                        .set(current_iface.index)
                        .controller(master_iface.index)
                        .execute()
                        .await;
                } else {
                    // 找不到 也就是目标还未初始化
                    dev_tx.send((time + 1, ifconfig)).unwrap();
                    continue;
                }
            }

            if ifconfig.enable_in_boot {
                std::process::Command::new("ip")
                    .args(["link", "set", &ifconfig.name, "up"])
                    .output()
                    .unwrap();
            }

            interface_map.remove(&ifconfig.name);
        }
    }

    // for iface in interface_map.into_values() {
    //     if iface.is_lo() {
    //         continue;
    //     }
    //     need_store_config.push(NetworkIfaceConfig::from_phy_dev(&iface));
    // }

    need_store_config
}

pub async fn get_all_devices() -> Vec<LandScapeInterface> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut links = handle.link().get().execute();
    let mut result = vec![];
    while let Some(msg) = links.try_next().await.unwrap() {
        if let Some(data) = LandScapeInterface::new(msg) {
            result.push(data);
        }
    }
    // handle.link().add().bridge("my-bridge-1".into()).execute().await.map_err(|e| format!("{e}"));
    // handle.link().set(27).controller(12);

    result
}

pub async fn get_address(iface_name: &str) -> Option<(u32, HashSet<Ipv4Addr>)> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut links = handle.link().get().match_name(iface_name.to_string()).execute();

    if let Ok(Some(link)) = links.try_next().await {
        let mut out_addr: HashSet<Ipv4Addr> = HashSet::new();
        let mut addresses =
            handle.address().get().set_link_index_filter(link.header.index).execute();
        while let Ok(Some(msg)) = addresses.try_next().await {
            if matches!(msg.header.family, AddressFamily::Inet) {
                for attr in msg.attributes.iter() {
                    match attr {
                        netlink_packet_route::address::AddressAttribute::Local(addr) => {
                            if let IpAddr::V4(addr) = addr {
                                out_addr.insert(addr.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Some((link.header.index, out_addr))
    } else {
        None
    }
}

pub async fn create_bridge(name: String) -> bool {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let create_result = handle.link().add().bridge(name).execute().await;
    create_result.is_ok()
}

/// Attach the link to a bridge (its controller).
/// This is equivalent to ip link set LINK master BRIDGE.
/// To succeed, both the bridge and the link that is being attached must be UP.
pub async fn set_controller(
    link_name: &str,
    master_index: Option<u32>,
) -> Option<LandScapeInterface> {
    if let Some(dev) = get_iface_by_name(link_name).await {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let create_result =
            handle.link().set(dev.index).controller(master_index.unwrap_or(0)).execute().await;
        if create_result.is_ok() {
            Some(dev)
        } else {
            None
        }
    } else {
        None
    }
}

pub async fn change_dev_status(iface_name: &str, up: bool) -> Option<LandScapeInterface> {
    if let Some(dev) = get_iface_by_name(iface_name).await {
        let status = if up { "up" } else { "down" };
        let result =
            std::process::Command::new("ip").args(["link", "set", iface_name, status]).output();
        if result.is_ok() {
            Some(dev)
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn sysinfo() {
        use sysinfo::{Components, Disks, Networks, System};

        // Please note that we use "new_all" to ensure that all list of
        // components, network interfaces, disks and users are already
        // filled!
        let mut sys = System::new_all();

        // First we update all information of our `System` struct.
        sys.refresh_all();

        println!("=> system:");
        // RAM and swap information:
        println!("total memory: {} bytes", sys.total_memory());
        println!("used memory : {} bytes", sys.used_memory());
        println!("total swap  : {} bytes", sys.total_swap());
        println!("used swap   : {} bytes", sys.used_swap());

        // Display system information:
        println!("System name:             {:?}", System::name());
        println!("System kernel version:   {:?}", System::kernel_version());
        println!("System OS version:       {:?}", System::os_version());
        println!("System host name:        {:?}", System::host_name());

        // Number of CPUs:
        println!("NB CPUs: {}", sys.cpus().len());

        // Display processes ID, name na disk usage:
        for (pid, process) in sys.processes() {
            println!("[{pid}] {} {:?}", process.name(), process.disk_usage());
        }

        // We display all disks' information:
        println!("=> disks:");
        let disks = Disks::new_with_refreshed_list();
        for disk in &disks {
            println!("{disk:?}");
        }

        // Network interfaces name, total data received and total data transmitted:
        let networks = Networks::new_with_refreshed_list();
        println!("=> networks:");
        for (interface_name, data) in &networks {
            println!(
                "{interface_name}: {} B (down) / {} B (up)",
                data.total_received(),
                data.total_transmitted(),
            );
            // If you want the amount of data received/transmitted since last call
            // to `Networks::refresh`, use `received`/`transmitted`.
        }

        // Components temperature:
        let components = Components::new_with_refreshed_list();
        println!("=> components:");
        for component in &components {
            println!("{component:?}");
        }
    }

    use netlink_packet_route::{
        link::{LinkAttribute, LinkExtentMask},
        AddressFamily,
    };
    use rtnetlink::{new_connection, Error, Handle};

    #[tokio::test]
    async fn netlink() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        super::dump_links(handle).await;
    }
}

use futures::stream::TryStreamExt;
use netlink_packet_route::{
    link::{LinkAttribute, LinkExtentMask},
    AddressFamily,
};
use rtnetlink::{new_connection, Error, Handle};
async fn dump_links(handle: Handle) -> Result<(), Error> {
    let mut links = handle.link().get().execute();
    'outer: while let Some(msg) = links.try_next().await? {
        for nla in msg.attributes.into_iter() {
            if let LinkAttribute::IfName(name) = nla {
                println!("found link {} ({})", msg.header.index, name);
                continue 'outer;
            }
        }
        eprintln!("found link {}, but the link has no name", msg.header.index);
    }
    Ok(())
}
