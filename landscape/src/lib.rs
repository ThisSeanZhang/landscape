use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use futures::stream::TryStreamExt;
use iface::get_iface_by_name;
use landscape_common::config::iface::{CreateDevType, NetworkIfaceConfig, WifiMode};
use landscape_common::dev::{DevState, LandscapeInterface};
use landscape_common::iface::dev_wifi::LandscapeWifiInterface;
use netlink_packet_route::{address::AddressAttribute, AddressFamily};
use rtnetlink::new_connection;

pub mod boot;

pub mod arp;
pub mod cert;
pub mod config_service;
pub mod dev;
pub mod dhcp_client;
pub mod dhcp_server;
pub mod docker;
pub mod dump;
pub mod firewall;
pub mod flow;
pub mod icmp;
pub mod iface;
pub mod metric;
pub mod observer;
pub mod pppoe_client;
pub mod route;
pub mod service;
pub mod sys_service;
pub mod wifi;

// fn gen_default_config(
//     interface_map: &HashMap<String, LandscapeInterface>,
// ) -> Vec<NetworkIfaceConfig> {
//     let mut interfaces: Vec<&LandscapeInterface> = interface_map
//         .values()
//         .filter(|ifce| !ifce.is_lo())
//         .filter(|d| !d.is_virtual_dev())
//         .collect();
//     interfaces.sort_by(|&a, &b| b.index.cmp(&a.index));
//     if interfaces.len() < 2 {
//         // 只有一个设备不支持
//         return vec![];
//     }
//     let _wan_iface = interfaces.pop().unwrap();

//     let br = NetworkIfaceConfig::crate_default_br_lan();
//     let mut dev_configs = vec![];
//     for other_eth in interfaces {
//         // 如果已经有对应的 controller 了就不进行处理了
//         if other_eth.controller_id.is_some() {
//             continue;
//         }
//         let mut dev = NetworkIfaceConfig::from_phy_dev(other_eth);
//         dev.controller_name = Some(br.name.clone());
//         dev_configs.push(dev);
//     }
//     dev_configs.push(br);
//     return dev_configs;
// }

// 初始化配置
pub async fn init_devs(network_config: Vec<NetworkIfaceConfig>) {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut links = handle.link().get().execute();

    let mut interface_map: HashMap<String, LandscapeInterface> = HashMap::new();
    while let Some(msg) = links.try_next().await.unwrap() {
        if let Some(data) = crate::dev::new_landscape_interface(msg) {
            interface_map.insert(data.name.clone(), data);
        }
    }

    if network_config.is_empty() {
        tracing::warn!("network config is empty")
    } else {
        let (dev_tx, mut dev_rx) =
            tokio::sync::mpsc::unbounded_channel::<(u8, NetworkIfaceConfig)>();

        for config in network_config.iter() {
            // 检查 wifi 类型
            using_iw_change_wifi_mode(&config.name, &config.wifi_mode);

            // Setting Iface Balance
            if let Some(balance) = &config.xps_rps {
                if let Err(e) = iface::setting_iface_balance(&config.name, balance.clone()) {
                    tracing::error!("setting iface balance error: {e:?}");
                }
            }

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
                        if let Err(e) =
                            handle.link().add().bridge(ifconfig.name.clone()).execute().await
                        {
                            tracing::error!("create bridge error: {e:?}");
                        }
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
                    if let Err(e) = create_result {
                        tracing::error!("set controller error: {e:?}");
                    }
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
}

pub fn using_iw_change_wifi_mode(iface_name: &str, mode: &WifiMode) {
    tracing::debug!("setting {} to mode: {:?}", iface_name, mode);
    match mode {
        WifiMode::Undefined => {}
        WifiMode::Client => {
            std::process::Command::new("iw")
                .args(["dev", iface_name, "set", "type", "managed"])
                .output()
                .unwrap();
        }
        WifiMode::AP => {
            std::process::Command::new("iw")
                .args(["dev", iface_name, "set", "type", "__ap"])
                .output()
                .unwrap();
        }
    }
}

pub async fn get_all_wifi_devices() -> HashMap<String, LandscapeWifiInterface> {
    let (connection, handle, _) = match wl_nl80211::new_connection() {
        Ok(conn) => conn,
        Err(_) => return HashMap::new(),
    };
    tokio::spawn(connection);

    let mut interface_handle = handle.interface().get().execute().await;
    let mut result = HashMap::new();

    loop {
        let msg_opt = match interface_handle.try_next().await {
            Ok(opt) => opt,
            Err(_) => None,
        };

        let msg = match msg_opt {
            Some(m) => m,
            None => break,
        };

        if let Some(data) = crate::iface::dev_wifi::new_landscape_wifi_interface(msg.payload) {
            result.insert(data.name.clone(), data);
        }
    }

    result
}

pub async fn get_all_devices() -> Vec<LandscapeInterface> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut links = handle.link().get().execute();
    let mut result = vec![];
    while let Some(msg) = links.try_next().await.unwrap() {
        if let Some(data) = crate::dev::new_landscape_interface(msg) {
            if data.is_lo() {
                continue;
            }
            result.push(data);
        }
    }
    result
}

pub async fn set_iface_ip_no_limit(link_name: &str, ip: IpAddr, prefix_length: u8) -> bool {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(link_name.to_string()).execute();
    if let Some(link) = links.try_next().await.unwrap() {
        let mut addr_iter = handle.address().get().execute();

        let mut has_same_ip = false;
        'search_same_ip: while let Some(addr) = addr_iter.try_next().await.unwrap() {
            if addr.header.index == link.header.index && addr.header.prefix_len == prefix_length {
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

        if !has_same_ip {
            tracing::info!("without same ip, add it");
            handle.address().add(link.header.index, ip, prefix_length).execute().await.unwrap();
        }
        true
    } else {
        false
    }
}

pub async fn get_ppp_address(
    iface_name: &str,
) -> Option<(u32, Option<Ipv4Addr>, Option<Ipv4Addr>)> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
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
                        netlink_packet_route::address::AddressAttribute::Local(addr) => {
                            if let IpAddr::V4(addr) = addr {
                                out_addr = Some(addr.clone());
                            }
                        }
                        netlink_packet_route::address::AddressAttribute::Address(addr) => {
                            if let IpAddr::V4(addr) = addr {
                                peer_addr = Some(addr.clone());
                            }
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

pub async fn create_bridge(name: String) -> bool {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let create_result = handle.link().add().bridge(name).execute().await;
    create_result.is_ok()
}

pub async fn delete_bridge(name: String) -> bool {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut result = handle.link().get().match_name(name).execute();
    loop {
        match result.try_next().await {
            Ok(link) => match link {
                Some(link) => {
                    let del_result = handle.link().del(link.header.index).execute().await;
                    if del_result.is_ok() {
                        return true;
                    }
                }
                None => {
                    return false;
                }
            },
            Err(e) => {
                tracing::error!("delete bridge error: {e:?}");
                return false;
            }
        }
    }
}

/// Attach the link to a bridge (its controller).
/// This is equivalent to ip link set LINK master BRIDGE.
/// To succeed, both the bridge and the link that is being attached must be UP.
pub async fn set_controller(
    link_name: &str,
    master_index: Option<u32>,
) -> Option<LandscapeInterface> {
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

pub async fn change_dev_status(iface_name: &str, up: bool) -> Option<LandscapeInterface> {
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
            println!("[{pid}] {:?} {:?}", process.name(), process.disk_usage());
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
}
