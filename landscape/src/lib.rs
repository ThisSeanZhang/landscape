use std::collections::HashMap;

use futures::stream::TryStreamExt;
use iface::get_iface_by_name;
use landscape_common::dev::{DevState, LandscapeInterface};
use landscape_common::iface::config::{CreateDevType, NetworkIfaceConfig, WifiMode};

pub mod boot;

pub mod arp;
pub mod cert;
pub mod dhcp_client;
pub mod dns;
pub mod docker;
pub mod dump;
pub mod enrolled_device;
pub mod firewall;
pub mod flow;
pub mod geo;
pub mod iface;
pub mod ipv6;
pub mod metric;
pub mod netlink;
pub use crate::netlink::observer;
pub mod pppoe_client;
pub mod route;
pub mod wifi;

pub mod lan_service;
pub mod sys_service;

// Backward-compatible re-exports from netlink module
pub use netlink::address::set_iface_ip as set_iface_ip_no_limit;
pub use netlink::address::{
    addresses_by_iface_id, addresses_by_iface_name, get_ppp_address, LandscapeSingleIpInfo,
};
pub use netlink::convert::{
    convert_link_kind, convert_link_state, convert_link_type, parse_link_message,
};
pub use netlink::link::{
    change_dev_status, create_bridge, delete_bridge, get_all_devices, set_controller,
};
pub use netlink::wifi::{convert_wifi_type, get_all_wifi_devices, parse_wifi_message};

pub fn gen_default_config(
    interface_map: &HashMap<String, LandscapeInterface>,
) -> Vec<NetworkIfaceConfig> {
    tracing::info!("Scanning all interfaces: {:?}", interface_map.keys().collect::<Vec<&String>>());
    let interfaces: Vec<&LandscapeInterface> = interface_map
        .values()
        .filter(|ifce| !ifce.is_lo())
        .filter(|d| !d.is_virtual_dev())
        .collect();

    if interfaces.is_empty() {
        tracing::info!("No physical interfaces found for auto-init.");
        return vec![];
    }

    let br = NetworkIfaceConfig::crate_default_br_lan();
    let mut dev_configs = vec![];
    let mut added_ifaces = vec![];
    for eth in interfaces {
        // 如果已经有对应的 controller 了就不进行处理了
        if eth.controller_id.is_some() {
            tracing::info!(
                "Skip interface {} because it already has a controller (index: {:?})",
                eth.name,
                eth.controller_id
            );
            continue;
        }
        let mut dev = iface::config::from_phy_dev(eth);
        dev.controller_name = Some(br.name.clone());
        dev.enable_in_boot = true;
        added_ifaces.push(eth.name.clone());
        dev_configs.push(dev);
    }
    tracing::info!("Interfaces added to bridge {}: {:?}", br.name, added_ifaces);
    dev_configs.push(br);
    dev_configs
}

// 初始化配置
pub async fn init_devs(network_config: Vec<NetworkIfaceConfig>) {
    let handle = match netlink::handle::create_handle() {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("failed to create netlink handle: {e:?}");
            return;
        }
    };
    let mut links = handle.link().get().execute();

    let mut interface_map: HashMap<String, LandscapeInterface> = HashMap::new();
    while let Some(msg) = links.try_next().await.unwrap() {
        if let Some(data) = netlink::convert::parse_link_message(msg) {
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
                        use rtnetlink::LinkBridge;
                        if let Err(e) = handle
                            .link()
                            .add(LinkBridge::new(&ifconfig.name).build())
                            .execute()
                            .await
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
                {
                    use netlink_packet_route::link::{LinkFlags, LinkMessage};
                    let mut msg = LinkMessage::default();
                    msg.header.index = current_iface.index;
                    msg.header.flags = LinkFlags::Up;
                    msg.header.change_mask = LinkFlags::Up;
                    if let Ok(_) = handle.link().change(msg).execute().await {
                        current_iface.dev_status = DevState::Up;
                    }
                }
                current_iface
            };

            // 先检查是否有 master 且 master 是否已经初始化
            if let Some(master_ifac_name) = ifconfig.controller_name.as_ref() {
                if let Some(master_iface) = get_iface_by_name(master_ifac_name).await {
                    use netlink_packet_route::link::{LinkAttribute, LinkMessage};
                    let mut msg = LinkMessage::default();
                    msg.header.index = current_iface.index;
                    msg.attributes = vec![LinkAttribute::Controller(master_iface.index)];
                    let create_result = handle.link().change(msg).execute().await;
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
                let ifname = ifconfig.name.clone();
                tokio::spawn(async move {
                    netlink::ethtool::disable_gro(&ifname).await;
                });
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
