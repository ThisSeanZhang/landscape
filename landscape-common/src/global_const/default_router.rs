use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use once_cell::sync::Lazy;
use tokio::sync::RwLock;

pub static LD_ALL_ROUTERS: Lazy<DefaultRouterManager> = Lazy::new(DefaultRouterManager::new);

#[derive(Eq, Hash, PartialEq, Debug)]
pub struct RouteInfo {
    pub iface_name: String,
    pub weight: u32,
    pub route: RouteType,
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum RouteType {
    Ipv6(Ipv6Addr),
    Ipv4(Ipv4Addr),
    PPP,
}

impl From<IpAddr> for RouteType {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ipv4_addr) => RouteType::Ipv4(ipv4_addr),
            IpAddr::V6(ipv6_addr) => RouteType::Ipv6(ipv6_addr),
        }
    }
}

pub struct DefaultRouterManager {
    infos: RwLock<HashSet<RouteInfo>>,
}

impl DefaultRouterManager {
    fn new() -> Self {
        DefaultRouterManager { infos: RwLock::new(HashSet::new()) }
    }

    pub async fn add_route(&self, info: RouteInfo) {
        tracing::info!("add default router: {:#?}", info);
        let mut infos = self.infos.write().await;
        infos.insert(info);
        drop(infos);
        self.gen_and_set_ecmp_route().await;
    }

    pub async fn del_route_by_iface(&self, iface_name: &str) {
        tracing::info!("del: {:#?} default router", iface_name);
        let mut infos = self.infos.write().await;
        infos.retain(|info| info.iface_name != iface_name);
        drop(infos);
        self.gen_and_set_ecmp_route().await;
    }

    /// gen cmd like this
    /// ip route add default \
    /// nexthop via 192.168.1.1 dev eth0 weight 2 \
    /// nexthop via 192.168.1.2 dev eth1 weight 1
    async fn gen_and_set_ecmp_route(&self) {
        let infos = self.infos.read().await;
        let mut ipv4_command =
            vec!["route".to_string(), "replace".to_string(), "default".to_string()];
        let mut ipv6_command = vec![
            "-6".to_string(),
            "route".to_string(),
            "replace".to_string(),
            "default".to_string(),
        ];

        let mut ipv4_nexthops = Vec::new();
        let mut ipv6_nexthops = Vec::new();

        if infos.is_empty() {
        } else {
            for info in infos.iter() {
                // 根据 RouteInfo 的类型生成适当的 nexthop
                match &info.route {
                    RouteType::Ipv4(ipv4) => {
                        ipv4_nexthops.push("nexthop".to_string());
                        ipv4_nexthops.push("via".to_string());
                        ipv4_nexthops.push(ipv4.to_string());
                        ipv4_nexthops.push("dev".to_string());
                        ipv4_nexthops.push(info.iface_name.clone());
                        ipv4_nexthops.push("weight".to_string());
                        ipv4_nexthops.push(info.weight.to_string());
                    }
                    RouteType::Ipv6(ipv6) => {
                        ipv6_nexthops.push("nexthop".to_string());
                        ipv6_nexthops.push("via".to_string());
                        ipv6_nexthops.push(ipv6.to_string());
                        ipv6_nexthops.push("dev".to_string());
                        ipv6_nexthops.push(info.iface_name.clone());
                        ipv6_nexthops.push("weight".to_string());
                        ipv6_nexthops.push(info.weight.to_string());
                    }
                    RouteType::PPP => {
                        ipv4_nexthops.push("nexthop".to_string());
                        ipv4_nexthops.push("dev".to_string());
                        ipv4_nexthops.push(info.iface_name.clone());
                        ipv4_nexthops.push("weight".to_string());
                        ipv4_nexthops.push(info.weight.to_string());
                    }
                }
            }

            // 将所有 nexthop 加入到命令中
            if !ipv4_nexthops.is_empty() {
                ipv4_command.extend_from_slice(&ipv4_nexthops);
                tracing::info!("{:?}", ipv4_command.join(" "));
                if let Err(e) = std::process::Command::new("ip").args(ipv4_command).output() {
                    tracing::error!("{:?}", e);
                }
            } else {
                let ipv4_command = vec!["route", "del", "default"];
                if let Err(e) = std::process::Command::new("ip").args(ipv4_command).output() {
                    tracing::error!("{:?}", e);
                }
            }

            if !ipv6_nexthops.is_empty() {
                ipv6_command.extend_from_slice(&ipv6_nexthops);
                tracing::info!("{:?}", ipv6_command.join(" "));
                if let Err(e) = std::process::Command::new("ip").args(ipv6_command).output() {
                    tracing::error!("{:?}", e);
                }
            } else {
                let ipv6_command = vec!["-6", "route", "del", "default"];
                if let Err(e) = std::process::Command::new("ip").args(ipv6_command).output() {
                    tracing::error!("{:?}", e);
                }
            }
        }
    }
}
