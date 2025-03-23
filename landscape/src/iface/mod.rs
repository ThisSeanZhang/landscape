use config::NetworkIfaceConfig;
use dev_wifi::LandScapeWifiInterface;
use futures::stream::TryStreamExt;
use rtnetlink::new_connection;
use serde::Serialize;

use crate::dev::LandScapeInterface;

pub mod config;
pub mod dev_wifi;
pub mod ip;

// 前端渲染拓扑节点
#[derive(Serialize, Debug, Clone)]
pub struct IfaceTopology {
    // 配置
    #[serde(flatten)]
    pub config: NetworkIfaceConfig,
    // 当前的状态: 除了 IP 之类的
    #[serde(flatten)]
    pub status: LandScapeInterface,

    pub wifi_info: Option<LandScapeWifiInterface>,
}

pub async fn get_iface_by_name(name: &str) -> Option<LandScapeInterface> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut links = handle.link().get().match_name(name.to_string()).execute();

    if let Ok(Some(msg)) = links.try_next().await {
        LandScapeInterface::new(msg)
    } else {
        None
    }
}
