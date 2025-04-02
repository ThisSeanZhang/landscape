use std::{collections::HashMap, net::Ipv6Addr};

use once_cell::sync::Lazy;
use tokio::sync::{watch, RwLock};

pub mod default_router;

pub static LD_PD_WATCHES: Lazy<IAPrefixMap> = Lazy::new(IAPrefixMap::new);

#[derive(Debug, Clone)]
pub struct LDIAPrefix {
    /// unit: s
    pub preferred_lifetime: u32,
    /// unit: s
    pub valid_lifetime: u32,
    pub prefix_len: u8,
    pub prefix_ip: Ipv6Addr,
}

pub struct IAPrefixMap {
    infos: RwLock<HashMap<String, watch::Sender<Option<LDIAPrefix>>>>,
}

impl IAPrefixMap {
    fn new() -> Self {
        IAPrefixMap { infos: RwLock::new(HashMap::new()) }
    }

    // 初始化一个 channel，如果不存在则创建
    pub async fn init(&self, iface_name: &str) {
        let mut infos = self.infos.write().await;
        // 如果不存在则创建一个初始值为 None 的 channel
        if !infos.contains_key(iface_name) {
            let (tx, _rx) = watch::channel(None);
            infos.insert(iface_name.to_string(), tx);
        }
    }

    // 将指定接口名称对应的 LDIAPrefix 值更新为 None
    pub async fn clean(&self, iface_name: &str) {
        let infos = self.infos.read().await;
        if let Some(sender) = infos.get(iface_name) {
            let _ = sender.send_replace(None);
        }
    }

    // 插入或替换接口名称对应的 LDIAPrefix 值
    pub async fn insert_or_replace(&self, iface_name: &str, ia_prefix: LDIAPrefix) {
        let mut infos = self.infos.write().await;
        if let Some(sender) = infos.get(iface_name) {
            tracing::debug!("replace new ia_prefix: {:#?}", ia_prefix);
            // 通过 send 更新 channel 中的值
            let _ = sender.send_replace(Some(ia_prefix));
        } else {
            tracing::debug!("insert new ia_prefix: {:#?}", ia_prefix);
            // 如果还没有为该接口创建 channel，则创建一个新的，并设置初始值
            let (tx, _rx) = watch::channel(Some(ia_prefix));
            infos.insert(iface_name.to_string(), tx);
        }
    }

    // 返回一个 watch receiver，用于监听指定接口名称对应的 LDIAPrefix 更新
    pub async fn get_ia_prefix(&self, iface_name: &str) -> watch::Receiver<Option<LDIAPrefix>> {
        let mut infos = self.infos.write().await;
        if let Some(sender) = infos.get(iface_name) {
            tracing::debug!("reuse a sender: {:?}", iface_name);
            sender.subscribe()
        } else {
            tracing::debug!("create a new sender: {:?}", iface_name);
            // 如果没有找到，则先创建一个 channel，然后返回其 receiver
            let (tx, rx) = watch::channel(None);
            infos.insert(iface_name.to_string(), tx);
            rx
        }
    }
}
