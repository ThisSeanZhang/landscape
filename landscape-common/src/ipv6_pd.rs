use std::{collections::HashMap, net::Ipv6Addr, sync::Arc};

use dashmap::DashMap;

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LDIAPrefix {
    /// unit: s
    pub preferred_lifetime: u32,
    /// unit: s
    pub valid_lifetime: u32,
    pub prefix_len: u8,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix_ip: Ipv6Addr,

    pub last_update_time: f64,
}

#[derive(Clone)]
pub struct IAPrefixMap {
    inner: Arc<DashMap<String, LDIAPrefix>>,
}

impl IAPrefixMap {
    pub fn new() -> Self {
        IAPrefixMap { inner: Arc::new(DashMap::new()) }
    }

    pub fn store(&self, iface_name: &str, prefix: LDIAPrefix) {
        self.inner.insert(iface_name.to_string(), prefix);
    }

    pub fn remove(&self, iface_name: &str) {
        self.inner.remove(iface_name);
    }

    pub fn load(&self, iface_name: &str) -> Option<LDIAPrefix> {
        self.inner.get(iface_name).map(|v| v.value().clone())
    }

    pub fn get_info(&self) -> HashMap<String, Option<LDIAPrefix>> {
        self.inner.iter().map(|e| (e.key().clone(), Some(e.value().clone()))).collect()
    }
}
