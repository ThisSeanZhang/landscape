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

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IPV6PDPrefixStatus {
    pub expected_pd_len: u8,
    pub actual_prefix: Option<LDIAPrefix>,
    pub meets_expected_pd_len: Option<bool>,
}

impl IPV6PDPrefixStatus {
    pub fn new(expected_pd_len: u8, actual_prefix: Option<LDIAPrefix>) -> Self {
        let meets_expected_pd_len =
            actual_prefix.as_ref().map(|prefix| prefix.prefix_len <= expected_pd_len);
        Self {
            expected_pd_len,
            actual_prefix,
            meets_expected_pd_len,
        }
    }
}

#[derive(Clone)]
pub struct IAPrefixMap {
    inner: Arc<DashMap<String, IPV6PDPrefixStatus>>,
}

impl IAPrefixMap {
    pub fn new() -> Self {
        IAPrefixMap { inner: Arc::new(DashMap::new()) }
    }

    pub fn set_expected_pd_len(&self, iface_name: &str, expected_pd_len: u8) {
        self.inner
            .entry(iface_name.to_string())
            .and_modify(|e| e.expected_pd_len = expected_pd_len)
            .or_insert(IPV6PDPrefixStatus::new(expected_pd_len, None));
    }

    pub fn store(&self, iface_name: &str, prefix: LDIAPrefix, expected_pd_len: u8) {
        self.inner
            .entry(iface_name.to_string())
            .and_modify(|e| {
                e.expected_pd_len = expected_pd_len;
                e.actual_prefix = Some(prefix.clone());
                e.meets_expected_pd_len = Some(prefix.prefix_len <= e.expected_pd_len);
            })
            .or_insert(IPV6PDPrefixStatus::new(expected_pd_len, Some(prefix)));
    }

    pub fn remove(&self, iface_name: &str) {
        self.inner.remove(iface_name);
    }

    pub fn load(&self, iface_name: &str) -> Option<LDIAPrefix> {
        self.inner.get(iface_name).and_then(|v| v.actual_prefix.clone())
    }

    pub fn get_info(&self) -> HashMap<String, Option<LDIAPrefix>> {
        self.inner.iter().map(|e| (e.key().clone(), e.value().actual_prefix.clone())).collect()
    }

    pub fn get_prefix_statuses(&self) -> HashMap<String, IPV6PDPrefixStatus> {
        self.inner.iter().map(|e| (e.key().clone(), e.value().clone())).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::{IAPrefixMap, IPV6PDPrefixStatus, LDIAPrefix};

    fn prefix(prefix_len: u8) -> LDIAPrefix {
        LDIAPrefix {
            preferred_lifetime: 300,
            valid_lifetime: 600,
            prefix_len,
            prefix_ip: Ipv6Addr::LOCALHOST,
            last_update_time: 0.0,
        }
    }

    #[test]
    fn larger_or_equal_network_meets_expected_pd_len() {
        assert_eq!(IPV6PDPrefixStatus::new(60, Some(prefix(56))).meets_expected_pd_len, Some(true));
        assert_eq!(IPV6PDPrefixStatus::new(60, Some(prefix(60))).meets_expected_pd_len, Some(true));
    }

    #[test]
    fn smaller_network_does_not_meet_expected_pd_len() {
        assert_eq!(
            IPV6PDPrefixStatus::new(60, Some(prefix(64))).meets_expected_pd_len,
            Some(false)
        );
    }

    #[test]
    fn missing_prefix_has_no_expected_len_verdict() {
        assert_eq!(IPV6PDPrefixStatus::new(60, None).meets_expected_pd_len, None);
    }

    #[test]
    fn store_preserves_expected_pd_len_when_prefix_arrives() {
        let map = IAPrefixMap::new();
        map.set_expected_pd_len("wan0", 64);

        map.store("wan0", prefix(56), 64);

        let status = map.get_prefix_statuses().remove("wan0").unwrap();
        assert_eq!(status.expected_pd_len, 64);
        assert_eq!(status.meets_expected_pd_len, Some(true));
        assert!(status.actual_prefix.is_some());
    }

    #[test]
    fn set_expected_pd_len_before_prefix_creates_entry_without_prefix() {
        let map = IAPrefixMap::new();
        map.set_expected_pd_len("wan0", 58);

        let status = map.get_prefix_statuses().remove("wan0").unwrap();
        assert_eq!(status.expected_pd_len, 58);
        assert!(status.actual_prefix.is_none());
        assert!(status.meets_expected_pd_len.is_none());
    }

    #[test]
    fn store_writes_expected_pd_len_with_prefix() {
        let map = IAPrefixMap::new();

        map.store("wan0", prefix(56), 58);

        let status = map.get_prefix_statuses().remove("wan0").unwrap();
        assert_eq!(status.expected_pd_len, 58);
        assert_eq!(status.meets_expected_pd_len, Some(true));
    }
}
