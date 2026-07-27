use std::{collections::HashMap, net::Ipv6Addr, sync::Arc};

use dashmap::DashMap;

pub const fn prefix_len_meets_expectation(actual_prefix_len: u8, expected_pd_len: u8) -> bool {
    actual_prefix_len <= expected_pd_len
}

pub const fn pd_expectation_fits_snapshot(expected_pd_len: u8, snapshot_prefix_len: u8) -> bool {
    expected_pd_len <= snapshot_prefix_len
}

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
    pub actual_prefix: LDIAPrefix,
    pub meets_expected_pd_len: bool,
}

impl IPV6PDPrefixStatus {
    pub fn new(expected_pd_len: u8, actual_prefix: LDIAPrefix) -> Self {
        let meets_expected_pd_len =
            prefix_len_meets_expectation(actual_prefix.prefix_len, expected_pd_len);
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

    pub fn store(&self, iface_name: &str, prefix: LDIAPrefix, expected_pd_len: u8) {
        self.inner.insert(iface_name.to_string(), IPV6PDPrefixStatus::new(expected_pd_len, prefix));
    }

    pub fn remove(&self, iface_name: &str) -> Option<IPV6PDPrefixStatus> {
        self.inner.remove(iface_name).map(|(_, status)| status)
    }

    /// Return the acquired prefix without applying LAN capacity policy.
    pub fn load_actual(&self, iface_name: &str) -> Option<LDIAPrefix> {
        self.inner.get(iface_name).map(|v| v.actual_prefix.clone())
    }

    /// Return the acquired prefix only when it satisfies the WAN PD expectation.
    ///
    /// This is the WAN-side policy gate: it compares the acquired prefix length with
    /// `expected_pd_len`. LAN snapshot compatibility is a separate policy applied by
    /// the LAN IPv6 service.
    pub fn load_for_lan(&self, iface_name: &str) -> Option<(LDIAPrefix, u8)> {
        self.inner.get(iface_name).and_then(|status| {
            if status.meets_expected_pd_len {
                Some((status.actual_prefix.clone(), status.expected_pd_len))
            } else {
                None
            }
        })
    }

    pub fn get_info(&self) -> HashMap<String, Option<LDIAPrefix>> {
        self.inner
            .iter()
            .map(|e| (e.key().clone(), Some(e.value().actual_prefix.clone())))
            .collect()
    }

    pub fn get_prefix_statuses(&self) -> HashMap<String, IPV6PDPrefixStatus> {
        self.inner.iter().map(|e| (e.key().clone(), e.value().clone())).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::{
        pd_expectation_fits_snapshot, prefix_len_meets_expectation, IAPrefixMap,
        IPV6PDPrefixStatus, LDIAPrefix,
    };

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
        assert!(IPV6PDPrefixStatus::new(60, prefix(56)).meets_expected_pd_len);
        assert!(IPV6PDPrefixStatus::new(60, prefix(60)).meets_expected_pd_len);
    }

    #[test]
    fn compatibility_helpers_follow_prefix_length_ordering() {
        assert!(prefix_len_meets_expectation(56, 60));
        assert!(prefix_len_meets_expectation(60, 60));
        assert!(!prefix_len_meets_expectation(64, 60));

        assert!(pd_expectation_fits_snapshot(56, 60));
        assert!(pd_expectation_fits_snapshot(60, 60));
        assert!(!pd_expectation_fits_snapshot(64, 60));
    }

    #[test]
    fn smaller_network_does_not_meet_expected_pd_len() {
        assert!(!IPV6PDPrefixStatus::new(60, prefix(64)).meets_expected_pd_len);
    }

    #[test]
    fn store_writes_actual_prefix_and_expected_len_together() {
        let map = IAPrefixMap::new();
        map.store("wan0", prefix(56), 64);

        let status = map.get_prefix_statuses().remove("wan0").unwrap();
        assert_eq!(status.expected_pd_len, 64);
        assert!(status.meets_expected_pd_len);
        assert_eq!(status.actual_prefix.prefix_len, 56);
    }

    #[test]
    fn map_has_no_status_before_prefix_arrives() {
        let map = IAPrefixMap::new();
        assert!(map.get_prefix_statuses().is_empty());
    }

    #[test]
    fn store_writes_expected_pd_len_with_prefix() {
        let map = IAPrefixMap::new();

        map.store("wan0", prefix(56), 58);

        let status = map.get_prefix_statuses().remove("wan0").unwrap();
        assert_eq!(status.expected_pd_len, 58);
        assert!(status.meets_expected_pd_len);
    }

    #[test]
    fn lan_access_is_gated_but_actual_access_is_not() {
        let map = IAPrefixMap::new();
        map.store("wan0", prefix(64), 60);

        assert_eq!(map.load_actual("wan0").unwrap().prefix_len, 64);
        assert!(map.load_for_lan("wan0").is_none());

        map.store("wan0", prefix(56), 60);
        let (actual, expected_pd_len) = map.load_for_lan("wan0").unwrap();
        assert_eq!(actual.prefix_len, 56);
        assert_eq!(expected_pd_len, 60);
    }

    #[test]
    fn remove_returns_the_previous_status_and_clears_the_entry() {
        let map = IAPrefixMap::new();
        map.store("wan0", prefix(56), 60);

        let removed = map.remove("wan0").unwrap();

        assert_eq!(removed.expected_pd_len, 60);
        assert_eq!(removed.actual_prefix.prefix_len, 56);
        assert!(map.load_actual("wan0").is_none());
        assert!(map.remove("wan0").is_none());
    }
}
