use std::{collections::HashMap, net::Ipv6Addr, sync::Arc};

use dashmap::DashMap;
use uuid::Uuid;

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
    inner: Arc<DashMap<Uuid, IPV6PDPrefixStatus>>,
}

impl Default for IAPrefixMap {
    fn default() -> Self {
        Self::new()
    }
}

impl IAPrefixMap {
    pub fn new() -> Self {
        IAPrefixMap { inner: Arc::new(DashMap::new()) }
    }

    pub fn store(&self, link_id: Uuid, prefix: LDIAPrefix, expected_pd_len: u8) {
        self.inner.insert(link_id, IPV6PDPrefixStatus::new(expected_pd_len, prefix));
    }

    pub fn remove(&self, link_id: &Uuid) -> Option<IPV6PDPrefixStatus> {
        self.inner.remove(link_id).map(|(_, status)| status)
    }

    /// Return the acquired prefix without applying LAN capacity policy.
    pub fn load_actual(&self, link_id: &Uuid) -> Option<LDIAPrefix> {
        self.inner.get(link_id).map(|v| v.actual_prefix.clone())
    }

    /// Return the acquired prefix only when it satisfies the WAN PD expectation.
    ///
    /// This is the WAN-side policy gate: it compares the acquired prefix length with
    /// `expected_pd_len`. LAN snapshot compatibility is a separate policy applied by
    /// the LAN IPv6 service.
    pub fn load_for_lan(&self, link_id: &Uuid) -> Option<(LDIAPrefix, u8)> {
        self.inner.get(link_id).and_then(|status| {
            if status.meets_expected_pd_len {
                Some((status.actual_prefix.clone(), status.expected_pd_len))
            } else {
                None
            }
        })
    }

    pub fn get_info(&self) -> HashMap<Uuid, Option<LDIAPrefix>> {
        self.inner.iter().map(|e| (*e.key(), Some(e.value().actual_prefix.clone()))).collect()
    }

    pub fn get_prefix_statuses(&self) -> HashMap<Uuid, IPV6PDPrefixStatus> {
        self.inner.iter().map(|e| (*e.key(), e.value().clone())).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::{
        IAPrefixMap, IPV6PDPrefixStatus, LDIAPrefix, pd_expectation_fits_snapshot,
        prefix_len_meets_expectation,
    };
    use uuid::Uuid;

    fn link_id() -> Uuid {
        Uuid::nil()
    }

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
        map.store(link_id(), prefix(56), 64);

        let status = map.get_prefix_statuses().remove(&link_id()).unwrap();
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

        map.store(link_id(), prefix(56), 58);

        let status = map.get_prefix_statuses().remove(&link_id()).unwrap();
        assert_eq!(status.expected_pd_len, 58);
        assert!(status.meets_expected_pd_len);
    }

    #[test]
    fn lan_access_is_gated_but_actual_access_is_not() {
        let map = IAPrefixMap::new();
        map.store(link_id(), prefix(64), 60);

        assert_eq!(map.load_actual(&link_id()).unwrap().prefix_len, 64);
        assert!(map.load_for_lan(&link_id()).is_none());

        map.store(link_id(), prefix(56), 60);
        let (actual, expected_pd_len) = map.load_for_lan(&link_id()).unwrap();
        assert_eq!(actual.prefix_len, 56);
        assert_eq!(expected_pd_len, 60);
    }

    #[test]
    fn remove_returns_the_previous_status_and_clears_the_entry() {
        let map = IAPrefixMap::new();
        map.store(link_id(), prefix(56), 60);

        let removed = map.remove(&link_id()).unwrap();

        assert_eq!(removed.expected_pd_len, 60);
        assert_eq!(removed.actual_prefix.prefix_len, 56);
        assert!(map.load_actual(&link_id()).is_none());
        assert!(map.remove(&link_id()).is_none());
    }
}
