use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
use landscape_common::wan_service::ipv6_pd::{IPV6PDPrefixStatus, LDIAPrefix};
use uuid::Uuid;

/// Process-wide PD prefix state, keyed by the wan link uuid
/// (`wan_links.id`). Filled by the WAN PD client; read by the LAN
/// IPv6 service, DDNS and the REST status views.
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

    use super::IAPrefixMap;
    use landscape_common::wan_service::ipv6_pd::LDIAPrefix;
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
