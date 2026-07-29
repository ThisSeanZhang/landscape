//! LAN hostname registry backed by enrolled-device and DHCP assignment events.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;

use landscape_common::event::hub::{
    EnrolledDeviceEvent, EnrolledDeviceEventReader, IPv4AssignEvent, IPv4AssignEventReader,
};
use landscape_common::sys_service::lan_hostname::LanHostnameConfig;

#[derive(Clone)]
struct HostnameRecord {
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
    from_enrolled_device: bool,
}

pub struct LanHostnameRegistry {
    hostname_map: Arc<DashMap<String, HostnameRecord>>,
    config: Arc<ArcSwap<LanHostnameConfig>>,
}

impl LanHostnameRegistry {
    pub fn new(
        config: LanHostnameConfig,
        initial_devices: Vec<(String, Ipv4Addr)>,
        ipv4_reader: IPv4AssignEventReader,
        device_reader: EnrolledDeviceEventReader,
    ) -> Arc<Self> {
        let hostname_map: Arc<DashMap<String, HostnameRecord>> = Arc::new(DashMap::new());

        for (hostname, ipv4) in &initial_devices {
            if let Ok(punycode) = idna::domain_to_ascii(hostname) {
                hostname_map.insert(
                    punycode,
                    HostnameRecord {
                        ipv4: *ipv4,
                        ipv6: None,
                        from_enrolled_device: true,
                    },
                );
            }
        }

        let registry = Arc::new(Self {
            hostname_map: hostname_map.clone(),
            config: Arc::new(ArcSwap::from_pointee(config)),
        });

        // Listener: device + DHCP events, serialized via select!
        {
            let map = hostname_map.clone();
            tokio::spawn(async move {
                use tokio::sync::broadcast::error::RecvError;
                let mut device_reader = device_reader;
                let mut ipv4_reader = ipv4_reader;
                let mut device_alive = true;
                let mut ipv4_alive = true;
                loop {
                    tokio::select! {
                        result = device_reader.recv(), if device_alive => {
                            match result {
                                Ok(event) => handle_device_event(&map, event),
                                Err(RecvError::Lagged(n)) => {
                                    tracing::warn!("lan_hostname: device event lagged by {n}");
                                }
                                Err(RecvError::Closed) => {
                                    tracing::info!("lan_hostname: device event channel closed");
                                    device_alive = false;
                                }
                            }
                        }
                        result = ipv4_reader.recv(), if ipv4_alive => {
                            match result {
                                Ok(event) => handle_ipv4_event(&map, event),
                                Err(RecvError::Lagged(n)) => {
                                    tracing::warn!("lan_hostname: ipv4 event lagged by {n}");
                                }
                                Err(RecvError::Closed) => {
                                    tracing::info!("lan_hostname: ipv4 event channel closed");
                                    ipv4_alive = false;
                                }
                            }
                        }
                    }
                    if !device_alive && !ipv4_alive {
                        break;
                    }
                }
            });
        }

        registry
    }

    pub fn update_config(&self, config: LanHostnameConfig) {
        self.config.store(Arc::new(config));
    }

    pub fn is_local_tld(&self, tld: &str) -> bool {
        let tld = tld.to_ascii_lowercase();
        let suffix = self.config.load().lan_suffix.to_ascii_lowercase();
        (!suffix.is_empty() && tld == suffix) || tld == "local"
    }

    pub fn resolve_a_by_hostname(&self, hostname: &str) -> Option<Ipv4Addr> {
        if hostname.is_empty() {
            return None;
        }
        let punycode = idna::domain_to_ascii(hostname).ok()?;
        self.hostname_map.get(&punycode).map(|r| r.ipv4)
    }

    pub fn resolve_aaaa_by_hostname(&self, hostname: &str) -> Option<Ipv6Addr> {
        if hostname.is_empty() {
            return None;
        }
        let punycode = idna::domain_to_ascii(hostname).ok()?;
        self.hostname_map.get(&punycode).and_then(|r| r.ipv6)
    }

    pub fn resolve_ptr_by_addr(&self, addr: &IpAddr) -> Option<String> {
        if !Self::is_managed_ptr_addr(addr) {
            return None;
        }
        let mut enrolled: Vec<String> = Vec::new();
        let mut dhcp: Vec<String> = Vec::new();
        for entry in self.hostname_map.iter() {
            let matches = match addr {
                IpAddr::V4(ip) => entry.value().ipv4 == *ip,
                IpAddr::V6(ip) => entry.value().ipv6 == Some(*ip),
            };
            if matches {
                if entry.value().from_enrolled_device {
                    enrolled.push(entry.key().clone());
                } else {
                    dhcp.push(entry.key().clone());
                }
            }
        }
        enrolled.sort_unstable();
        dhcp.sort_unstable();
        let hostname = enrolled.first().or_else(|| dhcp.first())?;
        let suffix = &self.config.load().lan_suffix;
        if suffix.is_empty() {
            Some(format!("{}.", hostname))
        } else {
            Some(format!("{}.{}.", hostname, suffix))
        }
    }

    pub fn is_managed_ptr_addr(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(ip) => {
                ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || is_shared_ipv4(*ip)
                    || ip.is_unspecified()
                    || ip.is_broadcast()
            }
            IpAddr::V6(ip) => {
                ip.is_unique_local()
                    || ip.is_loopback()
                    || ip.is_unicast_link_local()
                    || ip.is_unspecified()
            }
        }
    }

    pub fn set_ipv6(&self, hostname: &str, ipv6: Ipv6Addr) -> bool {
        if let Ok(punycode) = idna::domain_to_ascii(hostname) {
            if let Some(mut record) = self.hostname_map.get_mut(&punycode) {
                record.ipv6 = Some(ipv6);
                return true;
            }
        }
        false
    }
}

fn is_shared_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn handle_device_event(map: &DashMap<String, HostnameRecord>, event: EnrolledDeviceEvent) {
    match event {
        EnrolledDeviceEvent::Updated { old, new } => {
            if let Some(ref old_device) = old {
                if let Some(ref old_hostname) = old_device.hostname {
                    if let Ok(punycode) = idna::domain_to_ascii(old_hostname) {
                        map.remove(&punycode);
                    }
                }
            }
            if let (Some(ref hostname), Some(ipv4)) = (&new.hostname, new.ipv4) {
                if let Ok(punycode) = idna::domain_to_ascii(hostname) {
                    map.insert(
                        punycode,
                        HostnameRecord { ipv4, ipv6: new.ipv6, from_enrolled_device: true },
                    );
                }
            }
        }
        EnrolledDeviceEvent::Deleted { old } => {
            if let Some(ref hostname) = old.hostname {
                if let Ok(punycode) = idna::domain_to_ascii(hostname) {
                    map.remove(&punycode);
                }
            }
        }
    }
}

fn handle_ipv4_event(map: &DashMap<String, HostnameRecord>, event: IPv4AssignEvent) {
    match event {
        IPv4AssignEvent::Allocated(info) => {
            if let Some(hostname) = info.hostname {
                if let Ok(punycode) = idna::domain_to_ascii(&hostname) {
                    map.entry(punycode)
                        .and_modify(|rec| {
                            if rec.from_enrolled_device {
                                tracing::debug!(
                                    "lan_hostname: ignoring DHCP hostname '{}' -> {} (enrolled device wins)",
                                    hostname, info.ip
                                );
                                return;
                            }
                            rec.ipv4 = info.ip;
                        })
                        .or_insert_with(|| HostnameRecord {
                            ipv4: info.ip,
                            ipv6: None,
                            from_enrolled_device: false,
                        });
                }
            }
        }
        IPv4AssignEvent::Expired(info) => {
            if let Some(hostname) = info.hostname {
                if let Ok(punycode) = idna::domain_to_ascii(&hostname) {
                    map.remove_if(&punycode, |_, rec| !rec.from_enrolled_device);
                }
            }
        }
    }
}

impl LanHostnameRegistry {
    /// Creates a registry with ephemeral event channels for use in tests.
    /// Not intended for production use.
    pub fn new_for_test(config: LanHostnameConfig) -> Arc<Self> {
        let (_tx, rx) = tokio::sync::broadcast::channel(64);
        let (_tx2, rx2) = tokio::sync::broadcast::channel(64);
        Self::new(
            config,
            vec![],
            IPv4AssignEventReader::new(rx),
            EnrolledDeviceEventReader::new(rx2),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::event::hub::IPv4AssignInfo;
    use landscape_common::net::MacAddr;

    fn registry_with(records: &[(&str, HostnameRecord)]) -> LanHostnameRegistry {
        let map = DashMap::new();
        for (hostname, record) in records {
            map.insert((*hostname).to_string(), record.clone());
        }
        LanHostnameRegistry {
            hostname_map: Arc::new(map),
            config: Arc::new(ArcSwap::from_pointee(LanHostnameConfig {
                lan_suffix: "lan".to_string(),
            })),
        }
    }

    fn v4_record(ipv4: Ipv4Addr, from_enrolled_device: bool) -> HostnameRecord {
        HostnameRecord { ipv4, ipv6: None, from_enrolled_device }
    }

    fn assign_info(hostname: &str, ip: Ipv4Addr) -> IPv4AssignInfo {
        IPv4AssignInfo {
            iface_name: "eth0".to_string(),
            mac: MacAddr(0, 0, 0, 0, 0, 1),
            ip,
            hostname: Some(hostname.to_string()),
            device_id: None,
        }
    }

    #[test]
    fn ptr_survives_removal_of_another_hostname_sharing_the_ip() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let reg = registry_with(&[("alpha", v4_record(ip, false)), ("beta", v4_record(ip, false))]);

        assert!(reg.resolve_ptr_by_addr(&IpAddr::V4(ip)).is_some());

        reg.hostname_map.remove("alpha");
        assert_eq!(reg.resolve_ptr_by_addr(&IpAddr::V4(ip)), Some("beta.lan.".to_string()));

        reg.hostname_map.remove("beta");
        assert_eq!(reg.resolve_ptr_by_addr(&IpAddr::V4(ip)), None);
    }

    #[test]
    fn ptr_is_none_for_unmanaged_public_addr() {
        let reg = registry_with(&[]);
        assert!(reg.resolve_ptr_by_addr(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_none());
    }

    #[test]
    fn forward_lookup_has_no_builtin_localhost() {
        let reg = registry_with(&[]);
        assert!(reg.resolve_a_by_hostname("localhost").is_none());
        assert!(reg.resolve_aaaa_by_hostname("localhost").is_none());
    }

    #[test]
    fn dhcp_allocation_does_not_override_enrolled_device() {
        let map = DashMap::new();
        let enrolled_ip = Ipv4Addr::new(192, 168, 1, 10);
        map.insert("host".to_string(), v4_record(enrolled_ip, true));

        handle_ipv4_event(
            &map,
            IPv4AssignEvent::Allocated(assign_info("host", Ipv4Addr::new(192, 168, 1, 200))),
        );

        let record = map.get("host").unwrap();
        assert_eq!(record.ipv4, enrolled_ip);
        assert!(record.from_enrolled_device);
    }

    #[test]
    fn dhcp_expiry_removes_only_non_enrolled_records() {
        let map = DashMap::new();
        map.insert("lease".to_string(), v4_record(Ipv4Addr::new(192, 168, 1, 50), false));
        map.insert("device".to_string(), v4_record(Ipv4Addr::new(192, 168, 1, 51), true));

        handle_ipv4_event(
            &map,
            IPv4AssignEvent::Expired(assign_info("lease", Ipv4Addr::new(192, 168, 1, 50))),
        );
        handle_ipv4_event(
            &map,
            IPv4AssignEvent::Expired(assign_info("device", Ipv4Addr::new(192, 168, 1, 51))),
        );

        assert!(map.get("lease").is_none());
        assert!(map.get("device").is_some());
    }

    fn v6_record(ipv4: Ipv4Addr, ipv6: Ipv6Addr, from_enrolled_device: bool) -> HostnameRecord {
        HostnameRecord { ipv4, ipv6: Some(ipv6), from_enrolled_device }
    }

    fn registry_with_config(
        records: &[(&str, HostnameRecord)],
        lan_suffix: &str,
    ) -> LanHostnameRegistry {
        let map = DashMap::new();
        for (hostname, record) in records {
            map.insert((*hostname).to_string(), record.clone());
        }
        LanHostnameRegistry {
            hostname_map: Arc::new(map),
            config: Arc::new(ArcSwap::from_pointee(LanHostnameConfig {
                lan_suffix: lan_suffix.to_string(),
            })),
        }
    }

    // --- is_managed_ptr_addr ---

    #[test]
    fn managed_ptr_addr_accepts_private_ipv4() {
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 0, 1
        ))));
    }

    #[test]
    fn managed_ptr_addr_accepts_loopback_and_link_local() {
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn managed_ptr_addr_accepts_unique_local_ipv6() {
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn managed_ptr_addr_accepts_shared_cgn_ipv4() {
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(
            100, 64, 0, 1
        ))));
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 254
        ))));
    }

    #[test]
    fn managed_ptr_addr_accepts_unspecified_and_broadcast() {
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn managed_ptr_addr_rejects_public_ipv4() {
        assert!(!LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V4(Ipv4Addr::new(
            203, 0, 113, 1
        ))));
    }

    #[test]
    fn managed_ptr_addr_rejects_global_unicast_ipv6() {
        assert!(!LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!LanHostnameRegistry::is_managed_ptr_addr(&IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 1
        ))));
    }

    // --- resolve_a / resolve_aaaa with populated registry ---

    #[test]
    fn resolve_a_returns_ipv4_for_registered_hostname() {
        let ip = Ipv4Addr::new(10, 0, 0, 10);
        let reg = registry_with(&[("alpha", v4_record(ip, false))]);
        assert_eq!(reg.resolve_a_by_hostname("alpha"), Some(ip));
    }

    #[test]
    fn resolve_a_returns_none_for_unknown_hostname() {
        let reg = registry_with(&[]);
        assert_eq!(reg.resolve_a_by_hostname("unknown"), None);
    }

    #[test]
    fn resolve_a_returns_none_for_empty_hostname() {
        let reg = registry_with(&[("host", v4_record(Ipv4Addr::new(10, 0, 0, 1), false))]);
        assert_eq!(reg.resolve_a_by_hostname(""), None);
    }

    #[test]
    fn resolve_aaaa_returns_ipv6_for_registered_hostname() {
        let ipv4 = Ipv4Addr::new(10, 0, 0, 10);
        let ipv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let reg = registry_with(&[("alpha", v6_record(ipv4, ipv6, true))]);
        assert_eq!(reg.resolve_aaaa_by_hostname("alpha"), Some(ipv6));
    }

    #[test]
    fn resolve_aaaa_returns_none_when_only_ipv4_registered() {
        let ip = Ipv4Addr::new(10, 0, 0, 10);
        let reg = registry_with(&[("alpha", v4_record(ip, false))]);
        assert_eq!(reg.resolve_aaaa_by_hostname("alpha"), None);
    }

    // --- resolve_ptr_by_addr ---

    #[test]
    fn resolve_ptr_returns_fqdn_for_ipv6_addr() {
        let ipv4 = Ipv4Addr::new(10, 0, 0, 10);
        let ipv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 42);
        let reg = registry_with(&[("srv", v6_record(ipv4, ipv6, true))]);
        assert_eq!(reg.resolve_ptr_by_addr(&IpAddr::V6(ipv6)), Some("srv.lan.".to_string()));
    }

    #[test]
    fn resolve_ptr_returns_none_when_ipv6_not_matched() {
        let ipv4 = Ipv4Addr::new(10, 0, 0, 10);
        let ipv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let reg = registry_with(&[("srv", v6_record(ipv4, ipv6, true))]);
        let other = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 99);
        assert_eq!(reg.resolve_ptr_by_addr(&IpAddr::V6(other)), None);
    }

    #[test]
    fn resolve_ptr_returns_hostname_only_when_suffix_empty() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let reg = registry_with_config(&[("dev", v4_record(ip, false))], "");
        assert_eq!(reg.resolve_ptr_by_addr(&IpAddr::V4(ip)), Some("dev.".to_string()));
    }

    #[test]
    fn resolve_ptr_prefers_enrolled_device_over_dhcp_for_same_ip() {
        let ip = Ipv4Addr::new(10, 0, 0, 10);
        let reg =
            registry_with(&[("desktop-abc", v4_record(ip, false)), ("mysrv", v4_record(ip, true))]);
        assert_eq!(reg.resolve_ptr_by_addr(&IpAddr::V4(ip)), Some("mysrv.lan.".to_string()));
    }

    #[test]
    fn resolve_ptr_falls_back_to_dhcp_when_no_enrolled_device() {
        let ip = Ipv4Addr::new(10, 0, 0, 20);
        let reg = registry_with(&[("desktop-xyz", v4_record(ip, false))]);
        assert_eq!(reg.resolve_ptr_by_addr(&IpAddr::V4(ip)), Some("desktop-xyz.lan.".to_string()));
    }

    #[test]
    fn resolve_ptr_picks_first_alphabetical_among_enrolled() {
        let ip = Ipv4Addr::new(10, 0, 0, 30);
        let reg = registry_with(&[
            ("zulu", v4_record(ip, true)),
            ("alpha", v4_record(ip, true)),
            ("mid", v4_record(ip, false)),
        ]);
        assert_eq!(reg.resolve_ptr_by_addr(&IpAddr::V4(ip)), Some("alpha.lan.".to_string()));
    }

    #[test]
    fn resolve_ptr_picks_first_alphabetical_among_dhcp_only() {
        let ip = Ipv4Addr::new(10, 0, 0, 40);
        let reg =
            registry_with(&[("zebra", v4_record(ip, false)), ("apple", v4_record(ip, false))]);
        assert_eq!(reg.resolve_ptr_by_addr(&IpAddr::V4(ip)), Some("apple.lan.".to_string()));
    }

    #[test]
    fn resolve_ptr_ipv6_prefers_enrolled_over_dhcp() {
        let ipv4 = Ipv4Addr::new(10, 0, 0, 50);
        let ipv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 88);
        let reg = registry_with(&[
            ("dhcp-v6", v6_record(ipv4, ipv6, false)),
            ("enrolled-v6", v6_record(ipv4, ipv6, true)),
        ]);
        assert_eq!(
            reg.resolve_ptr_by_addr(&IpAddr::V6(ipv6)),
            Some("enrolled-v6.lan.".to_string())
        );
    }

    // --- is_local_tld ---

    #[test]
    fn is_local_tld_matches_configured_suffix() {
        let reg = registry_with(&[]);
        assert!(reg.is_local_tld("lan"));
    }

    #[test]
    fn is_local_tld_always_matches_local() {
        let reg = registry_with_config(&[], "");
        assert!(reg.is_local_tld("local"));

        let reg2 = registry_with_config(&[], "home.arpa");
        assert!(reg2.is_local_tld("local"));
    }

    #[test]
    fn is_local_tld_rejects_unknown_suffix() {
        let reg = registry_with(&[]);
        assert!(!reg.is_local_tld("com"));
        assert!(!reg.is_local_tld("example"));
    }

    #[test]
    fn is_local_tld_rejects_empty_suffix_when_config_empty() {
        let reg = registry_with_config(&[], "");
        assert!(!reg.is_local_tld(""));
        assert!(!reg.is_local_tld("lan"));
    }
}
