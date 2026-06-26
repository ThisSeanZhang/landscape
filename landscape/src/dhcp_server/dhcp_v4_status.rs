use std::{collections::HashMap, net::Ipv4Addr, time::Instant};

use cidr::Ipv4Inet;
use landscape_common::{
    dhcp::v4_server::{
        config::{CustomDhcpOption, DHCPv4ServerConfig},
        status::{DHCPv4OfferInfo, DHCPv4OfferInfoItem},
    },
    enrolled_device::EnrolledDevice,
    net::MacAddr,
    utils::time::get_f64_timestamp,
};
use uuid::Uuid;

const OFFER_VALID_TIME: u32 = 20;

#[derive(Debug)]
pub struct DHCPv4ServerOfferedCache {
    pub hostname: Option<String>,
    pub ip: Ipv4Addr,
    pub relative_offer_time: u64,
    pub valid_time: u32,
    pub is_static: bool,
    pub prev_ip: Option<Ipv4Addr>,
}

impl DHCPv4ServerOfferedCache {
    fn get_expire_time(&self) -> u64 {
        self.relative_offer_time + self.valid_time as u64
    }
}

#[derive(Debug, Clone, Default)]
pub struct PerMacDhcpOptions {
    pub custom_options: Vec<CustomDhcpOption>,
    pub filter_options: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAllocSource {
    Static(MacAddr),
    Dynamic,
    Declined,
}

#[derive(Debug, Clone)]
pub struct StaticBindingEntry {
    pub ipv4: Ipv4Addr,
    pub custom_options: Vec<CustomDhcpOption>,
    pub filter_options: Vec<u8>,
    pub device_id: Option<Uuid>,
    pub hostname: Option<String>,
}

impl StaticBindingEntry {
    pub fn from_enrolled(device: &EnrolledDevice) -> Option<Self> {
        Some(Self {
            ipv4: device.ipv4?,
            custom_options: device.dhcp_custom_options.clone(),
            filter_options: device.dhcp_filter_options.clone(),
            device_id: Some(device.id),
            hostname: device.hostname.clone(),
        })
    }
}

#[derive(Debug)]
pub struct DhcpV4AssignStatus {
    pub ip_range_start: Ipv4Inet,
    pub range_capacity: u32,
    pub boot_time: f64,
    pub relative_boot_time: Instant,
    pub static_bindings: HashMap<MacAddr, StaticBindingEntry>,
    pub ip_owner: HashMap<Ipv4Addr, MacAddr>,
    pub per_mac_options: HashMap<MacAddr, PerMacDhcpOptions>,
    pub allocated_host: HashMap<Ipv4Addr, IpAllocSource>,
    pub offered_ip: HashMap<MacAddr, DHCPv4ServerOfferedCache>,
}

impl DhcpV4AssignStatus {
    pub fn from_config_and_devices(
        config: &DHCPv4ServerConfig,
        enrolled_devices: Vec<EnrolledDevice>,
    ) -> Self {
        let ip_range_start = Ipv4Inet::new(config.ip_range_start, config.network_mask).unwrap();
        let ip_addr_end = match config.ip_range_end {
            Some(addr) if addr != Ipv4Addr::UNSPECIFIED => addr,
            _ => ip_range_start.last_address(),
        };
        let range_capacity = u32::from(ip_addr_end) - u32::from(config.ip_range_start);

        let mut status = DhcpV4AssignStatus {
            ip_range_start,
            range_capacity,
            boot_time: get_f64_timestamp(),
            relative_boot_time: Instant::now(),
            static_bindings: HashMap::new(),
            ip_owner: HashMap::new(),
            per_mac_options: HashMap::new(),
            allocated_host: HashMap::new(),
            offered_ip: HashMap::new(),
        };

        for device in enrolled_devices {
            if let Some(ipv4) = device.ipv4 {
                if let Some(old_ip) = status
                    .static_bindings
                    .insert(
                        device.mac,
                        StaticBindingEntry {
                            ipv4,
                            custom_options: device.dhcp_custom_options.clone(),
                            filter_options: device.dhcp_filter_options.clone(),
                            device_id: Some(device.id),
                            hostname: device.hostname.clone(),
                        },
                    )
                    .map(|e| e.ipv4)
                {
                    status.allocated_host.remove(&old_ip);
                    status.ip_owner.remove(&old_ip);
                }
                if let Some(old_mac) = status.ip_owner.insert(ipv4, device.mac) {
                    if old_mac != device.mac {
                        status.static_bindings.remove(&old_mac);
                        status.offered_ip.remove(&old_mac);
                    }
                }
                status.allocated_host.insert(ipv4, IpAllocSource::Static(device.mac));
                status.offered_ip.insert(
                    device.mac,
                    DHCPv4ServerOfferedCache {
                        hostname: device.hostname.clone(),
                        ip: ipv4,
                        relative_offer_time: 0,
                        valid_time: 86400,
                        is_static: true,
                        prev_ip: None,
                    },
                );
            }

            if !device.dhcp_custom_options.is_empty() || !device.dhcp_filter_options.is_empty() {
                status.per_mac_options.insert(
                    device.mac,
                    PerMacDhcpOptions {
                        custom_options: device.dhcp_custom_options,
                        filter_options: device.dhcp_filter_options,
                    },
                );
            }
        }

        status
    }

    pub fn add_or_update_binding(&mut self, mac: MacAddr, entry: StaticBindingEntry) {
        let ip = entry.ipv4;

        let kicked = if matches!(self.allocated_host.get(&ip), Some(IpAllocSource::Dynamic)) {
            self.find_dynamic_owner_of_ip(ip).map(|z_mac| {
                let hostname = self.offered_ip.get(&z_mac).and_then(|c| c.hostname.clone());
                self.offered_ip.remove(&z_mac);
                (z_mac, hostname)
            })
        } else {
            None
        };

        if let Some(old_entry) = self.static_bindings.remove(&mac) {
            self.ip_owner.remove(&old_entry.ipv4);
            if let Some(IpAllocSource::Static(m)) = self.allocated_host.get(&old_entry.ipv4) {
                if *m == mac {
                    self.allocated_host.remove(&old_entry.ipv4);
                }
            }
            self.offered_ip.remove(&mac);
            self.per_mac_options.remove(&mac);
        }

        if let Some(old_mac) = self.ip_owner.insert(ip, mac) {
            if old_mac != mac {
                self.static_bindings.remove(&old_mac);
                self.offered_ip.remove(&old_mac);
                self.per_mac_options.remove(&old_mac);
            }
        }

        self.static_bindings.insert(mac, entry.clone());
        self.allocated_host.insert(ip, IpAllocSource::Static(mac));
        self.offered_ip.insert(
            mac,
            DHCPv4ServerOfferedCache {
                hostname: entry.hostname.clone(),
                ip,
                relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                valid_time: 86400,
                is_static: true,
                prev_ip: None,
            },
        );
        if !entry.custom_options.is_empty() || !entry.filter_options.is_empty() {
            self.per_mac_options.insert(
                mac,
                PerMacDhcpOptions {
                    custom_options: entry.custom_options,
                    filter_options: entry.filter_options,
                },
            );
        }

        if let Some((z_mac, hostname)) = kicked {
            self.offer_ip(&z_mac, hostname);
            if let Some(cache) = self.offered_ip.get_mut(&z_mac) {
                cache.prev_ip = Some(ip);
            }
        }
    }

    pub fn remove_binding(&mut self, mac: &MacAddr) {
        let Some(entry) = self.static_bindings.remove(mac) else {
            return;
        };
        let ip = entry.ipv4;

        self.ip_owner.remove(&ip);
        self.offered_ip.remove(mac);
        self.per_mac_options.remove(mac);

        if let Some(IpAllocSource::Static(m)) = self.allocated_host.get(&ip) {
            if *m == *mac {
                let has_dynamic = self.offered_ip.values().any(|c| c.ip == ip && !c.is_static);
                if !has_dynamic {
                    self.allocated_host.remove(&ip);
                }
            }
        }
    }

    fn find_dynamic_owner_of_ip(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.offered_ip.iter().find_map(|(mac, cache)| {
            if cache.ip == ip && !cache.is_static {
                Some(*mac)
            } else {
                None
            }
        })
    }

    pub fn offer_ip(&mut self, mac_addr: &MacAddr, hostname: Option<String>) -> Option<Ipv4Addr> {
        if let Some(DHCPv4ServerOfferedCache { ip, .. }) = self.offered_ip.get(mac_addr) {
            return Some(*ip);
        }

        let mut seed = mac_addr.u32_ckecksum();
        loop {
            if self.allocated_host.len() as u32 == self.range_capacity {
                if self.clean_expire_ip().is_empty() {
                    break;
                }
            }
            let index = seed % self.range_capacity;
            let (client_addr, _overflow) = self.ip_range_start.overflowing_add_u32(index);
            let address = client_addr.address();
            if self.allocated_host.contains_key(&address) {
                seed += 1;
            } else {
                self.offered_ip.insert(
                    *mac_addr,
                    DHCPv4ServerOfferedCache {
                        hostname,
                        ip: address,
                        relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                        valid_time: OFFER_VALID_TIME,
                        is_static: false,
                        prev_ip: None,
                    },
                );
                self.allocated_host.insert(address, IpAllocSource::Dynamic);
                return Some(address);
            }
        }
        None
    }

    pub fn ack_request(
        &mut self,
        mac_addr: &MacAddr,
        ip_addr: Ipv4Addr,
        hostname: Option<String>,
        address_lease_time: u32,
    ) -> bool {
        if self.conflicts_with_static_binding(mac_addr, ip_addr) {
            return false;
        }

        if let Some(offered_cache) = self.offered_ip.get_mut(mac_addr) {
            if offered_cache.ip == ip_addr {
                offered_cache.hostname = hostname;
                if !offered_cache.is_static {
                    offered_cache.valid_time = address_lease_time;
                }
                offered_cache.relative_offer_time = self.relative_boot_time.elapsed().as_secs();
                return true;
            } else {
                tracing::error!(
                    "client: {mac_addr:?} request ip: {ip_addr:?}, not same as offer: {:?}",
                    offered_cache.ip
                )
            }
        } else {
            if self.allocated_host.contains_key(&ip_addr) {
                tracing::error!(
                    "Requested IP {ip_addr:?} is already allocated to another client, request by {mac_addr:?}"
                );
                return false;
            }

            if !self.is_ip_in_range(ip_addr) {
                tracing::warn!("Requested IP out of range");
                return false;
            }

            let lease_cache = DHCPv4ServerOfferedCache {
                hostname,
                ip: ip_addr,
                is_static: false,
                valid_time: address_lease_time,
                relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                prev_ip: None,
            };

            self.offered_ip.insert(*mac_addr, lease_cache);
            self.allocated_host.insert(ip_addr, IpAllocSource::Dynamic);

            tracing::info!("Assigned unoffered IP {ip_addr:?} to client {mac_addr:?}");
            return true;
        }
        false
    }

    pub fn clean_expire_ip(&mut self) -> Vec<(MacAddr, Ipv4Addr)> {
        let current_time = self.relative_boot_time.elapsed().as_secs();

        let mut expired: Vec<(MacAddr, Ipv4Addr)> = Vec::new();
        self.offered_ip.retain(|mac, value| {
            if value.is_static {
                true
            } else if current_time > value.get_expire_time() {
                expired.push((*mac, value.ip));
                false
            } else {
                true
            }
        });

        self.allocated_host.retain(|_key, source| !matches!(source, IpAllocSource::Declined));

        for (_, ip) in &expired {
            self.allocated_host.remove(ip);
        }

        if !expired.is_empty() {
            let ips: Vec<_> = expired.iter().map(|(_, ip)| ip).collect();
            tracing::info!("DHCPv4 server cleans up these IPs: {ips:?}");
        }
        expired
    }

    pub fn release_ip(&mut self, mac: &MacAddr, ip: Ipv4Addr) -> bool {
        if self.offered_ip.remove(mac).is_some() {
            self.allocated_host.remove(&ip);
            true
        } else {
            false
        }
    }

    pub fn conflicts_with_static_binding(&self, mac_addr: &MacAddr, ip_addr: Ipv4Addr) -> bool {
        if let Some(entry) = self.static_bindings.get(mac_addr) {
            if entry.ipv4 != ip_addr {
                tracing::warn!(
                    "client {:?} requested {:?}, but static binding requires {:?}",
                    mac_addr,
                    ip_addr,
                    entry.ipv4
                );
                return true;
            }
        }

        if let Some(static_mac) = self.ip_owner.get(&ip_addr) {
            if static_mac != mac_addr {
                tracing::warn!(
                    "client {:?} requested static IP {:?} owned by {:?}",
                    mac_addr,
                    ip_addr,
                    static_mac
                );
                return true;
            }
        }

        false
    }

    pub fn add_decline_ip(&mut self, ip: Ipv4Addr) {
        if !self.allocated_host.contains_key(&ip) {
            self.allocated_host.insert(ip, IpAllocSource::Declined);
        }
    }

    pub fn is_ip_in_range(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let start = u32::from(self.ip_range_start.address());
        let end = start + self.range_capacity;
        ip_u32 >= start && ip_u32 < end
    }

    pub fn get_offered_info(&self) -> DHCPv4OfferInfo {
        let mut offered_ips = Vec::with_capacity(self.offered_ip.len());
        let relative_boot_time = self.relative_boot_time.elapsed().as_secs();
        for (
            mac,
            DHCPv4ServerOfferedCache {
                ip,
                relative_offer_time,
                valid_time,
                is_static,
                hostname,
                prev_ip,
            },
        ) in self.offered_ip.iter()
        {
            offered_ips.push(DHCPv4OfferInfoItem {
                hostname: hostname.clone(),
                mac: *mac,
                ip: *ip,
                relative_active_time: *relative_offer_time,
                expire_time: *valid_time,
                is_static: *is_static,
                prev_ip: *prev_ip,
            });
        }
        DHCPv4OfferInfo {
            boot_time: self.boot_time,
            relative_boot_time,
            offered_ips,
        }
    }

    #[cfg(test)]
    pub fn init_for_test(config: DHCPv4ServerConfig) -> Self {
        Self::from_config_and_devices(&config, vec![])
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::{net::Ipv4Addr, thread::sleep, time::Duration};

    use landscape_common::{
        dhcp::v4_server::config::{CustomDhcpOption, DHCPv4ServerConfig},
        enrolled_device::EnrolledDevice,
        net::MacAddr,
    };

    use super::*;

    fn make_mac(s: &str) -> MacAddr {
        MacAddr::from_str(s).unwrap()
    }

    fn default_config() -> DHCPv4ServerConfig {
        DHCPv4ServerConfig::default()
    }

    #[test]
    fn t1_from_config_and_devices_with_two_devices() {
        let config = default_config();
        let mac1 = make_mac("00:00:00:00:00:01");
        let mac2 = make_mac("00:00:00:00:00:02");
        let ip1 = Ipv4Addr::new(192, 168, 5, 10);
        let ip2 = Ipv4Addr::new(192, 168, 5, 20);

        let d1 = EnrolledDevice {
            mac: mac1,
            name: "d1".to_string(),
            ipv4: Some(ip1),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"d1"}))
                .unwrap()
        };
        let d2 = EnrolledDevice {
            mac: mac2,
            name: "d2".to_string(),
            ipv4: Some(ip2),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:02","name":"d2"}))
                .unwrap()
        };

        let status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d1, d2]);

        assert_eq!(status.static_bindings.len(), 2);
        assert_eq!(status.ip_owner.len(), 2);
        assert_eq!(status.offered_ip.len(), 2);
        assert_eq!(status.allocated_host.len(), 2);
        assert_eq!(status.static_bindings.get(&mac1).unwrap().ipv4, ip1);
        assert_eq!(status.static_bindings.get(&mac2).unwrap().ipv4, ip2);
        let info = status.get_offered_info();
        let static_items: Vec<_> = info.offered_ips.iter().filter(|i| i.is_static).collect();
        assert_eq!(static_items.len(), 2);
    }

    #[test]
    fn t2_offer_ip_first() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac = make_mac("00:00:00:00:00:01");
        let result = status.offer_ip(&mac, None);
        assert!(result.is_some());
        assert_eq!(status.offered_ip.len(), 1);
        assert_eq!(status.allocated_host.len(), 1);
    }

    #[test]
    fn t3_offer_ip_cache_hit() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac = make_mac("00:00:00:00:00:01");
        let first = status.offer_ip(&mac, None).unwrap();
        let second = status.offer_ip(&mac, None).unwrap();
        assert_eq!(first, second);
        assert_eq!(status.offered_ip.len(), 1);
    }

    #[test]
    fn t4_offer_until_full() {
        let mut config = default_config();
        config.ip_range_start = Ipv4Addr::new(192, 168, 5, 200);
        config.ip_range_end = Some(Ipv4Addr::new(192, 168, 5, 203));
        let mut status = DhcpV4AssignStatus::init_for_test(config);

        let mut ips: HashSet<Ipv4Addr> = HashSet::new();
        for i in 0..3 {
            let mac = MacAddr::from([0, 0, 0, 0, 0, i + 1]);
            let result = status.offer_ip(&mac, None);
            assert!(result.is_some(), "failed at device {}", i);
            ips.insert(result.unwrap());
        }
        assert_eq!(ips.len(), 3, "should get 3 unique IPs");
        let mac = MacAddr::from([0, 0, 0, 0, 0, 4]);
        assert!(status.offer_ip(&mac, None).is_none(), "4th should fail");
    }

    #[test]
    fn t5_clean_expire_preserves_static() {
        let config = default_config();
        let mac_static = make_mac("00:00:00:00:00:01");
        let static_ip = Ipv4Addr::new(192, 168, 5, 10);

        let d = EnrolledDevice {
            mac: mac_static,
            name: "s".to_string(),
            ipv4: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        let mac_dyn = make_mac("00:00:00:00:00:02");
        let dyn_ip = status.offer_ip(&mac_dyn, None).unwrap();
        assert_ne!(dyn_ip, static_ip);

        sleep(Duration::from_secs(25));
        status.clean_expire_ip();

        assert!(
            status.offered_ip.contains_key(&mac_static),
            "static entry should survive clean_expire_ip"
        );
        assert!(
            !status.offered_ip.contains_key(&mac_dyn),
            "expired dynamic entry should be removed"
        );
        assert_eq!(status.allocated_host.get(&static_ip), Some(&IpAllocSource::Static(mac_static)));
    }

    #[test]
    fn t6_clean_expire_triggered_by_offer_when_full() {
        let mut config = default_config();
        config.ip_range_start = Ipv4Addr::new(192, 168, 5, 200);
        config.ip_range_end = Some(Ipv4Addr::new(192, 168, 5, 203));
        let mut status = DhcpV4AssignStatus::init_for_test(config);

        for i in 0..3 {
            let mac = MacAddr::from([0, 0, 0, 0, 0, i + 1]);
            let _ = status.offer_ip(&mac, None).unwrap();
        }

        sleep(Duration::from_secs(25));

        let mac4 = MacAddr::from([0, 0, 0, 0, 0, 4]);
        let result = status.offer_ip(&mac4, None);
        assert!(result.is_some(), "should allocate after cleanup via offer_ip");
    }

    #[test]
    fn t7_add_static_binding_no_conflict() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);

        status.add_or_update_binding(
            mac,
            StaticBindingEntry {
                ipv4: ip,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let info = status.get_offered_info();
        let static_item = info.offered_ips.iter().find(|i| i.mac == mac).unwrap();
        assert!(static_item.is_static);
        assert_eq!(static_item.ip, ip);
        assert_eq!(static_item.prev_ip, None);
        assert_eq!(status.allocated_host.get(&ip), Some(&IpAllocSource::Static(mac)));
    }

    #[test]
    fn t8_kick_dynamic_when_static_claims_ip() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac_z = make_mac("00:00:00:00:00:01");
        let ip_y = status.offer_ip(&mac_z, Some("dyn-client".to_string())).unwrap();

        let mac_x = make_mac("00:00:00:00:00:02");
        status.add_or_update_binding(
            mac_x,
            StaticBindingEntry {
                ipv4: ip_y,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let info = status.get_offered_info();
        let static_item = info.offered_ips.iter().find(|i| i.mac == mac_x).unwrap();
        assert!(static_item.is_static);
        assert_eq!(static_item.ip, ip_y);

        let z_item = info.offered_ips.iter().find(|i| i.mac == mac_z).unwrap();
        assert!(!z_item.is_static);
        assert_ne!(z_item.ip, ip_y);
        assert_eq!(z_item.prev_ip, Some(ip_y));
    }

    #[test]
    fn t8a_kicked_client_offer_ip_returns_cached() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac_z = make_mac("00:00:00:00:00:01");
        let ip_y = status.offer_ip(&mac_z, Some("dyn".to_string())).unwrap();

        let mac_x = make_mac("00:00:00:00:00:02");
        status.add_or_update_binding(
            mac_x,
            StaticBindingEntry {
                ipv4: ip_y,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let new_ip = status.offer_ip(&mac_z, None);
        assert!(new_ip.is_some());
        assert_ne!(new_ip.unwrap(), ip_y);
    }

    #[test]
    fn t8b_kicked_client_ack_request_new_ip() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac_z = make_mac("00:00:00:00:00:01");
        let ip_y = status.offer_ip(&mac_z, Some("dyn".to_string())).unwrap();

        let mac_x = make_mac("00:00:00:00:00:02");
        status.add_or_update_binding(
            mac_x,
            StaticBindingEntry {
                ipv4: ip_y,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let new_ip = status.offer_ip(&mac_z, None).unwrap();
        let result = status.ack_request(&mac_z, new_ip, None, 86400);
        assert!(result);
    }

    #[test]
    fn t8c_kicked_client_ack_request_old_ip_fails() {
        let mut status = DhcpV4AssignStatus::init_for_test(default_config());
        let mac_z = make_mac("00:00:00:00:00:01");
        let ip_y = status.offer_ip(&mac_z, Some("dyn".to_string())).unwrap();

        let mac_x = make_mac("00:00:00:00:00:02");
        status.add_or_update_binding(
            mac_x,
            StaticBindingEntry {
                ipv4: ip_y,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        let result = status.ack_request(&mac_z, ip_y, None, 86400);
        assert!(!result);
    }

    #[test]
    fn t9_static_mac_ack_own_ip() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);
        assert!(status.ack_request(&mac, ip, None, 86400));
    }

    #[test]
    fn t10_static_mac_ack_other_ip_fails() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let other_ip = Ipv4Addr::new(192, 168, 5, 20);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);
        assert!(!status.ack_request(&mac, other_ip, None, 86400));
    }

    #[test]
    fn t11_remove_static_binding_releases_ip() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        assert!(status.offered_ip.contains_key(&mac));
        assert!(status.allocated_host.contains_key(&ip));

        status.remove_binding(&mac);

        assert!(!status.offered_ip.contains_key(&mac));
        assert!(!status.allocated_host.contains_key(&ip));
        assert!(status.static_bindings.is_empty());
        assert!(status.ip_owner.is_empty());
    }

    #[test]
    fn t12_remove_static_binding_keeps_ah_if_dynamic_exists() {
        let config = default_config();
        let mac_static = make_mac("00:00:00:00:00:01");
        let static_ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac: mac_static,
            name: "s".to_string(),
            ipv4: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        let mac_dyn = make_mac("00:00:00:00:00:02");
        let dyn_ip = status.offer_ip(&mac_dyn, None).unwrap();
        assert_ne!(dyn_ip, static_ip);

        status.remove_binding(&mac_static);

        assert!(!status.offered_ip.contains_key(&mac_static));
        assert!(!status.allocated_host.contains_key(&static_ip));
        assert!(status.allocated_host.contains_key(&dyn_ip));
        assert!(status.offered_ip.contains_key(&mac_dyn));
    }

    #[test]
    fn t13_update_binding_same_mac_different_ip() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip_old = Ipv4Addr::new(192, 168, 5, 10);
        let ip_new = Ipv4Addr::new(192, 168, 5, 20);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip_old),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        status.add_or_update_binding(
            mac,
            StaticBindingEntry {
                ipv4: ip_new,
                custom_options: vec![],
                filter_options: vec![],
                device_id: None,
                hostname: None,
            },
        );

        assert!(!status.allocated_host.contains_key(&ip_old));
        assert_eq!(status.allocated_host.get(&ip_new), Some(&IpAllocSource::Static(mac)));
        assert_eq!(status.offered_ip.get(&mac).unwrap().ip, ip_new);
        assert!(status.offered_ip.get(&mac).unwrap().is_static);
    }

    #[test]
    fn t14_update_binding_options_change() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            dhcp_custom_options: vec![CustomDhcpOption::TFTPServerName("old".to_string())],
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        let old_opts = status.per_mac_options.get(&mac).unwrap().custom_options.clone();
        assert_eq!(old_opts.len(), 1);

        status.add_or_update_binding(
            mac,
            StaticBindingEntry {
                ipv4: ip,
                custom_options: vec![CustomDhcpOption::BootfileName("new.kpxe".to_string())],
                filter_options: vec![15],
                device_id: None,
                hostname: None,
            },
        );

        let new_opts = status.per_mac_options.get(&mac).unwrap().custom_options.clone();
        assert_eq!(new_opts.len(), 1);
        assert!(matches!(new_opts[0], CustomDhcpOption::BootfileName(_)));
        assert_eq!(status.per_mac_options.get(&mac).unwrap().filter_options, vec![15]);
    }

    #[test]
    fn t15_static_entry_survives_clean_expire() {
        let config = default_config();
        let mac = make_mac("00:00:00:00:00:01");
        let ip = Ipv4Addr::new(192, 168, 5, 10);
        let d = EnrolledDevice {
            mac,
            name: "s".to_string(),
            ipv4: Some(ip),
            ..serde_json::from_value(serde_json::json!({"mac":"00:00:00:00:00:01","name":"s"}))
                .unwrap()
        };
        let mut status = DhcpV4AssignStatus::from_config_and_devices(&config, vec![d]);

        sleep(Duration::from_secs(1));
        assert!(status.clean_expire_ip().is_empty(), "should report no cleanup needed");

        assert!(status.offered_ip.contains_key(&mac));
        assert!(status.allocated_host.contains_key(&ip));
    }
}
