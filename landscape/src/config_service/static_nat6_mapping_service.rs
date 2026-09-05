use std::{
    collections::{HashMap, HashSet},
    net::Ipv6Addr,
    sync::Arc,
    time::Duration,
};

use landscape_common::config_service::static_nat::config6::{
    StaticNatMappingV6Config, StaticNatV6PortConfig, StaticNatV6Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::error::DbError;
use landscape_common::database::LandscapeStore;
use landscape_common::event::hub::{
    EnrolledDeviceEvent, EnrolledDeviceEventReader, IPv6AssignEvent, IPv6AssignEventReader,
};
use landscape_common::utils::time::get_f64_timestamp;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_common::LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::static_nat_mapping_v6::repository::StaticNatMappingV6Repository;
use tokio::sync::{mpsc, Mutex, RwLock};
use uuid::Uuid;

type DeviceIpv6Cache = HashMap<Uuid, HashSet<Ipv6Addr>>;

// This cache contains only observed dynamic addresses, primarily SLAAC addresses
// learned from RA-related client activity. Configured IA_NA targets remain
// authoritative and are resolved from the enrolled-device database on every
// runtime rule refresh. Dynamic entries are intentionally best-effort and may
// temporarily lag after startup or event loss until later client activity emits
// another assignment event; periodic router advertisements do not populate this
// cache directly.
#[derive(Default)]
struct DeviceIpv6State {
    addresses: DeviceIpv6Cache,
}

#[derive(Clone)]
pub struct StaticNat6MappingService {
    store: StaticNatMappingV6Repository,
    wan_iid: Arc<u64>,
    device_ipv6_state: Arc<RwLock<DeviceIpv6State>>,
    refresh_lock: Arc<Mutex<()>>,
    dataplane: Arc<dyn NatDataplane>,
}

impl StaticNat6MappingService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        device_reader: EnrolledDeviceEventReader,
        ipv6_reader: IPv6AssignEventReader,
        wan_iid: Arc<u64>,
        dataplane: Arc<dyn NatDataplane>,
    ) -> Self {
        let service = Self {
            store: store_provider.static_nat_mapping_v6_store(),
            wan_iid,
            device_ipv6_state: Arc::new(RwLock::new(DeviceIpv6State::default())),
            refresh_lock: Arc::new(Mutex::new(())),
            dataplane,
        };

        let is_empty = service.store.list().await.is_ok_and(|l| l.is_empty());
        if is_empty {
            service.init_default_rules().await;
        }

        service.refresh_runtime_rules().await;

        service.spawn_device_event_loop(device_reader);
        service.spawn_ipv6_event_loop(ipv6_reader);

        service
    }

    fn spawn_device_event_loop(&self, mut reader: EnrolledDeviceEventReader) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match reader.recv().await {
                    Ok(event) => {
                        let mut state = this.device_ipv6_state.write().await;
                        apply_enrolled_device_event(&mut state, &event);
                        drop(state);
                        this.refresh_runtime_rules().await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            "static NAT v6 device listener lagged, skipped {skipped} events"
                        );
                        this.refresh_runtime_rules().await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    fn spawn_ipv6_event_loop(&self, mut reader: IPv6AssignEventReader) {
        let (refresh_tx, mut refresh_rx) = mpsc::channel(1);

        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match reader.recv().await {
                    Ok(event) => {
                        let changed = {
                            let mut state = this.device_ipv6_state.write().await;
                            apply_ipv6_assign_event(&mut state, event)
                        };
                        if changed {
                            let _ = refresh_tx.try_send(());
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            "static NAT v6 IPv6 assign listener lagged, skipped {skipped} events"
                        );
                        // Do not disturb the database-backed IA_NA rules. The
                        // observed RA/SLAAC cache is allowed to converge on later
                        // allocation, expiry, or flush events.
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let this = self.clone();
        tokio::spawn(async move {
            while refresh_rx.recv().await.is_some() {
                tokio::time::sleep(Duration::from_secs(1)).await;
                while refresh_rx.try_recv().is_ok() {}
                this.refresh_runtime_rules().await;
            }
        });
    }

    async fn init_default_rules(&self) {
        for config in default_static_mapping_v6_rules() {
            let _ = self.store.set(config).await;
        }
    }

    // --- V6 CRUD ---

    pub async fn list(&self) -> Vec<StaticNatMappingV6Config> {
        self.store.list().await.unwrap_or_default()
    }

    pub async fn find_by_id(&self, id: Uuid) -> Option<StaticNatMappingV6Config> {
        self.store.find_by_id(id).await.ok()?
    }

    pub async fn checked_set(
        &self,
        config: StaticNatMappingV6Config,
    ) -> Result<StaticNatMappingV6Config, DbError> {
        let result = self.store.checked_set(config).await?;
        self.refresh_runtime_rules().await;
        Ok(result)
    }

    pub async fn checked_set_list(
        &self,
        configs: Vec<StaticNatMappingV6Config>,
    ) -> Result<(), DbError> {
        for config in &configs {
            self.store.check_conflict(config).await?;
        }
        for config in configs {
            self.store.checked_set(config).await?;
        }
        self.refresh_runtime_rules().await;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) {
        if self.find_by_id(id).await.is_some() {
            let _ = self.store.delete(id).await;
            self.refresh_runtime_rules().await;
        }
    }

    pub async fn validate_runtime_target(
        &self,
        config: &StaticNatMappingV6Config,
    ) -> Result<(), StaticNatError> {
        self.store.validate_runtime_target_v6(config).await
    }

    // --- Runtime ---

    pub async fn refresh_runtime_rules(&self) {
        let _refresh_guard = self.refresh_lock.lock().await;
        let device_ipv6_cache = self.device_ipv6_state.read().await.addresses.clone();
        let configs =
            match self.store.list_runtime_configs_v6(*self.wan_iid, &device_ipv6_cache).await {
                Ok(configs) => configs,
                Err(error) => {
                    tracing::error!("failed to load static NAT v6 runtime configs: {error:?}");
                    return;
                }
            };

        self.dataplane.sync_static_nat6(&configs);
    }
}

fn apply_ipv6_assign_event(state: &mut DeviceIpv6State, event: IPv6AssignEvent) -> bool {
    match event {
        IPv6AssignEvent::Allocated(info) => {
            let Some(device_id) = info.device_id else {
                return false;
            };
            let new_ips: Vec<_> = info.ips.into_iter().filter(is_usable_dynamic_ipv6).collect();
            if new_ips.is_empty() {
                return false;
            }
            let entry = state.addresses.entry(device_id).or_default();
            let old_len = entry.len();
            entry.extend(new_ips);
            entry.len() != old_len
        }
        IPv6AssignEvent::Expired(info) => {
            let Some(device_id) = info.device_id else {
                return false;
            };
            let Some(entry) = state.addresses.get_mut(&device_id) else {
                return false;
            };
            let mut changed = false;
            for ip in info.ips {
                changed |= entry.remove(&ip);
            }
            if entry.is_empty() {
                state.addresses.remove(&device_id);
            }
            changed
        }
        IPv6AssignEvent::Flush(info) => {
            let Some(device_id) = info.device_id else {
                return false;
            };
            let new_ips: HashSet<_> = info.ips.into_iter().filter(is_usable_dynamic_ipv6).collect();
            if new_ips.is_empty() {
                state.addresses.remove(&device_id).is_some()
            } else if state.addresses.get(&device_id) == Some(&new_ips) {
                false
            } else {
                state.addresses.insert(device_id, new_ips);
                true
            }
        }
    }
}

fn is_usable_dynamic_ipv6(ip: &Ipv6Addr) -> bool {
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_unicast_link_local())
}

fn apply_enrolled_device_event(state: &mut DeviceIpv6State, event: &EnrolledDeviceEvent) {
    if let EnrolledDeviceEvent::Deleted { old } = event {
        state.addresses.remove(&old.id);
    }
}

fn default_static_mapping_v6_rules() -> Vec<StaticNatMappingV6Config> {
    vec![StaticNatMappingV6Config {
        wan_iface_name: None,
        lan_target: Some(StaticNatV6Target::Local),
        l4_protocols: vec![17],
        id: Uuid::new_v4(),
        enable: true,
        remark: "Default DHCPv6 Client Port".to_string(),
        update_at: get_f64_timestamp(),
        port_config: StaticNatV6PortConfig::Ports {
            ports: vec![LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT],
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::{
        config_service::enrolled_device::EnrolledDevice, event::hub::IPv6AssignInfo, net::MacAddr,
    };

    fn assign_info(device_id: Option<Uuid>, ips: Vec<Ipv6Addr>) -> IPv6AssignInfo {
        IPv6AssignInfo {
            iface_name: "lan0".to_string(),
            mac: MacAddr::from([0, 1, 2, 3, 4, 5]),
            ips,
            device_id,
        }
    }

    fn enrolled_device(id: Uuid, mac: MacAddr, ipv6: Option<Ipv6Addr>) -> EnrolledDevice {
        EnrolledDevice {
            id,
            update_at: 0.0,
            iface_name: Some("lan0".to_string()),
            name: "device".to_string(),
            fake_name: None,
            remark: None,
            hostname: None,
            mac,
            ipv4: None,
            ipv6,
            tag: Vec::new(),
            dhcp_custom_options: Vec::new(),
            dhcp_filter_options: Vec::new(),
        }
    }

    #[test]
    fn default_dhcpv6_rule_targets_local_wan_iid() {
        let rules = default_static_mapping_v6_rules();
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].lan_target, Some(StaticNatV6Target::Local)));
    }

    #[test]
    fn ipv6_assign_events_update_device_cache() {
        let device_id = Uuid::new_v4();
        let first = "2001:db8:1::10".parse().unwrap();
        let second = "fd00:1::20".parse().unwrap();
        let replacement = "2001:db8:2::30".parse().unwrap();
        let mut state = DeviceIpv6State::default();

        assert!(apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Allocated(assign_info(Some(device_id), vec![first, second])),
        ));
        assert_eq!(state.addresses[&device_id], HashSet::from([first, second]));

        assert!(apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Expired(assign_info(Some(device_id), vec![first])),
        ));
        assert_eq!(state.addresses[&device_id], HashSet::from([second]));

        assert!(apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Flush(assign_info(Some(device_id), vec![replacement])),
        ));
        assert_eq!(state.addresses[&device_id], HashSet::from([replacement]));

        assert!(apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Flush(assign_info(Some(device_id), Vec::new())),
        ));
        assert!(!state.addresses.contains_key(&device_id));
    }

    #[test]
    fn ipv6_assign_cache_ignores_unowned_and_special_addresses() {
        let device_id = Uuid::new_v4();
        let usable = "fd00::10".parse().unwrap();
        let mut state = DeviceIpv6State::default();

        assert!(!apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Allocated(assign_info(None, vec![usable])),
        ));
        assert!(!apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Allocated(assign_info(
                Some(device_id),
                vec![Ipv6Addr::UNSPECIFIED, Ipv6Addr::LOCALHOST, "fe80::1".parse().unwrap()],
            )),
        ));
        assert!(!state.addresses.contains_key(&device_id));
    }

    #[test]
    fn device_lifecycle_controls_dynamic_cache_activity() {
        let id = Uuid::new_v4();
        let mac = MacAddr::from([0, 1, 2, 3, 4, 5]);
        let ipv6 = Some("::100".parse().unwrap());
        let old = enrolled_device(id, mac, ipv6);
        let dynamic_ip = "2001:db8::200".parse().unwrap();
        let mut state = DeviceIpv6State::default();
        state.addresses.insert(id, HashSet::from([dynamic_ip]));

        // Device updates (even removing the static IPv6 suffix) must keep the
        // dynamic cache, so mappings can follow addresses of devices without a
        // static suffix.
        apply_enrolled_device_event(
            &mut state,
            &EnrolledDeviceEvent::Updated {
                old: Some(old.clone()),
                new: enrolled_device(id, mac, ipv6),
            },
        );
        assert_eq!(state.addresses[&id], HashSet::from([dynamic_ip]));

        apply_enrolled_device_event(
            &mut state,
            &EnrolledDeviceEvent::Updated {
                old: Some(old.clone()),
                new: enrolled_device(id, mac, None),
            },
        );
        assert_eq!(state.addresses[&id], HashSet::from([dynamic_ip]));

        // A flush after the suffix removal still updates the cached addresses.
        let replacement = "2001:db8::201".parse().unwrap();
        assert!(apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Flush(assign_info(Some(id), vec![replacement])),
        ));
        assert_eq!(state.addresses[&id], HashSet::from([replacement]));

        // Deleting the device removes its cached addresses.
        apply_enrolled_device_event(&mut state, &EnrolledDeviceEvent::Deleted { old });
        assert!(!state.addresses.contains_key(&id));
    }

    #[test]
    fn device_without_static_ipv6_tracks_dynamic_addresses() {
        let id = Uuid::new_v4();
        let mac = MacAddr::from([0, 1, 2, 3, 4, 5]);
        let mut state = DeviceIpv6State::default();
        let dynamic_a = "2001:db8:1::200".parse().unwrap();
        let dynamic_b = "fd00:1::300".parse().unwrap();

        // A device registered with only a MAC (no static IPv6 suffix) can still
        // accumulate dynamic addresses from SLAAC/DHCPv6 assignment events.
        apply_enrolled_device_event(
            &mut state,
            &EnrolledDeviceEvent::Updated { old: None, new: enrolled_device(id, mac, None) },
        );
        assert!(apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Allocated(assign_info(Some(id), vec![dynamic_a])),
        ));
        assert!(apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Allocated(assign_info(Some(id), vec![dynamic_b])),
        ));
        assert_eq!(state.addresses[&id], HashSet::from([dynamic_a, dynamic_b]));

        assert!(apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Expired(assign_info(Some(id), vec![dynamic_a])),
        ));
        assert_eq!(state.addresses[&id], HashSet::from([dynamic_b]));

        assert!(apply_ipv6_assign_event(
            &mut state,
            IPv6AssignEvent::Flush(assign_info(Some(id), Vec::new())),
        ));
        assert!(!state.addresses.contains_key(&id));
    }
}
