use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::service::ServiceStatus;
use crate::wan_link::health::WanLinkHealthState;

pub fn swap_if_changed<T: PartialEq>(slot: &ArcSwap<T>, v: T) {
    if **slot.load() != v {
        slot.store(Arc::new(v));
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DhcpV4Runtime {
    Discovering {
        attempts: u64,
        backoff_rounds: u32,
    },
    Requesting {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        offered_ip: Ipv4Addr,
    },
    Bound {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        ip: Ipv4Addr,
        prefix: u8,
        lease_secs: u64,
        renew_secs: u64,
    },
    Renewing {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        ip: Ipv4Addr,
    },
    Rebinding {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        ip: Ipv4Addr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PppoeRuntime {
    Dialing,
    Negotiating,
    Online {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        local_ip: Ipv4Addr,
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        peer_ip: Ipv4Addr,
        session_id: u16,
    },
    RedialBackoff {
        retry_count: u64,
        retry_in_secs: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PppdRuntime {
    Spawning,
    WaitingAddr {
        #[cfg_attr(
            feature = "openapi",
            schema(required = true, nullable = true, value_type = Option<String>)
        )]
        local: Option<Ipv4Addr>,
        #[cfg_attr(
            feature = "openapi",
            schema(required = true, nullable = true, value_type = Option<String>)
        )]
        peer: Option<Ipv4Addr>,
    },
    Online {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        local_ip: Ipv4Addr,
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        peer_ip: Ipv4Addr,
    },
    RestartBackoff {
        failure_count: u32,
        retry_in_secs: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct PdLease {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix_ip: Ipv6Addr,
    pub prefix_len: u8,
    pub valid_secs: u32,
    pub preferred_secs: u32,
    #[cfg_attr(
        feature = "openapi",
        schema(required = true, nullable = true, value_type = Option<String>)
    )]
    pub wan_ip: Option<Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PdRuntime {
    #[default]
    Idle,
    Soliciting,
    Requesting,
    Bound(PdLease),
    Renewing(PdLease),
    Rebinding(PdLease),
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct HealthProbeStatus {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub target: Ipv4Addr,
    #[cfg_attr(
        feature = "openapi",
        schema(required = true, nullable = true, value_type = Option<u64>)
    )]
    pub rtt_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckRuntime {
    #[default]
    Idle,
    Running {
        state: WanLinkHealthState,
        #[cfg_attr(
            feature = "openapi",
            schema(required = true, nullable = true, value_type = Option<f64>)
        )]
        rtt_ewma_ms: Option<f64>,
        probes: Vec<HealthProbeStatus>,
    },
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum V4Runtime {
    #[default]
    Idle,
    Dhcp(DhcpV4Runtime),
    Pppoe(PppoeRuntime),
    Pppd(PppdRuntime),
    Static {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        ip: Ipv4Addr,
    },
    IdleAnchor,
    Stopped,
}

impl From<DhcpV4Runtime> for V4Runtime {
    fn from(v: DhcpV4Runtime) -> Self {
        V4Runtime::Dhcp(v)
    }
}

#[derive(Debug, Clone, Default)]
pub struct WanLinkSectionsStatus {
    v4: Arc<ArcSwap<V4Runtime>>,
    pd: Arc<ArcSwap<PdRuntime>>,
    nat4: Arc<ArcSwap<ServiceStatus>>,
    nat6: Arc<ArcSwap<ServiceStatus>>,
    mss: Arc<ArcSwap<ServiceStatus>>,
    firewall: Arc<ArcSwap<ServiceStatus>>,
    health_check: Arc<ArcSwap<HealthCheckRuntime>>,
}

impl WanLinkSectionsStatus {
    pub fn v4_slot(&self) -> Arc<ArcSwap<V4Runtime>> {
        self.v4.clone()
    }

    pub fn set_v4(&self, v: V4Runtime) {
        swap_if_changed(&self.v4, v);
    }

    pub fn v4(&self) -> V4Runtime {
        (**self.v4.load()).clone()
    }

    pub fn pd_slot(&self) -> Arc<ArcSwap<PdRuntime>> {
        self.pd.clone()
    }

    pub fn set_pd(&self, v: PdRuntime) {
        swap_if_changed(&self.pd, v);
    }

    pub fn pd(&self) -> PdRuntime {
        (**self.pd.load()).clone()
    }

    pub fn health_check_slot(&self) -> Arc<ArcSwap<HealthCheckRuntime>> {
        self.health_check.clone()
    }

    pub fn set_nat4(&self, v: ServiceStatus) {
        swap_if_changed(&self.nat4, v);
    }

    pub fn nat4_slot(&self) -> Arc<ArcSwap<ServiceStatus>> {
        self.nat4.clone()
    }

    pub fn nat4(&self) -> ServiceStatus {
        (**self.nat4.load()).clone()
    }

    pub fn set_nat6(&self, v: ServiceStatus) {
        swap_if_changed(&self.nat6, v);
    }

    pub fn nat6_slot(&self) -> Arc<ArcSwap<ServiceStatus>> {
        self.nat6.clone()
    }

    pub fn nat6(&self) -> ServiceStatus {
        (**self.nat6.load()).clone()
    }

    pub fn mss_slot(&self) -> Arc<ArcSwap<ServiceStatus>> {
        self.mss.clone()
    }

    pub fn firewall_slot(&self) -> Arc<ArcSwap<ServiceStatus>> {
        self.firewall.clone()
    }

    pub fn set_mss(&self, v: ServiceStatus) {
        swap_if_changed(&self.mss, v);
    }

    pub fn mss(&self) -> ServiceStatus {
        (**self.mss.load()).clone()
    }

    pub fn set_firewall(&self, v: ServiceStatus) {
        swap_if_changed(&self.firewall, v);
    }

    pub fn firewall(&self) -> ServiceStatus {
        (**self.firewall.load()).clone()
    }

    pub fn set_health_check(&self, v: HealthCheckRuntime) {
        swap_if_changed(&self.health_check, v);
    }

    pub fn health_check(&self) -> HealthCheckRuntime {
        (**self.health_check.load()).clone()
    }

    pub fn snapshot(&self) -> WanLinkSectionsSnapshot {
        WanLinkSectionsSnapshot {
            v4: self.v4(),
            pd: self.pd(),
            nat4: self.nat4(),
            nat6: self.nat6(),
            mss: self.mss(),
            firewall: self.firewall(),
            health_check: self.health_check(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkSectionsSnapshot {
    pub v4: V4Runtime,
    pub pd: PdRuntime,
    pub nat4: ServiceStatus,
    pub nat6: ServiceStatus,
    pub mss: ServiceStatus,
    pub firewall: ServiceStatus,
    pub health_check: HealthCheckRuntime,
}

#[derive(Clone, Default)]
pub struct WanLinkRuntimeStatusStore {
    links: Arc<ArcSwap<HashMap<Uuid, Arc<WanLinkSectionsStatus>>>>,
}

impl WanLinkRuntimeStatusStore {
    pub fn install(&self, id: Uuid, sections: Arc<WanLinkSectionsStatus>) {
        self.links.rcu(|map| {
            let mut new = (**map).clone();
            new.insert(id, sections.clone());
            new
        });
    }

    pub fn remove(&self, id: &Uuid) {
        self.links.rcu(|map| {
            let mut new = (**map).clone();
            new.remove(id);
            new
        });
    }

    pub fn get(&self, id: &Uuid) -> Option<Arc<WanLinkSectionsStatus>> {
        self.links.load().get(id).cloned()
    }

    pub fn snapshots(&self) -> HashMap<Uuid, WanLinkSectionsSnapshot> {
        self.links.load().iter().map(|(id, s)| (*id, s.snapshot())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_if_changed_keeps_arc_on_equal_value() {
        let slot = ArcSwap::new(Arc::new(V4Runtime::Idle));
        let before = slot.load_full();
        swap_if_changed(&slot, V4Runtime::Idle);
        let after = slot.load_full();
        assert!(Arc::ptr_eq(&before, &after));

        swap_if_changed(&slot, V4Runtime::Stopped);
        assert_eq!(*slot.load_full(), V4Runtime::Stopped);
    }

    #[test]
    fn v4_slot_shares_the_cell() {
        let sections = WanLinkSectionsStatus::default();
        let slot = sections.v4_slot();

        slot.store(Arc::new(V4Runtime::Dhcp(DhcpV4Runtime::Requesting {
            offered_ip: Ipv4Addr::new(10, 0, 0, 2),
        })));

        assert_eq!(
            sections.v4(),
            V4Runtime::Dhcp(DhcpV4Runtime::Requesting { offered_ip: Ipv4Addr::new(10, 0, 0, 2) })
        );

        sections.set_v4(V4Runtime::Stopped);
        assert_eq!(*slot.load_full(), V4Runtime::Stopped);
    }

    #[test]
    fn store_install_remove_snapshot() {
        let store = WanLinkRuntimeStatusStore::default();
        let id = Uuid::new_v4();
        let sections = Arc::new(WanLinkSectionsStatus::default());
        sections.set_v4(V4Runtime::Dhcp(DhcpV4Runtime::Bound {
            ip: Ipv4Addr::new(1, 2, 3, 4),
            prefix: 24,
            lease_secs: 3600,
            renew_secs: 1800,
        }));

        store.install(id, sections);
        assert_eq!(
            store.snapshots().get(&id).map(|s| s.v4.clone()),
            Some(V4Runtime::Dhcp(DhcpV4Runtime::Bound {
                ip: Ipv4Addr::new(1, 2, 3, 4),
                prefix: 24,
                lease_secs: 3600,
                renew_secs: 1800,
            }))
        );

        store.remove(&id);
        assert!(store.get(&id).is_none());
        assert!(store.snapshots().is_empty());
    }
}
