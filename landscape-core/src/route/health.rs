//! Link health aggregation: per-link snapshots pushed by the health-check
//! sections, flip-only change events, and cleanup when WAN routes go away.

use std::collections::HashMap;

use landscape_common::wan_link::{WanLinkHealthInfo, WanLinkHealthState};
use tokio::sync::broadcast;
use uuid::Uuid;

use super::{IpRouteService, clone_locked_state};

/// Published when a link's debounced health state flips. `to: Unknown`
/// only ever means the entry was cleared: a verdict never falls back to
/// `Unknown` on its own.
#[derive(Debug, Clone, PartialEq)]
pub struct WanLinkHealthEvent {
    pub link_id: Uuid,
    pub from: WanLinkHealthState,
    pub to: WanLinkHealthState,
    /// Snapshot at the moment of the transition.
    pub info: WanLinkHealthInfo,
}

pub type LinkHealths = HashMap<Uuid, WanLinkHealthInfo>;

impl IpRouteService {
    pub(crate) async fn clone_link_healths(&self) -> LinkHealths {
        clone_locked_state(&self.link_healths).await
    }

    /// Upsert a link's health snapshot; broadcasts only on state flips.
    pub async fn update_link_health(&self, info: WanLinkHealthInfo) {
        let flip = {
            let mut lock = self.link_healths.write().await;
            let from = lock.get(&info.link_id).map_or(WanLinkHealthState::Unknown, |old| old.state);
            let to = info.state;
            lock.insert(info.link_id, info.clone());
            (from != to).then_some(WanLinkHealthEvent { link_id: info.link_id, from, to, info })
        };
        if let Some(event) = flip {
            let _ = self.health_events.send(event);
        }
    }

    /// Drop a link's entry (session gone / section stopped), broadcasting
    /// the removal as a flip to `Unknown`; silent when nothing is stored.
    pub async fn clear_link_health(&self, link_id: Uuid) {
        let removed = self.link_healths.write().await.remove(&link_id);
        if let Some(old) = removed
            && old.state != WanLinkHealthState::Unknown
        {
            let _ = self.health_events.send(WanLinkHealthEvent {
                link_id,
                from: old.state,
                to: WanLinkHealthState::Unknown,
                info: old,
            });
        }
    }

    pub async fn get_link_health(&self, link_id: Uuid) -> Option<WanLinkHealthInfo> {
        self.link_healths.read().await.get(&link_id).cloned()
    }

    pub async fn get_link_healths(&self) -> LinkHealths {
        self.clone_link_healths().await
    }

    pub fn subscribe_health_events(&self) -> broadcast::Receiver<WanLinkHealthEvent> {
        self.health_events.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use landscape_common::wan_link::{TargetHealthStat, WanLinkHealthState};

    use super::*;

    fn info(link_id: Uuid, state: WanLinkHealthState) -> WanLinkHealthInfo {
        WanLinkHealthInfo {
            link_id,
            state,
            consecutive_failures: 0,
            targets: vec![TargetHealthStat {
                target: Ipv4Addr::new(1, 1, 1, 1),
                last_rtt_ms: Some(20),
                rtt_ewma_ms: Some(20.0),
            }],
            rtt_ewma_ms: Some(20.0),
            loss_ewma: Some(0.0),
            last_success_at: None,
            last_failure_at: None,
            updated_at: 0.0,
        }
    }

    fn service() -> IpRouteService {
        super::super::test_used_ip_route()
    }

    #[tokio::test]
    async fn same_state_upsert_is_silent() {
        let service = service();
        let link = Uuid::new_v4();
        let mut events = service.subscribe_health_events();

        service.update_link_health(info(link, WanLinkHealthState::Unknown)).await;
        service.update_link_health(info(link, WanLinkHealthState::Unknown)).await;

        assert!(events.try_recv().is_err());
        assert!(service.get_link_health(link).await.is_some());
    }

    #[tokio::test]
    async fn state_flips_broadcast_with_snapshot() {
        let service = service();
        let link = Uuid::new_v4();
        let mut events = service.subscribe_health_events();

        service.update_link_health(info(link, WanLinkHealthState::Unknown)).await;
        service.update_link_health(info(link, WanLinkHealthState::Healthy)).await;
        service.update_link_health(info(link, WanLinkHealthState::Healthy)).await;
        service.update_link_health(info(link, WanLinkHealthState::Unhealthy)).await;

        let event = events.try_recv().unwrap();
        assert_eq!(event.link_id, link);
        assert_eq!(
            (event.from, event.to),
            (WanLinkHealthState::Unknown, WanLinkHealthState::Healthy)
        );
        assert_eq!(event.info.state, WanLinkHealthState::Healthy);

        let event = events.try_recv().unwrap();
        assert_eq!(
            (event.from, event.to),
            (WanLinkHealthState::Healthy, WanLinkHealthState::Unhealthy)
        );
        assert!(events.try_recv().is_err());
    }

    #[tokio::test]
    async fn clear_broadcasts_only_for_real_verdicts() {
        let service = service();
        let link = Uuid::new_v4();
        let mut events = service.subscribe_health_events();

        service.clear_link_health(link).await;
        service.update_link_health(info(link, WanLinkHealthState::Unknown)).await;
        service.clear_link_health(link).await;
        assert!(events.try_recv().is_err(), "no verdict ever existed");

        service.update_link_health(info(link, WanLinkHealthState::Healthy)).await;
        assert!(events.try_recv().is_ok());

        service.clear_link_health(link).await;
        let event = events.try_recv().unwrap();
        assert_eq!(event.to, WanLinkHealthState::Unknown);
        assert_eq!(event.from, WanLinkHealthState::Healthy);
        assert!(service.get_link_health(link).await.is_none());
        assert!(service.get_link_healths().await.is_empty());
    }

    #[tokio::test]
    async fn removing_a_link_wan_route_clears_its_health() {
        let service = service();
        let link = Uuid::new_v4();
        service
            .insert_ipv4_link_route(
                link,
                landscape_common::sys_service::route_service::RouteTargetInfo {
                    weight: 1,
                    ifindex: 1,
                    mac: None,
                    default_route: false,
                    is_docker: false,
                    iface_name: "eth0".to_string(),
                    iface_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                    gateway_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    dev_only_nexthop: false,
                },
            )
            .await;
        service.update_link_health(info(link, WanLinkHealthState::Healthy)).await;
        assert!(service.get_link_health(link).await.is_some());

        service.remove_ipv4_link_route(link).await;
        assert!(service.get_link_health(link).await.is_none(), "route gone clears health");
    }

    #[tokio::test]
    async fn removing_a_netns_route_keeps_link_health() {
        let service = service();
        let link = Uuid::new_v4();
        service.update_link_health(info(link, WanLinkHealthState::Healthy)).await;

        service
            .remove_ipv4_wan_route(
                &landscape_common::sys_service::route_service::RouteOwner::Netns("web".to_string()),
            )
            .await;

        assert!(
            service.get_link_health(link).await.is_some(),
            "netns removal must not touch link health"
        );
    }
}
