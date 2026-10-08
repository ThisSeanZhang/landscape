//! Per-section runtime status for a WAN link, surfaced to REST/UI.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::service::ServiceStatus;

/// Aggregate lifecycle of a WAN link, derived from its section statuses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum WanLinkState {
    /// Config exists but no acquisition intent.
    #[default]
    Idle,
    Starting,
    Running,
    /// Session up with a failed sub-service, or session down while
    /// sub-services are still attached.
    Degraded,
    Failed,
    Stop,
}

/// Sections disabled by config report [`ServiceStatus::Stop`].
#[derive(Debug, Clone, Default, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkStatus {
    pub state: WanLinkState,
    pub session: ServiceStatus,
    pub pd: ServiceStatus,
    pub nat: ServiceStatus,
    pub firewall: ServiceStatus,
    pub mss: ServiceStatus,
}

impl WanLinkStatus {
    /// `session = None` means the link has no session child (no acquisition
    /// intent).
    pub fn compute_state(
        active: bool,
        session: Option<ServiceStatus>,
        pd: ServiceStatus,
        nat: ServiceStatus,
        firewall: ServiceStatus,
        mss: ServiceStatus,
    ) -> WanLinkState {
        if !active {
            return WanLinkState::Idle;
        }

        let sections = [pd, nat, firewall, mss];
        let any_section_active =
            sections.iter().any(|s| matches!(s, ServiceStatus::Staring | ServiceStatus::Running));
        let any_section_failed = sections.iter().any(|s| matches!(s, ServiceStatus::Failed));

        match session {
            Some(ServiceStatus::Failed) => WanLinkState::Failed,
            Some(ServiceStatus::Staring) => WanLinkState::Starting,
            Some(ServiceStatus::Stopping | ServiceStatus::Stop | ServiceStatus::Disabled) => {
                if any_section_active {
                    WanLinkState::Degraded
                } else {
                    WanLinkState::Stop
                }
            }
            Some(ServiceStatus::Running) | None => {
                if any_section_failed {
                    WanLinkState::Degraded
                } else if sections.iter().any(|s| matches!(s, ServiceStatus::Staring)) {
                    WanLinkState::Starting
                } else if any_section_active || session == Some(ServiceStatus::Running) {
                    WanLinkState::Running
                } else {
                    WanLinkState::Stop
                }
            }
        }
    }

    pub fn refresh(&mut self, active: bool) {
        self.state = Self::compute_state(
            active,
            Some(self.session.clone()),
            self.pd.clone(),
            self.nat.clone(),
            self.firewall.clone(),
            self.mss.clone(),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Pd,
    Nat,
    Firewall,
    Mss,
}

pub type WanLinkStatusStore = Arc<RwLock<HashMap<Uuid, WanLinkStatus>>>;

#[derive(Clone)]
pub struct WanLinkStatusHandle {
    id: Uuid,
    store: WanLinkStatusStore,
    active: Arc<AtomicBool>,
}

impl WanLinkStatusHandle {
    pub fn new(id: Uuid, store: WanLinkStatusStore, active: bool) -> Self {
        Self {
            id,
            store,
            active: Arc::new(AtomicBool::new(active)),
        }
    }

    pub async fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Relaxed);
        self.update(|_| {}).await;
    }

    pub async fn set_session(&self, status: ServiceStatus) {
        self.update(|entry| entry.session = status).await;
    }

    pub async fn set_section(&self, kind: SectionKind, status: ServiceStatus) {
        self.update(|entry| match kind {
            SectionKind::Pd => entry.pd = status,
            SectionKind::Nat => entry.nat = status,
            SectionKind::Firewall => entry.firewall = status,
            SectionKind::Mss => entry.mss = status,
        })
        .await;
    }

    pub async fn remove(&self) {
        self.store.write().await.remove(&self.id);
    }

    async fn update(&self, modify: impl FnOnce(&mut WanLinkStatus)) {
        let active = self.active.load(Ordering::Relaxed);
        let mut map = self.store.write().await;
        let entry = map.entry(self.id).or_default();
        modify(entry);
        entry.refresh(active);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> ServiceStatus {
        ServiceStatus::Running
    }

    fn dead() -> ServiceStatus {
        ServiceStatus::Stop
    }

    fn failed() -> ServiceStatus {
        ServiceStatus::Failed
    }

    #[test]
    fn inactive_link_is_idle_no_matter_what() {
        assert_eq!(
            WanLinkStatus::compute_state(
                false,
                Some(failed()),
                failed(),
                failed(),
                failed(),
                failed()
            ),
            WanLinkState::Idle
        );
    }

    #[test]
    fn session_failed_means_link_failed() {
        assert_eq!(
            WanLinkStatus::compute_state(true, Some(failed()), ok(), ok(), ok(), ok()),
            WanLinkState::Failed
        );
    }

    #[test]
    fn failed_section_degrades_a_running_link() {
        assert_eq!(
            WanLinkStatus::compute_state(true, Some(ok()), ok(), failed(), dead(), failed()),
            WanLinkState::Degraded
        );
    }

    #[test]
    fn stopped_session_with_live_sections_is_degraded() {
        assert_eq!(
            WanLinkStatus::compute_state(true, Some(dead()), ok(), dead(), dead(), dead()),
            WanLinkState::Degraded
        );
    }

    #[test]
    fn no_session_follows_sections() {
        assert_eq!(
            WanLinkStatus::compute_state(true, None, ok(), dead(), dead(), dead()),
            WanLinkState::Running
        );
    }
}
