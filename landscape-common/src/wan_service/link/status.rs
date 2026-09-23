use serde::Serialize;

use crate::service::ServiceStatus;

/// Aggregate lifecycle of a WAN link, derived from its section statuses.
///
/// This is the user-facing verdict; the individual section statuses in
/// [`LinkStatus`] carry the detail. Mapping rules:
/// - gate off (`!active()`) -> [`LinkState::Idle`], regardless of sections
/// - session acquisition failed -> [`LinkState::Failed`]
/// - session up but an enabled sub-service failed -> [`LinkState::Degraded`]
/// - session lost (stopped without failure) while sub-services still run ->
///   [`LinkState::Degraded`]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum LinkState {
    /// Config exists but no acquisition intent (`v4_active() || pd_active()`).
    #[default]
    Idle,
    Starting,
    Running,
    /// The session is up but at least one enabled sub-service failed, or the
    /// session went down while sub-services are still attached.
    Degraded,
    Failed,
    Stop,
}

/// Per-section runtime view of one link. Sections disabled by config report
/// [`ServiceStatus::Stop`].
#[derive(Debug, Clone, Default, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LinkStatus {
    pub state: LinkState,
    /// v4/session acquisition driver (static / dhcp / pppoe / pppd).
    pub session: ServiceStatus,
    /// IPv6 prefix delegation.
    pub pd: ServiceStatus,
    pub nat: ServiceStatus,
    pub firewall: ServiceStatus,
    pub mss: ServiceStatus,
}

impl LinkStatus {
    pub fn new(state: LinkState) -> Self {
        Self { state, ..Default::default() }
    }

    /// `session = None` means no session child exists for this link
    /// (ethernet without v4 intent, or a session-less static config).
    pub fn compute_state(
        active: bool,
        session: Option<ServiceStatus>,
        pd: ServiceStatus,
        nat: ServiceStatus,
        firewall: ServiceStatus,
        mss: ServiceStatus,
    ) -> LinkState {
        if !active {
            return LinkState::Idle;
        }

        let sections = [pd, nat, firewall, mss];
        let any_section_active =
            sections.iter().any(|s| matches!(s, ServiceStatus::Staring | ServiceStatus::Running));
        let any_section_failed = sections.iter().any(|s| matches!(s, ServiceStatus::Failed));

        match session {
            Some(ServiceStatus::Failed) => LinkState::Failed,
            Some(ServiceStatus::Staring) => LinkState::Starting,
            Some(ServiceStatus::Stopping | ServiceStatus::Stop) => {
                // Session ended without declaring failure: if sub-services are
                // still attached the link is degraded, otherwise it is down.
                if any_section_active {
                    LinkState::Degraded
                } else {
                    LinkState::Stop
                }
            }
            Some(ServiceStatus::Running) | None => {
                if any_section_failed {
                    LinkState::Degraded
                } else if sections.iter().any(|s| matches!(s, ServiceStatus::Staring)) {
                    LinkState::Starting
                } else if any_section_active || session == Some(ServiceStatus::Running) {
                    LinkState::Running
                } else {
                    // Nothing runs and nothing failed.
                    LinkState::Stop
                }
            }
        }
    }

    /// Refresh the aggregate state from the current section statuses.
    pub fn refresh(&mut self, active: bool, session: Option<ServiceStatus>) {
        self.state = Self::compute_state(
            active,
            session,
            self.pd.clone(),
            self.nat.clone(),
            self.firewall.clone(),
            self.mss.clone(),
        );
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
            LinkStatus::compute_state(
                false,
                Some(failed()),
                failed(),
                failed(),
                failed(),
                failed()
            ),
            LinkState::Idle
        );
        assert_eq!(LinkStatus::compute_state(false, None, ok(), ok(), ok(), ok()), LinkState::Idle);
    }

    #[test]
    fn session_failed_means_link_failed() {
        assert_eq!(
            LinkStatus::compute_state(true, Some(failed()), dead(), dead(), dead(), dead()),
            LinkState::Failed
        );
        assert_eq!(
            LinkStatus::compute_state(true, Some(failed()), ok(), ok(), ok(), ok()),
            LinkState::Failed
        );
    }

    #[test]
    fn session_starting_is_starting() {
        assert_eq!(
            LinkStatus::compute_state(
                true,
                Some(ServiceStatus::Staring),
                dead(),
                dead(),
                dead(),
                dead()
            ),
            LinkState::Starting
        );
    }

    #[test]
    fn running_session_with_healthy_sections_is_running() {
        assert_eq!(
            LinkStatus::compute_state(true, Some(ok()), ok(), dead(), ok(), dead()),
            LinkState::Running
        );
    }

    #[test]
    fn failed_section_degrades_a_running_link() {
        assert_eq!(
            LinkStatus::compute_state(true, Some(ok()), ok(), failed(), dead(), failed()),
            LinkState::Degraded
        );
    }

    #[test]
    fn stopped_session_with_live_sections_is_degraded() {
        assert_eq!(
            LinkStatus::compute_state(true, Some(dead()), ok(), dead(), dead(), dead()),
            LinkState::Degraded
        );
        assert_eq!(
            LinkStatus::compute_state(
                true,
                Some(ServiceStatus::Stopping),
                dead(),
                ok(),
                dead(),
                dead()
            ),
            LinkState::Degraded
        );
    }

    #[test]
    fn stopped_session_without_sections_is_stop() {
        assert_eq!(
            LinkStatus::compute_state(true, Some(dead()), dead(), dead(), dead(), dead()),
            LinkState::Stop
        );
    }

    #[test]
    fn no_session_follows_sections() {
        // pd-only ethernet link: no v4 session child, only sections.
        assert_eq!(
            LinkStatus::compute_state(true, None, ok(), dead(), dead(), dead()),
            LinkState::Running
        );
        assert_eq!(
            LinkStatus::compute_state(true, None, failed(), dead(), dead(), dead()),
            LinkState::Degraded
        );
        assert_eq!(
            LinkStatus::compute_state(true, None, dead(), dead(), dead(), dead()),
            LinkState::Stop
        );
        assert_eq!(
            LinkStatus::compute_state(true, None, ServiceStatus::Staring, dead(), dead(), dead()),
            LinkState::Starting
        );
    }

    #[test]
    fn section_starting_defers_running_verdict() {
        assert_eq!(
            LinkStatus::compute_state(
                true,
                Some(ok()),
                ok(),
                ServiceStatus::Staring,
                dead(),
                dead()
            ),
            LinkState::Starting
        );
    }

    #[test]
    fn refresh_updates_state_in_place() {
        let mut status = LinkStatus::new(LinkState::Idle);
        status.nat = ok();
        status.refresh(true, Some(ok()));
        assert_eq!(status.state, LinkState::Running);
        status.firewall = failed();
        status.refresh(true, Some(ok()));
        assert_eq!(status.state, LinkState::Degraded);
    }
}
