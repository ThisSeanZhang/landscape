use serde::{Deserialize, Serialize};

/// A build-time capability that the running backend supports.
///
/// Capabilities reflect which compile-time features were enabled when the
/// `landscape-webserver` binary was built. The frontend fetches this list and
/// grays out (disables) the UI that depends on a missing capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Capability {
    /// HTTP/HTTPS reverse proxy gateway (cargo feature `gateway`).
    Gateway,
    /// Persistent metric storage and history queries (cargo feature `metric-persistent`).
    MetricPersistent,
    /// Per-subsystem memory self-monitoring (cargo feature `mem-track`).
    MemTrack,
}
