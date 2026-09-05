//! Boundary marker for eBPF dataplane capabilities.
//!
//! Landscape services receive narrow capability traits (e.g.
//! [`crate::wan_service::pppoe::PppoeDataplane`]) instead of the full
//! eBPF runtime.  Attached dataplane state (TC/XDP stages, chain slots)
//! is handed back as an opaque guard: dropping it tears the state down.

/// Opaque teardown guard for an attached eBPF dataplane.
///
/// Holding the guard keeps the dataplane attached; dropping it detaches
/// and recycles all related kernel state.  There is intentionally no
/// other API surface.
pub trait DataplaneGuard: Send + Sync {}

/// The unit type is a valid (do-nothing) guard, used by no-op
/// implementations in tests.
impl DataplaneGuard for () {}
