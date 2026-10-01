//! Re-export of the core IP route state service.
//!
//! The implementation lives in `landscape-core`; per-flow WAN target
//! recomputation is driven by [`crate::flow::rule_service::FlowRuleService`].

pub use landscape_core::route::{IpRouteService, LocalAddrView, WanRouteEvent, WanRouteEventKind};
