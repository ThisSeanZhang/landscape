pub mod api;
pub mod config;
pub mod error;
pub mod rule_cache;
pub mod runtime;

pub use api::*;
pub use config::*;
pub use error::GeoError;
pub use rule_cache::*;
pub use runtime::{GeoSourceKind, GeoTaskPhase, GeoTaskProgress};

#[derive(Debug)]
pub enum RawDatState {
    Ready(Vec<u8>),
    Started,
    Running,
}
