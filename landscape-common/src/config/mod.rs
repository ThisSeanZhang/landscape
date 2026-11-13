pub mod cli;
pub mod error;
pub mod init;

pub use cli::{ConfigCliArgs, ConfigCliError, ConfigOutput};
pub use error::InitConfigError;
pub use init::InitConfig;

use uuid::Uuid;

pub type FlowId = u32;
pub type ConfigId = Uuid;

/// Implicit "default flow" for unmatched traffic. It owns seeded rules
/// (e.g. the default DNS rule) and is editable from the UI, but has no
/// `FlowConfig` row — flow-existence checks must exempt it.
pub const DEFAULT_FLOW_ID: FlowId = 0;
