pub use landscape_common::dns::check::{
    CheckChainDnsResult, CheckDnsReq, CheckDnsResult, LandscapeRecord as CommonRecord,
};

pub mod coordinator;
pub(crate) mod domain;

pub mod listener;
pub mod mdns;
pub mod resolve;
pub mod server;
pub(crate) mod upstream;

mod records;
mod system;

pub use records::{convert_record_type, to_common_records};
pub use system::{prepare_system_dns, restore_resolver_conf};

#[cfg(all(feature = "pool-exp", feature = "pool-native"))]
compile_error!("features `pool-exp` and `pool-native` are mutually exclusive: enable exactly one");
