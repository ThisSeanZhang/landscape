pub mod api;
pub mod config;
pub mod runtime;

pub use api::{GetDnsConfigResponse, UpdateDnsConfigRequest};
pub use config::LandscapeDnsConfig;
pub use runtime::{CacheRuntimeConfig, DnsRuntimeConfig, DohRuntimeConfig};
