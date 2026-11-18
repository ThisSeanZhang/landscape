use std::sync::Arc;

use landscape_common::sys_config::CacheRuntimeConfig;
use landscape_core::geo_cache::SiteMatcherRegistry;

use crate::server::{EngineBuilder, LandscapeDnsServer};

mod events;
mod refresh;
mod source;
pub use source::{DnsConfigError, DnsConfigSource, FlowConfigBundle};

#[cfg(test)]
mod tests;

/// Drives the DNS server from configuration and change events. It owns the
/// engine builder and the config source, while the server owns listeners and
/// per-flow runtime state.
pub struct DnsCoordinator {
    server: LandscapeDnsServer,
    builder: EngineBuilder,
    source: Arc<dyn DnsConfigSource>,
}

impl DnsCoordinator {
    pub fn new(
        server: LandscapeDnsServer,
        matcher_registry: Arc<SiteMatcherRegistry>,
        source: Arc<dyn DnsConfigSource>,
    ) -> Self {
        Self {
            server,
            builder: EngineBuilder::new(matcher_registry),
            source,
        }
    }

    pub fn server(&self) -> &LandscapeDnsServer {
        &self.server
    }

    pub async fn apply_cache_config(&self, cache_runtime: CacheRuntimeConfig) {
        let previous_cache_runtime = self.server.cache_config();
        let rebuild_cache = previous_cache_runtime.cache_capacity != cache_runtime.cache_capacity
            || previous_cache_runtime.cache_ttl != cache_runtime.cache_ttl;
        self.server.update_runtime_config(cache_runtime);
        self.server.renew_runtime_config(rebuild_cache).await;
    }
}
