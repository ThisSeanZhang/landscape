use std::sync::Arc;

use landscape_common::config_service::geo::{
    GeoError, GeoFileCacheKey, GeoMatcherSource, GeoSiteFileConfig,
};
use landscape_common::dns::gen_default_dns_rule_and_upstream;
use landscape_common::event::hub::{EnrolledDeviceEventReader, IPv4AssignEventReader};
use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
use landscape_core::lan_hostname::LanHostnameRegistry;
use landscape_dns::server::{CacheRuntimeConfig, LandscapeDnsServer, MatcherBuilder};

struct EmptyGeoSource;

#[async_trait::async_trait]
impl GeoMatcherSource for EmptyGeoSource {
    async fn load_geo_domains(
        &self,
        _key: &GeoFileCacheKey,
    ) -> Result<Option<Vec<GeoSiteFileConfig>>, GeoError> {
        Ok(None)
    }
}

/// cargo run --package landscape-dns --bin test_dns_server
#[tokio::main]
async fn main() -> std::io::Result<()> {
    landscape_common::init_tracing!();

    let listen_port = 54;
    let (_tx, rx) = tokio::sync::broadcast::channel(64);
    let (_tx2, rx2) = tokio::sync::broadcast::channel(64);
    let lan_hostname_registry = LanHostnameRegistry::new(
        LanHostnameConfig::default(),
        vec![],
        IPv4AssignEventReader::new(rx),
        EnrolledDeviceEventReader::new(rx2),
    );
    let server = LandscapeDnsServer::new(
        listen_port,
        None,
        CacheRuntimeConfig::default(),
        None,
        None,
        None,
        lan_hostname_registry,
    );

    let (default_rule, upstream) = gen_default_dns_rule_and_upstream();
    let builder = MatcherBuilder::new(Arc::new(EmptyGeoSource));
    let (redirect_engine, resolve_engine, _) =
        builder.build_flow(0, vec![default_rule], vec![], vec![], vec![upstream]).await;
    println!("=============================================");
    server.refresh_flow_runtime(0, redirect_engine, resolve_engine).await;

    let _ = tokio::signal::ctrl_c().await;

    Ok(())
}
