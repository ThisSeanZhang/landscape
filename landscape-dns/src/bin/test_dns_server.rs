use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::dns::gen_default_dns_rule_and_upstream;
use landscape_common::flow::{NoopDnsResultSink, NoopFlowSocketRegistrar};
use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
use landscape_core::geo_cache::{GeoCacheDatabase, SiteCacheRepository, SiteMatcherRegistry};
use landscape_core::lan_device::LanDeviceDirectory;
use landscape_dns::server::{CacheRuntimeConfig, LandscapeDnsServer, MatcherBuilder};

/// cargo run --package landscape-dns --bin test_dns_server
#[tokio::main]
async fn main() -> std::io::Result<()> {
    landscape_common::init_tracing!();

    let listen_port = 54;
    let server = LandscapeDnsServer::new(
        listen_port,
        None,
        CacheRuntimeConfig::default(),
        None,
        None,
        None,
        LanDeviceDirectory::new_for_test(),
        Arc::new(ArcSwap::from_pointee(LanHostnameConfig::default())),
        Arc::new(NoopDnsResultSink),
        Arc::new(NoopFlowSocketRegistrar),
    );

    let (default_rule, upstream) = gen_default_dns_rule_and_upstream();
    // empty in-memory geo cache: every geo key resolves to "missing"
    let registry = Arc::new(SiteMatcherRegistry::new(SiteCacheRepository::new(
        GeoCacheDatabase::site_mem().await,
    )));
    let builder = MatcherBuilder::new(registry);
    let (redirect_engine, resolve_engine, _) =
        builder.build_flow(0, vec![default_rule], vec![], vec![], vec![upstream]).await;
    println!("=============================================");
    server.refresh_flow_runtime(0, redirect_engine, resolve_engine).await;

    let _ = tokio::signal::ctrl_c().await;

    Ok(())
}
