use landscape_common::dns::rule::DNSRuntimeRule;
use landscape_common::dns::ChainDnsServerInitInfo;
use landscape_common::event::hub::{EnrolledDeviceEventReader, IPv4AssignEventReader};
use landscape_common::sys_service::hostname_registry::HostnameRegistryConfig;
use landscape_core::lan_hostname::HostnameRegistry;
use landscape_dns::server::{CacheRuntimeConfig, LandscapeDnsServer};

/// cargo run --package landscape-dns --bin test_dns_server
#[tokio::main]
async fn main() -> std::io::Result<()> {
    landscape_common::init_tracing!();

    let listen_port = 54;
    let (_tx, rx) = tokio::sync::broadcast::channel(64);
    let (_tx2, rx2) = tokio::sync::broadcast::channel(64);
    let hostname_registry = HostnameRegistry::new(
        HostnameRegistryConfig::default(),
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
        hostname_registry,
    );

    // handler
    let default_rule = vec![DNSRuntimeRule::default()];

    let info = ChainDnsServerInitInfo { dns_rules: default_rule, redirect_rules: vec![] };
    println!("=============================================");
    server.refresh_flow_server(info.into()).await;

    let _ = tokio::signal::ctrl_c().await;

    Ok(())
}
