use landscape_common::{dns::rule::DNSRuntimeRule, dns::ChainDnsServerInitInfo};
use landscape_dns::server::{CacheRuntimeConfig, LandscapeDnsServer};

/// cargo run --package landscape-dns --bin test_dns_server
#[tokio::main]
async fn main() -> std::io::Result<()> {
    landscape_common::init_tracing!();

    let listen_port = 54;
    let (_, ipv4_rx) =
        tokio::sync::broadcast::channel::<landscape_common::event::hub::IPv4AssignEvent>(1);
    let ipv4_reader = landscape_common::event::hub::IPv4AssignEventReader::new(ipv4_rx);
    let server = LandscapeDnsServer::new(
        listen_port,
        None,
        CacheRuntimeConfig::default(),
        None,
        None,
        None,
        ipv4_reader,
    );

    // handler
    let default_rule = vec![DNSRuntimeRule::default()];

    let info = ChainDnsServerInitInfo { dns_rules: default_rule, redirect_rules: vec![] };
    println!("=============================================");
    server.refresh_flow_server(info.into()).await;

    let _ = tokio::signal::ctrl_c().await;

    Ok(())
}
