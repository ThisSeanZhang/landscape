use landscape_common::{
    config::dns::DNSRuntimeRule,
    dns::{upstream::DnsUpstreamConfig, ChainDnsServerInitInfo},
};
use landscape_dns::reuseport_chain_server::LandscapeReusePortChainDnsServer;

/// cargo run --package landscape-dns --bin test_reuseport_chain_server
#[tokio::main]
async fn main() -> std::io::Result<()> {
    landscape_common::init_tracing!();

    let listen_port = 54;
    let server = LandscapeReusePortChainDnsServer::new(listen_port);

    // handler
    let default_rule = vec![DNSRuntimeRule::default()];

    let info = ChainDnsServerInitInfo { dns_rules: default_rule, redirect_rules: vec![] };
    println!("=============================================");
    server.refresh_flow_server(0, info).await;

    let _ = tokio::signal::ctrl_c().await;

    Ok(())
}
