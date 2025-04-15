use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use landscape_common::dns::DNSRuleConfig;
use landscape_dns::server::{request::LandscapeDnsRequestHandle, server::DiffFlowServer};
use tokio::sync::RwLock;

/// cargo run --package landscape-dns --bin test_diff_mark_server
#[tokio::main]
async fn main() -> std::io::Result<()> {
    landscape_common::init_tracing!();

    let listen_port = 53;

    let default_rule = vec![DNSRuleConfig::default()];
    let handler = LandscapeDnsRequestHandle::new(default_rule, &HashMap::new(), 100);
    let mut handlers_map = HashMap::new();
    handlers_map.insert(100, handler);
    let mut server = DiffFlowServer::new(
        Arc::new(RwLock::new(handlers_map)),
        Arc::new(RwLock::new(HashMap::new())),
    );

    server.listen_on(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), listen_port));

    server.block_until_done().await.unwrap();
    Ok(())
}
