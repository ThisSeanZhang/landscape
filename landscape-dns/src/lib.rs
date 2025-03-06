use hickory_proto::rr::{Record, RecordType};
use hickory_server::ServerFuture;
use landscape_common::args::LAND_HOME_PATH;
use landscape_common::dns::{DNSRuleConfig, DomainConfig};
use landscape_common::mark::PacketMark;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use landscape_common::GEO_SITE_FILE_NAME;
use lru::LruCache;
use multi_rule_dns_server::DnsServer;
use protos::geo::GeoSiteListOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;

mod connection;
pub mod ip_rule;
pub mod multi_rule_dns_server;
pub mod protos;
pub mod rule;

/// Timeout for TCP connections.
const TCP_TIMEOUT: Duration = Duration::from_secs(10);

pub struct CacheDNSItem {
    rdatas: Vec<Record>,
    insert_time: Instant,
    mark: PacketMark,
}

pub type DNSCache = LruCache<(String, RecordType), Vec<CacheDNSItem>>;

#[derive(Serialize, Debug, Clone)]
pub struct LandscapeDnsService {
    pub status: DefaultWatchServiceStatus,
}

impl LandscapeDnsService {
    pub async fn new() -> Self {
        LandscapeDnsService { status: DefaultWatchServiceStatus::new() }
    }

    pub async fn read_geo_site_file(&self) -> HashMap<String, Vec<DomainConfig>> {
        let mut result = HashMap::new();
        let geo_file_path = LAND_HOME_PATH.join(GEO_SITE_FILE_NAME);

        if geo_file_path.exists() && geo_file_path.is_file() {
            // 读取文件并解析为 Owned 结构体
            let data = tokio::fs::read(geo_file_path).await.unwrap();
            let list = GeoSiteListOwned::try_from(data).unwrap();

            for entry in list.entry.iter() {
                let domains = entry.domain.iter().map(rule::convert_domain_from_proto).collect();
                result.insert(entry.country_code.to_string(), domains);
            }
        } else {
            tracing::error!("geo file don't exists or not a file, return empty map");
        }

        result
    }

    pub async fn start(
        &self,
        udp_port: u16,
        tcp_port: Option<u16>,
        dns_rules: Vec<DNSRuleConfig>,
        old_cache: Option<Arc<Mutex<DNSCache>>>,
    ) -> Arc<Mutex<DNSCache>> {
        let dns_rules = dns_rules.into_iter().filter(|rule| rule.enable).collect();
        let handler = DnsServer::new(dns_rules, self.read_geo_site_file().await, old_cache);
        let cache = handler.clone_cache();

        let mut server = ServerFuture::new(handler);

        let status_clone = self.status.clone();

        status_clone.just_change_status(ServiceStatus::Staring);
        // register UDP listeners
        server.register_socket(
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), udp_port))
                .await
                .unwrap(),
        );

        if let Some(tcp_port) = tcp_port {
            server.register_listener(
                TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tcp_port))
                    .await
                    .unwrap(),
                TCP_TIMEOUT,
            );
        }

        tokio::spawn(async move {
            status_clone.just_change_status(ServiceStatus::Running);

            let state_end_loop = status_clone.wait_to_stopping();
            let trigger_by_ui = tokio::select! {
                _ = state_end_loop => {
                    true
                },
                result = server.block_until_done() => {
                    let message = if let Err(e) = result {
                        Some(e.to_string())
                    } else {
                        None
                    };
                    tracing::error!("DNS Stop by Error: {message:?}");
                    status_clone.just_change_status(ServiceStatus::Stop);
                    false
                }
            };

            if trigger_by_ui {
                tracing::info!("DNS stopping trigger by ui");
                if let Err(e) = server.shutdown_gracefully().await {
                    tracing::error!("{e:?}");
                    status_clone.just_change_status(ServiceStatus::Stop);
                } else {
                    status_clone.just_change_status(ServiceStatus::Stop);
                }
            }
        });
        cache
    }

    pub fn stop(&self) {
        self.status.just_change_status(ServiceStatus::Stopping);
    }
}
