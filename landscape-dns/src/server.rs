use std::{
    collections::HashMap,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use hickory_server::ServerFuture;
use landscape_common::{
    config::DnsRuntimeConfig, dns::ChainDnsServerInitInfo, event::DnsMetricMessage,
    service::WatchService,
};
use rustls::server::ResolvesServerCert;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::{
    convert_record_type, server::handler::DnsRequestHandler, CheckChainDnsResult, CheckDnsReq,
};

pub(crate) mod handler;
pub(crate) mod matcher;
pub(crate) mod rule;

#[derive(Clone)]
pub struct LandscapeDnsServer {
    pub status: WatchService,
    flow_dns_server: Arc<Mutex<HashMap<u32, (DnsRequestHandler, CancellationToken)>>>,
    pub addr: SocketAddr,
    pub msg_tx: Option<mpsc::Sender<DnsMetricMessage>>,
    pub doh: Option<DohListenerConfig>,
}

#[derive(Clone)]
pub struct DohListenerConfig {
    pub addr: SocketAddr,
    pub handshake_timeout: Duration,
    pub server_cert_resolver: Arc<dyn ResolvesServerCert>,
    pub dns_hostname: Option<String>,
    pub http_endpoint: String,
}

impl LandscapeDnsServer {
    pub fn new(
        listen_port: u16,
        msg_tx: Option<mpsc::Sender<DnsMetricMessage>>,
        doh: Option<DohListenerConfig>,
    ) -> Self {
        crate::check_resolver_conf();
        let status = WatchService::new();
        Self {
            status,
            flow_dns_server: Arc::new(Mutex::new(HashMap::new())),
            addr: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, listen_port, 0, 0)),
            msg_tx,
            doh,
        }
    }

    pub fn get_status(&self) -> &WatchService {
        &self.status
    }

    pub async fn refresh_flow_server(
        &self,
        flow_id: u32,
        info: ChainDnsServerInitInfo,
        dns_config: DnsRuntimeConfig,
    ) {
        {
            let mut lock = self.flow_dns_server.lock().await;
            if let Some((old_handler, _)) = lock.get_mut(&flow_id) {
                old_handler.renew_rules(info, dns_config).await;
                return;
            }
        }

        let handler = DnsRequestHandler::new(info, dns_config, flow_id, self.msg_tx.clone());
        let token = start_dns_server(flow_id, self.addr, self.doh.clone(), handler.clone()).await;

        {
            let mut lock = self.flow_dns_server.lock().await;
            lock.insert(flow_id, (handler, token));
        }
    }

    pub async fn check_domain(&self, req: CheckDnsReq) -> CheckChainDnsResult {
        let handler = {
            let flow_server = self.flow_dns_server.lock().await;
            if let Some((handler, _)) = flow_server.get(&req.flow_id) {
                Some(handler.clone())
            } else {
                None
            }
        };

        if let Some(handler) = handler {
            handler.check_domain(&req.get_domain(), convert_record_type(req.record_type)).await
        } else {
            CheckChainDnsResult::default()
        }
    }
}

pub async fn start_dns_server(
    flow_id: u32,
    addr: SocketAddr,
    doh: Option<DohListenerConfig>,
    handler: DnsRequestHandler,
) -> CancellationToken {
    let Ok((udp, sock_fd)) = crate::listener::create_udp_socket(addr).await else {
        tracing::error!("[flow: {flow_id}]: create udp socket error");
        let result = CancellationToken::new();
        result.cancel();
        return result;
    };

    landscape_ebpf::map_setting::dns::setting_dns_sock_map(sock_fd, flow_id);
    landscape_ebpf::dns_dispatcher::attach_reuseport_ebpf(sock_fd).unwrap();
    let mut server = ServerFuture::new(handler);
    server.register_socket(udp);
    if let Some(doh) = doh {
        // DoH follows the same model as UDP: one reuseport listener per flow + eBPF selection.
        match crate::listener::create_tcp_listener(doh.addr) {
            Ok((listener, sock_fd)) => {
                landscape_ebpf::map_setting::dns::setting_dns_sock_map_tcp(sock_fd, flow_id);
                landscape_ebpf::dns_dispatcher::attach_reuseport_ebpf(sock_fd).unwrap();
                if let Err(e) = server.register_https_listener(
                    listener,
                    doh.handshake_timeout,
                    doh.server_cert_resolver.clone(),
                    doh.dns_hostname.clone(),
                    doh.http_endpoint,
                ) {
                    tracing::error!("[flow: {flow_id}]: register DoH listener error: {e}");
                }
            }
            Err(e) => {
                tracing::error!("[flow: {flow_id}]: create DoH listener error: {e}");
            }
        }
    }

    let token = server.shutdown_token().clone();

    tokio::spawn(async move {
        if let Err(e) = server.block_until_done().await {
            tracing::error!("[flow: {flow_id}]: server down, error: {e:?}");
        } else {
            tracing::info!("[flow: {flow_id}]: server down");
        }
    });

    token
}
