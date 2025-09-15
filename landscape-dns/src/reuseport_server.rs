use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    str::FromStr,
    sync::Arc,
};

use hickory_proto::{
    op::ResponseCode,
    rr::{
        rdata::{A, AAAA},
        RData, Record, RecordType,
    },
};
use hickory_server::ServerFuture;
use landscape_common::{
    dns::{DnsServerInitInfo, RedirectInfo, RuleHandlerInfo},
    service::DefaultWatchServiceStatus,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    connection::{create_resolver, LandscapeMarkDNSResolver},
    convert_record_type,
    reuseport_server::{matcher::DomainMatcher, request::LandscapeDnsRequestHandle},
    CheckDnsReq, CheckDnsResult,
};

pub mod listener;
mod matcher;
mod request;

#[derive(Clone)]
pub struct LandscapeReusePortDnsServer {
    pub status: DefaultWatchServiceStatus,
    flow_dns_server: Arc<Mutex<HashMap<u32, (LandscapeDnsRequestHandle, CancellationToken)>>>,
    pub addr: SocketAddr,
}

impl LandscapeReusePortDnsServer {
    pub fn new(listen_port: u16) -> Self {
        crate::check_resolver_conf();
        let status = DefaultWatchServiceStatus::new();
        Self {
            status,
            flow_dns_server: Arc::new(Mutex::new(HashMap::new())),
            addr: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, listen_port, 0, 0)),
        }
    }

    pub fn get_status(&self) -> &DefaultWatchServiceStatus {
        &self.status
    }

    pub async fn refresh_flow_server(&self, flow_id: u32, info: DnsServerInitInfo) {
        tracing::debug!(
            "[flow_id: {flow_id}]: dns init default_resolver: {:#?}",
            info.default_resolver
        );
        {
            let mut lock = self.flow_dns_server.lock().await;
            if let Some((old_handler, _)) = lock.get_mut(&flow_id) {
                old_handler.renew_rules(info).await;
                return;
            }
        }

        let handler = LandscapeDnsRequestHandle::new(info, flow_id);
        let token = start_dns_server(flow_id, self.addr, handler.clone()).await;

        {
            let mut lock = self.flow_dns_server.lock().await;
            lock.insert(flow_id, (handler, token));
        }
    }

    pub async fn check_domain(&self, req: CheckDnsReq) -> CheckDnsResult {
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
            CheckDnsResult::default()
        }
    }
}

pub async fn start_dns_server(
    flow_id: u32,
    addr: SocketAddr,
    handler: LandscapeDnsRequestHandle,
) -> CancellationToken {
    let Ok((udp, sock_fd)) = listener::create_udp_socket(addr).await else {
        tracing::error!("[flow: {flow_id}]: create udp socket error");
        let result = CancellationToken::new();
        result.cancel();
        return result;
    };

    landscape_ebpf::map_setting::dns::setting_dns_sock_map(sock_fd, flow_id);
    landscape_ebpf::dns_dispatcher::attach_reuseport_ebpf(sock_fd).unwrap();
    let mut server = ServerFuture::new(handler);
    server.register_socket(udp);

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

pub struct FlowDnsServer {
    redirect_matcher: DomainMatcher<RedirectInfo>,
    matcher: DomainMatcher<RuleHandlerInfo>,
    resolver_map: HashMap<Uuid, LandscapeMarkDNSResolver>,
    default_resolver: Option<RuleHandlerInfo>,
    // cache: Arc<Mutex<DNSCache>>,
}

impl FlowDnsServer {
    pub fn new(info: DnsServerInitInfo) -> Self {
        // let (matcher, resolver_map, default_resolver) = Self::build_rules(infos);
        FlowDnsServer {
            redirect_matcher: DomainMatcher::new(info.redirect_rules),
            matcher: DomainMatcher::new(info.rules),
            resolver_map: info
                .resolver_configs
                .into_iter()
                .map(|e| (e.id, create_resolver(e.flow_id, e.mark, e.resolve_mode)))
                .collect(),
            default_resolver: info.default_resolver,
        }
    }

    pub fn redirect_lookup(&self, domain: &str, query_type: RecordType) -> Vec<Record> {
        if let Some(info) = self.redirect_matcher.match_value(domain) {
            let mut result = vec![];
            for ip in &info.result_ip {
                let rdata_ip = match (ip, &query_type) {
                    (IpAddr::V4(ip), RecordType::A) => Some(RData::A(A(*ip))),
                    (IpAddr::V6(ip), RecordType::AAAA) => Some(RData::AAAA(AAAA(*ip))),
                    _ => None,
                };

                if let Some(rdata) = rdata_ip {
                    result.push(Record::from_rdata(
                        hickory_resolver::Name::from_str(domain).unwrap(),
                        300,
                        rdata,
                    ));
                }
            }

            return result;
        }
        vec![]
    }

    pub async fn lookup(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Result<(Vec<Record>, &RuleHandlerInfo), ResponseCode> {
        let info = self.matcher.match_value(&domain).or(self.default_resolver.as_ref());
        if let Some(info) = info {
            if let Some(resolver) = self.resolver_map.get(&info.resolver_id) {
                return match resolver.lookup(domain, query_type).await {
                    Ok(lookup) => Ok((lookup.records().to_vec(), info)),
                    Err(e) => {
                        let result = if e.is_no_records_found() {
                            ResponseCode::NoError
                        } else {
                            tracing::error!(
                                "[flow_id: {:?}] DNS resolution failed for {}: {}",
                                info.flow_id,
                                domain,
                                e
                            );
                            ResponseCode::ServFail
                        };
                        Err(result)
                    }
                };
            } else {
                tracing::debug!(
                    "can not find resolver_id: {:?} in resolver_map: {:?}",
                    info.resolver_id,
                    self.resolver_map
                );
            }
        }

        Err(ResponseCode::ServFail)
    }
}
