use std::sync::atomic::{AtomicUsize, Ordering};

use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::sys_service::gateway::{HttpUpstreamTarget, LoadBalanceMethod};
use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::SharedGatewayRoutes;
use crate::health::GatewayHealth;
use crate::routes::{CompiledGatewayRoutes, CompiledSniRoute};
use std::sync::Arc;

pub struct SniProxyRouter {
    routes: SharedGatewayRoutes,
    round_robin_counter: AtomicUsize,
    health: GatewayHealth,
}

impl SniProxyRouter {
    pub fn new(routes: SharedGatewayRoutes) -> Self {
        Self::with_health(routes, GatewayHealth::default())
    }

    pub(crate) fn with_health(routes: SharedGatewayRoutes, health: GatewayHealth) -> Self {
        Self {
            routes,
            round_robin_counter: AtomicUsize::new(0),
            health,
        }
    }

    pub fn has_sni_proxy_rules(&self) -> bool {
        self.routes.load().has_sni_routes()
    }

    pub fn match_target(&self, sni: &str) -> Option<MatchedSniTarget> {
        self.route(&self.routes.load(), sni).ok().flatten()
    }

    pub(crate) fn snapshot(&self) -> Arc<CompiledGatewayRoutes> {
        self.routes.load_full()
    }

    pub(crate) fn route(
        &self,
        routes: &CompiledGatewayRoutes,
        sni: &str,
    ) -> io::Result<Option<MatchedSniTarget>> {
        let Some(route) = routes.match_sni_route(sni) else { return Ok(None) };
        MatchedSniTarget::new(&route, &self.health, &self.round_robin_counter, sni)
            .map(Some)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no eligible SNI upstream"))
    }
}

#[derive(Debug, Clone)]
pub struct MatchedSniTarget {
    pub rule_name: String,
    pub sni: String,
    pub target: HttpUpstreamTarget,
}

impl MatchedSniTarget {
    fn new(
        rule: &CompiledSniRoute,
        health: &GatewayHealth,
        counter: &AtomicUsize,
        sni: &str,
    ) -> Option<Self> {
        let seed = match rule.upstream.load_balance {
            LoadBalanceMethod::RoundRobin if rule.upstream.targets.len() > 1 => {
                counter.fetch_add(1, Ordering::Relaxed) as u64
            }
            _ => fnv1a_hash(sni),
        };
        let target = health.select(&rule.upstream, seed)?.clone();

        Some(Self {
            rule_name: rule.rule_name.clone(),
            sni: sni.to_string(),
            target,
        })
    }
}

pub async fn proxy_tls_passthrough(
    downstream: TcpStream,
    target: &MatchedSniTarget,
    cancel: CancellationToken,
) -> io::Result<()> {
    proxy_prefixed_tls_passthrough(
        crate::client_hello::ReplayTcpStream::new(downstream, Vec::new()),
        target,
        cancel,
    )
    .await
}

pub(crate) async fn proxy_prefixed_tls_passthrough(
    downstream: crate::client_hello::ReplayTcpStream,
    target: &MatchedSniTarget,
    cancel: CancellationToken,
) -> io::Result<()> {
    let target = &target.target;
    let upstream = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = crate::upstream::connect_tcp(target.connection_host(), target.port, std::time::Duration::from_secs(10)) => result?,
    };

    let (mut downstream_read, mut downstream_write) = downstream.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let mut client_to_upstream =
        spawn_task(task_label::task::GATEWAY_SNI_CLIENT_TO_UPSTREAM, async move {
            let result = io::copy(&mut downstream_read, &mut upstream_write).await;
            let _ = upstream_write.shutdown().await;
            result
        });

    let mut upstream_to_client =
        spawn_task(task_label::task::GATEWAY_SNI_UPSTREAM_TO_CLIENT, async move {
            let result = io::copy(&mut upstream_read, &mut downstream_write).await;
            let _ = downstream_write.shutdown().await;
            result
        });

    // EOF half-closes only that direction. Keep forwarding the other direction
    // until it also finishes; cancellation/errors still finish both tasks.
    let mut client_done = false;
    let mut upstream_done = false;
    let result = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Ok(()),
            result = &mut client_to_upstream, if !client_done => {
                client_done = true;
                if let Err(error) = join_copy_task(result) { break Err(error); }
                if upstream_done { break Ok(()); }
            },
            result = &mut upstream_to_client, if !upstream_done => {
                upstream_done = true;
                if let Err(error) = join_copy_task(result) { break Err(error); }
                if client_done { break Ok(()); }
            },
        }
    };
    if !client_done {
        client_to_upstream.abort();
        let _ = client_to_upstream.await;
    }
    if !upstream_done {
        upstream_to_client.abort();
        let _ = upstream_to_client.await;
    }
    result
}

fn join_copy_task(result: Result<io::Result<u64>, tokio::task::JoinError>) -> io::Result<()> {
    match result {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(io::Error::other(e)),
    }
}

/// Parse the SNI (Server Name Indication) extension from a TLS ClientHello message.
///
/// The function peeks at the raw bytes without consuming them.
/// Returns `Some(hostname)` if a valid SNI extension is found, `None` otherwise.
pub fn parse_sni_from_client_hello(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }

    let handshake = &buf[5..5 + record_len];
    parse_sni_from_handshake(handshake)
}

pub(crate) fn parse_sni_from_handshake(handshake: &[u8]) -> Option<String> {
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }

    let hs_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake.len() < 4 + hs_len {
        return None;
    }

    let ch = &handshake[4..4 + hs_len];
    if ch.len() < 34 {
        return None;
    }

    let mut pos = 34;

    if pos >= ch.len() {
        return None;
    }
    let session_id_len = ch[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos >= ch.len() {
        return None;
    }
    let cm_len = ch[pos] as usize;
    pos += 1 + cm_len;

    if pos + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    if ext_end > ch.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_data_len > ext_end {
            return None;
        }

        if ext_type == 0x0000 {
            return parse_sni_extension(&ch[pos..pos + ext_data_len]);
        }
        pos += ext_data_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut pos = 2;
    let end = 2 + list_len;
    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if name_type == 0x00 && pos + name_len <= end {
            return String::from_utf8(data[pos..pos + name_len].to_vec())
                .ok()
                .map(|name| name.to_ascii_lowercase());
        }
        pos += name_len;
    }

    None
}

fn fnv1a_hash(input: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for b in input.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use landscape_common::sys_service::gateway::{
        ClientIpHeaderPolicy, HttpUpstreamConfig, HttpUpstreamMatchRule, HttpUpstreamRuleConfig,
        ProxyHeaderConflictMode,
    };

    fn target(address: &str, port: u16, weight: u32) -> HttpUpstreamTarget {
        HttpUpstreamTarget {
            address: address.to_string(),
            port,
            weight,
            tls: true,
            skip_cert_verify: false,
        }
    }

    fn sni_rule(
        name: &str,
        domains: &[&str],
        targets: Vec<HttpUpstreamTarget>,
    ) -> HttpUpstreamRuleConfig {
        HttpUpstreamRuleConfig {
            id: uuid::Uuid::new_v4(),
            enable: true,
            name: name.to_string(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
            match_rule: HttpUpstreamMatchRule::SniProxy,
            upstream: HttpUpstreamConfig {
                targets,
                load_balance: LoadBalanceMethod::RoundRobin,
                health_check: None,
                request_headers: vec![],
                header_conflict_mode: ProxyHeaderConflictMode::Set,
                client_ip_headers: ClientIpHeaderPolicy::None,
            },
            update_at: 0.0,
        }
    }

    fn shared_routes(rules: Vec<HttpUpstreamRuleConfig>) -> SharedGatewayRoutes {
        Arc::new(crate::routes::GatewayRoutes::new(
            crate::routes::CompiledGatewayRoutes::compile(&rules).unwrap(),
        ))
    }

    fn build_client_hello_with_sni(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let server_name_len = host_bytes.len() as u16;
        let sni_list_len = 1 + 2 + server_name_len;
        let sni_ext_len = 2 + sni_list_len;

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(sni_ext_len + 4).to_be_bytes());
        hello.extend_from_slice(&0u16.to_be_bytes());
        hello.extend_from_slice(&sni_ext_len.to_be_bytes());
        hello.extend_from_slice(&sni_list_len.to_be_bytes());
        hello.push(0);
        hello.extend_from_slice(&server_name_len.to_be_bytes());
        hello.extend_from_slice(host_bytes);

        let hello_len = hello.len() as u32;
        let mut handshake = vec![
            0x01,
            ((hello_len >> 16) & 0xff) as u8,
            ((hello_len >> 8) & 0xff) as u8,
            (hello_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);

        let record_len = handshake.len() as u16;
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[tokio::test]
    async fn health_checks_remove_and_restore_an_upstream_without_reloading_the_listener() {
        use landscape_common::sys_service::gateway::HealthCheckConfig;
        use std::time::Duration;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut rule =
            sni_rule("health", &["test.example"], vec![target("[::1]", address.port(), 1)]);
        rule.upstream.health_check = Some(HealthCheckConfig {
            interval_secs: 1,
            timeout_secs: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        });
        let routes = shared_routes(vec![]);
        let health = GatewayHealth::default();
        let router = SniProxyRouter::with_health(routes.clone(), health.clone());
        let stop = CancellationToken::new();
        let worker = tokio::spawn({
            let routes = routes.clone();
            let stop = stop.clone();
            async move { health.monitor(&routes, &stop).await }
        });
        routes.store(Arc::new(CompiledGatewayRoutes::compile(&[rule]).unwrap()));
        drop(listener);
        tokio::time::timeout(Duration::from_secs(5), async {
            while router.match_target("test.example").is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(router.route(&router.snapshot(), "test.example").is_err());
            let _upstream = TcpListener::bind(address).await.unwrap();
            while router.match_target("test.example").is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        stop.cancel();
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn local_https_replays_inspected_hello_and_serves_http() {
        use rustls::{
            ClientConfig, RootCertStore, ServerConfig, crypto::ring, pki_types::PrivateKeyDer,
        };
        use std::time::Duration;
        use tokio::io::{AsyncBufReadExt, BufReader};
        let cert = rcgen::generate_simple_self_signed(vec!["local.example".into()]).unwrap();
        let provider = Arc::new(ring::default_provider());
        let mut tls = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let routes = shared_routes(vec![sni_rule(
            "other",
            &["other.example"],
            vec![target("127.0.0.1", 443, 1)],
        )]);
        let reservation = std::net::TcpListener::bind("[::]:0").unwrap();
        let address = (std::net::Ipv6Addr::LOCALHOST, reservation.local_addr().unwrap().port());
        drop(reservation);
        let server = crate::GatewayServer::spawn(
            routes,
            &crate::GatewayRuntimeConfig { enable: true, http_port: 0, https_port: address.1 },
            Some(crate::GatewayTlsConfig { server_config: Arc::new(tls) }),
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while !server.has_https_listener() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            let connection = TcpStream::connect(address).await.unwrap();
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client.clone()))
                .connect("local.example".try_into().unwrap(), connection)
                .await
                .unwrap();
            tls.write_all(b"GET / HTTP/1.1\r\nHost: local.example\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = String::new();
            BufReader::new(tls).read_line(&mut response).await.unwrap();
            assert!(response.starts_with("HTTP/1.1 404"), "{response}");

            client.alpn_protocols = vec![b"h2".to_vec()];
            let socket = TcpStream::connect(address).await.unwrap();
            let tls = tokio_rustls::TlsConnector::from(Arc::new(client))
                .connect("local.example".try_into().unwrap(), socket)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let (mut h2, connection) = h2::client::handshake(tls).await.unwrap();
            let driver = tokio::spawn(connection);
            let request = http::Request::builder().uri("https://local.example/").body(()).unwrap();
            let (response, _) = h2.send_request(request, true).unwrap();
            assert_eq!(response.await.unwrap().status(), http::StatusCode::NOT_FOUND);
            drop(h2);
            driver.await.unwrap().unwrap();
        })
        .await
        .unwrap();
        server.shutdown_and_wait(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn passthrough_keeps_the_response_after_client_half_close() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let incoming = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream = TcpListener::bind("[::1]:0").await.unwrap();
            let mut client = TcpStream::connect(incoming.local_addr().unwrap()).await.unwrap();
            let (connection, _) = incoming.accept().await.unwrap();
            let target = MatchedSniTarget {
                rule_name: "test".into(),
                sni: "test.example".into(),
                target: target("[::1]", upstream.local_addr().unwrap().port(), 1),
            };
            let relay = tokio::spawn(async move {
                proxy_tls_passthrough(connection, &target, CancellationToken::new()).await
            });
            let (mut server, _) = upstream.accept().await.unwrap();
            client.write_all(b"query").await.unwrap();
            client.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            server.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"query");
            server.write_all(b"response").await.unwrap();
            server.shutdown().await.unwrap();
            bytes.clear();
            client.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"response");
            relay.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn test_router_without_rules() {
        let router = SniProxyRouter::new(shared_routes(vec![]));
        assert!(!router.has_sni_proxy_rules());
        assert!(router.match_target("example.com").is_none());
    }

    #[test]
    fn test_parse_sni_from_valid_client_hello() {
        let hello = build_client_hello_with_sni("App.Example.com");
        assert_eq!(parse_sni_from_client_hello(&hello).as_deref(), Some("app.example.com"));
    }

    #[test]
    fn test_parse_sni_rejects_truncated_client_hello() {
        let mut hello = build_client_hello_with_sni("app.example.com");
        hello.truncate(hello.len() - 3);
        assert_eq!(parse_sni_from_client_hello(&hello), None);
    }

    #[test]
    fn test_exact_match_wins_over_wildcard() {
        let router = SniProxyRouter::new(shared_routes(vec![
            sni_rule("wildcard", &["*.example.com"], vec![target("10.0.0.2", 443, 1)]),
            sni_rule("exact", &["api.example.com"], vec![target("10.0.0.3", 8443, 1)]),
        ]));

        let matched = router.match_target("api.example.com").unwrap();
        assert_eq!(matched.rule_name, "exact");
        assert_eq!(matched.target.address, "10.0.0.3");
        assert_eq!(matched.target.port, 8443);
    }

    #[test]
    fn test_wildcard_match_requires_a_subdomain() {
        let router = SniProxyRouter::new(shared_routes(vec![sni_rule(
            "wildcard",
            &["*.example.com"],
            vec![target("10.0.0.2", 443, 1)],
        )]));

        assert!(router.match_target("api.example.com").is_some());
        assert!(router.match_target("example.com").is_none());
    }

    #[test]
    fn test_disabled_rules_are_ignored() {
        let mut rule = sni_rule("disabled", &["api.example.com"], vec![target("10.0.0.2", 443, 1)]);
        rule.enable = false;
        let router = SniProxyRouter::new(shared_routes(vec![rule]));

        assert!(!router.has_sni_proxy_rules());
        assert!(router.match_target("api.example.com").is_none());
    }

    #[test]
    fn test_round_robin_selects_multiple_targets() {
        let router = SniProxyRouter::new(shared_routes(vec![sni_rule(
            "rr",
            &["api.example.com"],
            vec![target("10.0.0.2", 443, 1), target("10.0.0.3", 443, 1)],
        )]));

        let first = router.match_target("api.example.com").unwrap();
        let second = router.match_target("api.example.com").unwrap();

        assert_eq!(first.target.address, "10.0.0.2");
        assert_eq!(second.target.address, "10.0.0.3");
    }

    #[test]
    fn reload_preserves_selected_target_and_round_robin_position() {
        let routes = shared_routes(vec![sni_rule(
            "old",
            &["api.example.com"],
            vec![target("10.0.0.2", 443, 1), target("10.0.0.3", 443, 1)],
        )]);
        let router = SniProxyRouter::new(routes.clone());
        let selected_before_reload = router.match_target("api.example.com").unwrap();

        let replacement = sni_rule(
            "new",
            &["api.example.com"],
            vec![target("10.0.0.4", 8443, 1), target("10.0.0.5", 8443, 1)],
        );
        routes.store(Arc::new(
            crate::routes::CompiledGatewayRoutes::compile(&[replacement]).unwrap(),
        ));

        let selected_after_reload = router.match_target("api.example.com").unwrap();
        assert_eq!(selected_after_reload.rule_name, "new");
        assert_eq!(selected_after_reload.target.address, "10.0.0.5");
        assert_eq!(selected_after_reload.target.port, 8443);
        assert_eq!(selected_before_reload.rule_name, "old");
        assert_eq!(selected_before_reload.target.address, "10.0.0.2");
        assert_eq!(selected_before_reload.target.port, 443);

        routes.store(Arc::new(crate::routes::CompiledGatewayRoutes::default()));
        assert!(!router.has_sni_proxy_rules());
        assert!(router.match_target("api.example.com").is_none());
        assert_eq!(selected_before_reload.target.address, "10.0.0.2");
    }

    #[test]
    fn exact_rule_without_targets_does_not_fall_back_to_wildcard() {
        let router = SniProxyRouter::new(shared_routes(vec![
            sni_rule("wildcard", &["*.example.com"], vec![target("10.0.0.2", 443, 1)]),
            sni_rule("exact", &["api.example.com"], vec![]),
        ]));

        assert!(router.match_target("api.example.com").is_none());
        assert!(router.match_target("other.example.com").is_some());
    }

    #[test]
    fn test_rule_without_targets_is_not_selected() {
        let router = SniProxyRouter::new(shared_routes(vec![sni_rule(
            "empty",
            &["api.example.com"],
            vec![],
        )]));

        assert!(router.match_target("api.example.com").is_none());
    }
}
