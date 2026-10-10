//! Native transport implementations behind the pool's `DnsConnector`.
//!
//! This module implements the UDP, TCP, DoT, DoH and DoQ transports with no
//! hickory-net dependency: only `hickory-proto` (the wire codec) is used.
//! The pool logic only ever sees the [`traits::DnsConnector`] /
//! [`traits::DnsConn`] boundaries.
//!
//! Transport notes:
//! - UDP: a fresh connected socket (random source port, SO_MARK applied) per
//!   query attempt; responses are validated against the request (id +
//!   question echo) and the pool retries at the attempt level, so a
//!   blackholed upstream is not hammered with datagrams.
//! - TCP / DoT: one [`mux::MuxConn`] multiplexes all queries over a single
//!   stream (random message ids, per-request timeouts, in-flight cap). A
//!   connection that dies fails every in-flight query with a real error and
//!   every later query reports the close — the pool's retirement logic then
//!   works as designed (hickory-net conflated a dead channel with "busy").
//! - DoH: one h2 connection, one HTTP/2 stream per query (id 0, RFC 8484).
//! - DoQ: native quinn ([`quic`]).

use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{DnsRequestOptions, Edns, Message, Query, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};

use landscape_common::dns::upstream::DnsUpstreamMode;

use crate::connection::provider::MarkRuntimeProvider;
use crate::connection::upstream::native::doh::DohConnector;
use crate::connection::upstream::native::udp::UdpConnector;
use crate::connection::upstream::pool_config::PoolConfig;
use crate::connection::upstream::traits::{DnsConn, DnsConnError, DnsConnector, DnsTransport};

pub(crate) mod doh;
pub(crate) mod mux;
pub(crate) mod quic;
mod tls;
pub(crate) mod udp;

/// Transport protocol of one upstream endpoint (ip + protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndpointProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

impl EndpointProtocol {
    fn transport(self) -> DnsTransport {
        match self {
            EndpointProtocol::Udp => DnsTransport::Udp,
            EndpointProtocol::Tcp
            | EndpointProtocol::Tls
            | EndpointProtocol::Https
            | EndpointProtocol::Quic => DnsTransport::Stream,
        }
    }
}

/// Builds every connector for an upstream (one per IP, and for plaintext one
/// UDP + one TCP per IP), mirroring the old `create_resolver` topology.
///
/// `tls_config` is an injection point: production passes `None` and trusts the
/// platform verifier (falling back to the Mozilla root set when the system
/// store is empty); tests (and a future per-upstream custom-CA feature) pass
/// a prepared `rustls::ClientConfig` instead.
pub(crate) fn build_connectors(
    mode: &DnsUpstreamMode,
    ips: &[IpAddr],
    port: Option<u16>,
    provider: MarkRuntimeProvider,
    config: &PoolConfig,
    tls_config: Option<Arc<rustls::ClientConfig>>,
) -> Vec<Arc<dyn DnsConnector>> {
    let tls_config = match mode {
        DnsUpstreamMode::Plaintext => None,
        _ => {
            let config = match tls_config {
                Some(config) => config,
                None => match build_tls_config() {
                    Ok(config) => Arc::new(config),
                    Err(e) => {
                        tracing::error!(
                            "failed to build TLS client config (no CA trust store available): {e}; \
                             TLS/DoH/DoQ upstreams are disabled"
                        );
                        return vec![];
                    }
                },
            };
            Some(config)
        }
    };

    match mode {
        DnsUpstreamMode::Plaintext => {
            let port = port.unwrap_or(53);
            ips.iter()
                .flat_map(|ip| {
                    let addr = SocketAddr::new(*ip, port);
                    [
                        connector(
                            EndpointProtocol::Udp,
                            addr,
                            None,
                            None,
                            provider.clone(),
                            tls_config.clone(),
                            config,
                        ),
                        connector(
                            EndpointProtocol::Tcp,
                            addr,
                            None,
                            None,
                            provider.clone(),
                            tls_config.clone(),
                            config,
                        ),
                    ]
                })
                .collect()
        }
        DnsUpstreamMode::Tls { domain } => {
            let port = port.unwrap_or(853);
            ips.iter()
                .map(|ip| {
                    connector(
                        EndpointProtocol::Tls,
                        SocketAddr::new(*ip, port),
                        Some(domain.clone().into()),
                        None,
                        provider.clone(),
                        tls_config.clone(),
                        config,
                    )
                })
                .collect()
        }
        DnsUpstreamMode::Https { domain, http_endpoint } => {
            let port = port.unwrap_or(443);
            let path: Arc<str> = http_endpoint
                .as_ref()
                .filter(|s| !s.is_empty())
                .map(|s| s.clone().into())
                .unwrap_or_else(|| Arc::from("/dns-query"));
            ips.iter()
                .map(|ip| {
                    connector(
                        EndpointProtocol::Https,
                        SocketAddr::new(*ip, port),
                        Some(domain.clone().into()),
                        Some(path.clone()),
                        provider.clone(),
                        tls_config.clone(),
                        config,
                    )
                })
                .collect()
        }
        DnsUpstreamMode::Quic { domain } => {
            let port = port.unwrap_or(853);
            ips.iter()
                .map(|ip| {
                    connector(
                        EndpointProtocol::Quic,
                        SocketAddr::new(*ip, port),
                        Some(domain.clone().into()),
                        None,
                        provider.clone(),
                        tls_config.clone(),
                        config,
                    )
                })
                .collect()
        }
    }
}

fn connector(
    protocol: EndpointProtocol,
    addr: SocketAddr,
    server_name: Option<Arc<str>>,
    path: Option<Arc<str>>,
    provider: MarkRuntimeProvider,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    config: &PoolConfig,
) -> Arc<dyn DnsConnector> {
    // DoT does not need SNI (the port identifies the service) and sending it
    // makes the connection easier to block. Applied at build time so the
    // stored config (and the connectors sharing it) is already SNI-less.
    let tls_config = tls_config.map(|config| {
        if protocol == EndpointProtocol::Tls && config.enable_sni {
            let mut config = (*config).clone();
            config.enable_sni = false;
            Arc::new(config)
        } else {
            config
        }
    });
    match protocol {
        EndpointProtocol::Udp => Arc::new(UdpConnector {
            addr,
            provider,
            query_timeout: config.query_timeout,
        }),
        EndpointProtocol::Tcp | EndpointProtocol::Tls => Arc::new(StreamConnector {
            protocol,
            addr,
            server_name,
            tls_config,
            provider,
            query_timeout: config.query_timeout,
            connect_timeout: config.connect_timeout,
            max_active_requests: config.max_active_requests,
        }),
        EndpointProtocol::Https => Arc::new(DohConnector {
            addr,
            server_name: server_name.expect("DoH needs a server name"),
            path: path.expect("DoH needs a query path"),
            tls_config: tls_config.expect("DoH needs a TLS config"),
            provider,
            connect_timeout: config.connect_timeout,
            query_timeout: config.query_timeout,
            max_active_requests: config.max_active_requests,
        }),
        EndpointProtocol::Quic => quic::connector(addr, server_name, tls_config, provider, config),
    }
}

/// A multiplexed stream connector: dials a plaintext TCP or a DoT connection
/// and hands it to [`mux::MuxConn`].
struct StreamConnector {
    protocol: EndpointProtocol,
    addr: SocketAddr,
    server_name: Option<Arc<str>>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    provider: MarkRuntimeProvider,
    query_timeout: Duration,
    connect_timeout: Duration,
    max_active_requests: usize,
}

impl std::fmt::Debug for StreamConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamConnector")
            .field("protocol", &self.protocol)
            .field("addr", &self.addr)
            .finish()
    }
}

#[async_trait]
impl DnsConnector for StreamConnector {
    async fn connect(&self) -> Result<Arc<dyn DnsConn>, DnsConnError> {
        let conn = match self.protocol {
            EndpointProtocol::Tcp => {
                let stream = self
                    .provider
                    .connect_tcp(self.addr, Some(self.connect_timeout))
                    .await
                    .map_err(|e| DnsConnError::Io(e.to_string()))?;
                mux::MuxConn::spawn(
                    stream,
                    self.addr.ip(),
                    self.query_timeout,
                    self.max_active_requests,
                    "Tcp",
                )
            }
            EndpointProtocol::Tls => {
                let (Some(tls_config), Some(server_name)) = (&self.tls_config, &self.server_name)
                else {
                    return Err(DnsConnError::Internal("missing DoT TLS config".into()));
                };
                let stream = tls::connect_tls(
                    &self.provider,
                    self.addr,
                    server_name,
                    tls_config.clone(),
                    self.connect_timeout,
                )
                .await?;
                mux::MuxConn::spawn(
                    stream,
                    self.addr.ip(),
                    self.query_timeout,
                    self.max_active_requests,
                    "Tls",
                )
            }
            _ => unreachable!("StreamConnector only dials TCP/DoT"),
        };
        Ok(Arc::new(conn))
    }

    fn transport(&self) -> DnsTransport {
        self.protocol.transport()
    }

    fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    /// Test-only endpoint introspection (topology assertions).
    #[cfg(test)]
    fn test_endpoint(&self) -> Option<(SocketAddr, String)> {
        Some((self.addr, format!("{:?}", self.protocol)))
    }

    /// Test-only TLS config introspection (e.g. the DoT SNI pin).
    #[cfg(test)]
    fn test_tls_config(&self) -> Option<Arc<rustls::ClientConfig>> {
        self.tls_config.clone()
    }
}

/// Builds the production TLS client config. The platform verifier (system CA
/// store) is preferred; when the store is empty — e.g. minimal container
/// images without `ca-certificates` — it falls back to the Mozilla root set
/// so TLS/DoH/DoQ upstreams keep working instead of the whole rule being
/// silently skipped.
fn build_tls_config() -> Result<rustls::ClientConfig, rustls::Error> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?;
    match builder.with_platform_verifier() {
        Ok(builder) => Ok(builder.with_no_client_auth()),
        Err(e) => {
            tracing::warn!(
                "platform TLS verification unavailable ({e}); falling back to the Mozilla root set"
            );
            fallback_tls_config()
        }
    }
}

/// A `rustls::ClientConfig` trusting the Mozilla root set (bundled, no
/// platform store needed).
fn fallback_tls_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// Builds the wire message for a query, mirroring `DnsRequest::from_query`
/// (recursion desired from the options, EDNS OPT record with the requested
/// payload when EDNS is enabled). The message id is assigned by the
/// transport (random for UDP/streams, 0 for DoH/DoQ).
pub(super) fn build_message(query: &Query, options: &DnsRequestOptions) -> Message {
    let mut message = Message::query();
    message.queries.push(query.clone());
    message.metadata.recursion_desired = options.recursion_desired;
    if options.use_edns {
        message
            .edns
            .get_or_insert_with(Edns::new)
            .set_max_payload(options.edns_payload_len)
            .set_dnssec_ok(options.edns_set_dnssec_ok);
    }
    message
}

/// Mirrors the old `DnsError::from_response` semantics: explicit error codes
/// are surfaced as `Protocol`, empty NXDomain/NoError answers as `Protocol`
/// with their code preserved (the caller maps NXDomain -> NxDomain etc.) and
/// the authority-section SOA attached (RFC 2308 negative caching), and
/// anything with answers/truncation succeeds.
pub(super) fn classify_message(message: Message) -> Result<Message, DnsConnError> {
    use ResponseCode::*;
    match message.metadata.response_code {
        Refused => Err(DnsConnError::Protocol(Refused, None)),
        code @ ServFail
        | code @ FormErr
        | code @ NotImp
        | code @ YXDomain
        | code @ YXRRSet
        | code @ NXRRSet
        | code @ NotAuth
        | code @ NotZone
        | code @ BADVERS
        | code @ BADSIG
        | code @ BADKEY
        | code @ BADTIME
        | code @ BADMODE
        | code @ BADNAME
        | code @ BADALG
        | code @ BADTRUNC
        | code @ BADCOOKIE => Err(DnsConnError::Protocol(code, None)),
        code @ NXDomain | code @ NoError if !contains_answer(&message) && !message.truncation => {
            // The SOA (negative TTL) survives so negative answers can be
            // cached per RFC 2308 instead of degenerating to a bare code.
            Err(DnsConnError::Protocol(code, soa_of(&message).map(Box::new)))
        }
        _ => Ok(message),
    }
}

/// The SOA record of a message's authority section, if any.
fn soa_of(message: &Message) -> Option<Record> {
    message.authorities.iter().find(|record| matches!(record.data, RData::SOA(_))).cloned()
}

/// Does the response contain any record matching the query name and type?
/// (Port of `DnsResponse::contains_answer` for the bare `Message`.)
fn contains_answer(message: &Message) -> bool {
    for q in &message.queries {
        let found = match q.query_type() {
            RecordType::ANY => message.all_sections().any(|r| &r.name == q.name()),
            RecordType::SOA => message
                .all_sections()
                .filter(|r| r.record_type().is_soa())
                .any(|r| r.name.zone_of(q.name())),
            q_type => {
                if !message.answers.is_empty() {
                    true
                } else {
                    message
                        .all_sections()
                        .filter(|r| r.record_type() == q_type)
                        .any(|r| &r.name == q.name())
                }
            }
        };

        if found {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use super::*;

    /// An empty message with the given response code.
    fn coded_message(code: ResponseCode) -> Message {
        let mut message = Message::response(0, OpCode::Query);
        message.metadata.response_code = code;
        message
    }

    #[test]
    fn classify_explicit_error_codes_are_protocol_errors() {
        // ServFail and friends map to an explicit protocol error...
        for code in [
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::FormErr,
            ResponseCode::NotImp,
        ] {
            assert!(matches!(
                classify_message(coded_message(code)),
                Err(DnsConnError::Protocol(c, None)) if c == code
            ));
        }
        // ...and so do empty negative answers, code preserved (the caller
        // maps NXDomain/NoError to negative answers).
        assert!(matches!(
            classify_message(coded_message(ResponseCode::NXDomain)),
            Err(DnsConnError::Protocol(ResponseCode::NXDomain, _))
        ));
        assert!(matches!(
            classify_message(coded_message(ResponseCode::NoError)),
            Err(DnsConnError::Protocol(ResponseCode::NoError, _))
        ));
    }

    /// A typed SOA record for SOA-carrying negative answers.
    fn soa_test_record() -> Record {
        let soa = hickory_proto::rr::rdata::SOA::new(
            Name::from_str("example.com.").unwrap(),
            Name::from_str("ns.example.com.").unwrap(),
            1,
            1,
            1,
            1,
            300,
        );
        Record::from_rdata(Name::from_str("example.com.").unwrap(), 60, RData::SOA(soa))
    }

    #[test]
    fn classify_negative_answer_preserves_soa() {
        // An empty NXDomain with an SOA in the authority section keeps the
        // SOA (negative TTL) on the error, per RFC 2308.
        let mut message = coded_message(ResponseCode::NXDomain);
        message.authorities.push(soa_test_record());
        let err = classify_message(message).unwrap_err();
        match err {
            DnsConnError::Protocol(ResponseCode::NXDomain, Some(soa)) => {
                assert!(matches!(soa.data, RData::SOA(_)));
                assert_eq!(soa.ttl, 60);
            }
            other => panic!("expected Protocol with SOA, got {other:?}"),
        }
    }

    #[test]
    fn classify_answers_are_success_even_with_error_code() {
        // An answer-bearing response is a success regardless of the code
        // (some servers answer NXDomain with records in the answer section).
        // `contains_answer` matches the echoed query, so the message must
        // carry it, like a real response does.
        let mut message = coded_message(ResponseCode::NXDomain);
        let name = Name::from_str("example.com.").unwrap();
        message.queries.push(Query::query(name.clone(), RecordType::A));
        message.answers.push(Record::from_rdata(name, 60, RData::A(A(Ipv4Addr::new(1, 2, 3, 4)))));
        assert!(classify_message(message).is_ok());
    }

    #[test]
    fn classify_truncated_empty_response_is_success() {
        // A truncated empty response keeps the TC bit so the pool's stream
        // fallback can recover the full answer; it must not be turned into
        // a protocol error.
        let mut message = coded_message(ResponseCode::NoError);
        message.metadata.truncation = true;
        let classified = classify_message(message).unwrap();
        assert!(classified.truncation);
    }

    /// A client config for connector-topology tests (no platform store
    /// dependency).
    fn test_tls_config() -> Arc<rustls::ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        )
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    /// Dials are lazy: `build_connectors` only creates connector handles, so
    /// the topology can be asserted without any network I/O.
    #[test]
    fn build_connectors_plaintext_builds_udp_and_tcp_per_ip() {
        let provider = MarkRuntimeProvider::new(0x8000, Default::default());
        let config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
        let conns = build_connectors(
            &DnsUpstreamMode::Plaintext,
            &[v4(1, 2, 3, 4), v4(5, 6, 7, 8)],
            None,
            provider,
            &config,
            None,
        );
        assert_eq!(conns.len(), 4);
        let endpoints: Vec<_> = conns.iter().map(|c| c.test_endpoint()).collect();
        assert_eq!(
            endpoints,
            vec![
                Some((SocketAddr::new(v4(1, 2, 3, 4), 53), "Udp".to_string())),
                Some((SocketAddr::new(v4(1, 2, 3, 4), 53), "Tcp".to_string())),
                Some((SocketAddr::new(v4(5, 6, 7, 8), 53), "Udp".to_string())),
                Some((SocketAddr::new(v4(5, 6, 7, 8), 53), "Tcp".to_string())),
            ]
        );
    }

    #[test]
    fn build_connectors_plaintext_honours_port_override() {
        let provider = MarkRuntimeProvider::new(0x8000, Default::default());
        let config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
        let conns = build_connectors(
            &DnsUpstreamMode::Plaintext,
            &[v4(1, 2, 3, 4)],
            Some(5353),
            provider,
            &config,
            None,
        );
        assert_eq!(conns.len(), 2);
        for conn in &conns {
            assert_eq!(conn.test_endpoint().unwrap().0.port(), 5353);
        }
    }

    #[test]
    fn build_connectors_encrypted_builds_one_stream_per_ip() {
        for (mode, expected_port) in [
            (DnsUpstreamMode::Tls { domain: "dns.example".into() }, 853),
            (DnsUpstreamMode::Https { domain: "dns.example".into(), http_endpoint: None }, 443),
            (DnsUpstreamMode::Quic { domain: "dns.example".into() }, 853),
        ] {
            let provider = MarkRuntimeProvider::new(0x8000, Default::default());
            let config = PoolConfig::for_mode(&mode);
            let conns = build_connectors(
                &mode,
                &[v4(1, 2, 3, 4), v4(5, 6, 7, 8)],
                None,
                provider,
                &config,
                Some(test_tls_config()),
            );
            assert_eq!(conns.len(), 2);
            for conn in &conns {
                assert_eq!(conn.transport(), DnsTransport::Stream);
                assert_eq!(conn.test_endpoint().unwrap().0.port(), expected_port);
            }
        }
    }

    #[test]
    fn dot_connectors_disable_sni() {
        // DoT does not need SNI (the port identifies the service) and sending
        // it makes it easier to block: the pin lives on the stored TLS
        // config, applied at build time.
        let provider = MarkRuntimeProvider::new(0x8000, Default::default());
        let config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
        let mode = DnsUpstreamMode::Tls { domain: "dns.example".into() };
        let conns = build_connectors(
            &mode,
            &[v4(1, 2, 3, 4)],
            None,
            provider,
            &config,
            Some(test_tls_config()),
        );
        assert_eq!(conns.len(), 1);
        let tls = conns[0].test_tls_config().expect("TLS mode keeps a config");
        assert!(!tls.enable_sni);
    }

    #[test]
    fn fallback_tls_config_trusts_bundled_mozilla_roots() {
        // The webpki-root fallback must yield a usable config (used when the
        // system CA store is empty); the bundled root set is non-empty by
        // construction.
        assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty());
        assert!(fallback_tls_config().is_ok());
    }

    /// The native DoQ connector applies the pool's QUIC tuning: idle timeout
    /// aligned to `config.idle_timeout`, keep-alives on by default for DoQ
    /// and derived from the idle timeout (60s idle -> 20s, capped at the
    /// conservative 10s bound below quinn's 30s negotiated default).
    #[test]
    fn quic_connector_applies_idle_and_keep_alive_tuning() {
        let mode = DnsUpstreamMode::Quic { domain: "dns.example".into() };
        let config = PoolConfig::for_mode(&mode);
        assert!(config.keep_alive);
        let provider = MarkRuntimeProvider::new(0x8000, Default::default());
        let conns = build_connectors(
            &mode,
            &[v4(1, 2, 3, 4)],
            None,
            provider,
            &config,
            Some(test_tls_config()),
        );
        assert_eq!(conns.len(), 1);
        assert_eq!(
            conns[0].test_quic_transport(),
            Some((Duration::from_secs(60), Some(Duration::from_secs(10))))
        );
    }

    /// An explicit keep-alive override disables it again, and a custom idle
    /// timeout is applied to the connection.
    #[test]
    fn quic_connector_honours_keep_alive_override_and_idle_timeout() {
        let mode = DnsUpstreamMode::Quic { domain: "dns.example".into() };
        let mut config = PoolConfig::from_settings(
            &mode,
            &crate::connection::upstream::pool_config::PoolSettings {
                keep_alive: Some(false),
                ..Default::default()
            },
        );
        config.idle_timeout = Duration::from_secs(30);
        let provider = MarkRuntimeProvider::new(0x8000, Default::default());
        let conns = build_connectors(
            &mode,
            &[v4(1, 2, 3, 4)],
            None,
            provider,
            &config,
            Some(test_tls_config()),
        );
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].test_quic_transport(), Some((Duration::from_secs(30), None)));
    }

    /// QUIC tuning is DoQ-only: even with keep-alives enabled in the config,
    /// the non-QUIC connectors expose no QUIC transport settings (and are
    /// unaffected by them).
    #[test]
    fn non_quic_connectors_ignore_quic_tuning() {
        let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
        config.keep_alive = true;
        let provider = MarkRuntimeProvider::new(0x8000, Default::default());
        let conns = build_connectors(
            &DnsUpstreamMode::Tls { domain: "dns.example".into() },
            &[v4(1, 2, 3, 4)],
            None,
            provider,
            &config,
            Some(test_tls_config()),
        );
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].test_quic_transport(), None);
    }
}
