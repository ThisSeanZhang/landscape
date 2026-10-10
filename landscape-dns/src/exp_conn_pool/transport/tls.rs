//! Self-managed DNS-over-TLS (RFC 7858): the shared length-prefixed framing
//! core (see [`stream`]) over a rustls `TlsStream`. The client configuration
//! mirrors the legacy dial path: derived from the resolver's TLS config with
//! SNI disabled (port 853 is DNS-dedicated) and no ALPN offered.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use hickory_resolver::net::NetError;

use crate::exp_conn_pool::allowance::TimeAllowance;
use crate::exp_conn_pool::transport::DialParams;
use crate::exp_conn_pool::transport::stream::{StreamConnection, connect_marked_tcp};

/// The framing core over a TLS stream.
pub(crate) type TlsConnection =
    StreamConnection<ReadHalf<TlsStream<TokioTcpStream>>, WriteHalf<TlsStream<TokioTcpStream>>>;

pub(crate) fn dot_client_config(base: ClientConfig) -> Arc<ClientConfig> {
    let mut config = base;
    config.enable_sni = false;
    Arc::new(config)
}

pub(crate) async fn connect_tls(
    addr: SocketAddr,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
    dial: DialParams,
    allowance: TimeAllowance,
) -> Result<TlsConnection, NetError> {
    let tcp = connect_marked_tcp(addr, dial, allowance).await?;
    let connector = TlsConnector::from(config);
    let tls = allowance.complete_within(connector.connect(server_name, tcp)).await??;
    let (reader, writer) = tokio::io::split(tls);
    Ok(StreamConnection::from_halves(reader, writer))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_resolver::net::NetError;
    use rustls::pki_types::{PrivateKeyDer, ServerName as TestServerName};
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::DialParams;
    use crate::exp_conn_pool::allowance::TimeAllowance;
    use crate::exp_conn_pool::transport::wire_query;

    const SERVER_NAME: &str = "dns.example";

    fn localhost_dial() -> DialParams {
        DialParams { mark_value: 0, bind_addr4: None, bind_addr6: None }
    }

    fn query(name: &str) -> DnsRequest {
        let query = Query::query(Name::parse(name, None).unwrap(), RecordType::A);
        DnsRequest::from_query(query, DnsRequestOptions::default())
    }

    // Explicit crypto provider: nothing installs a process-level default,
    // and tests must not depend on crate features enabled elsewhere.
    fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn test_cert() -> (rustls::ServerConfig, Arc<ClientConfig>) {
        let certified = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()]).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap(),
            )
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let client = ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (server, Arc::new(client))
    }

    async fn spawn_dot_echo_upstream() -> (std::net::SocketAddr, Arc<ClientConfig>) {
        let (server_config, client_config) = test_cert();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let Ok(mut stream) = acceptor.accept(stream).await else { continue };
                tokio::spawn(async move {
                    loop {
                        let mut len = [0u8; 2];
                        if stream.read_exact(&mut len).await.is_err() {
                            break;
                        }
                        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                        if stream.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        let mut message = Message::from_vec(&buf).expect("request decodes");
                        message.metadata.message_type = MessageType::Response;
                        let response = message.to_vec().unwrap();
                        let _ = stream.write_all(&(response.len() as u16).to_be_bytes()).await;
                        let _ = stream.write_all(&response).await;
                    }
                });
            }
        });
        (addr, client_config)
    }

    #[tokio::test]
    async fn round_trip_over_tls() {
        let (addr, client_config) = spawn_dot_echo_upstream().await;
        let conn = super::connect_tls(
            addr,
            TestServerName::try_from(SERVER_NAME.to_string()).unwrap(),
            client_config,
            localhost_dial(),
            TimeAllowance::new(Duration::from_secs(2)),
        )
        .await
        .unwrap();
        assert!(conn.is_alive());

        let request = query("example.com.");
        let id = request.metadata.id;
        let response = conn.query(wire_query(request)).await.unwrap();
        assert_eq!(response.metadata.id, id);
        assert_eq!(response.metadata.message_type, MessageType::Response);
    }

    #[tokio::test]
    async fn peer_close_over_tls_fails_pending_and_marks_dead() {
        let (server_config, client_config) = test_cert();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut buf).await.unwrap();
            drop(stream);
        });

        let conn = super::connect_tls(
            addr,
            TestServerName::try_from(SERVER_NAME.to_string()).unwrap(),
            client_config,
            localhost_dial(),
            TimeAllowance::new(Duration::from_secs(2)),
        )
        .await
        .unwrap();
        let error = conn.query(wire_query(query("example.com."))).await.unwrap_err();
        // A closed peer must surface as connection-closed so the scheduler
        // can transparently redial.
        assert!(error.is_connection_closed());
        assert!(!conn.is_alive());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_failure_surfaces_as_error() {
        // A plain-TCP listener that never answers the TLS handshake: the
        // allowance must turn it into a timeout, not a hang.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let (_server_config, client_config) = test_cert();

        let error = super::connect_tls(
            addr,
            TestServerName::try_from(SERVER_NAME.to_string()).unwrap(),
            client_config,
            localhost_dial(),
            TimeAllowance::new(Duration::from_millis(200)),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, NetError::Timeout));
    }
}
