//! Self-managed DNS-over-QUIC (RFC 9250): one long-lived connection carrying
//! one client-initiated bidirectional stream per query (§4.2). The stream —
//! not the message ID — correlates query and response, so the wire ID is
//! always zero (§4.2.1). The client configuration mirrors the legacy dial:
//! the resolver's TLS config with the "doq" ALPN (§4.1). Liveness is read
//! from quinn's own close state (idle timeout negotiated per §4.4), so no
//! watcher task is needed.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::ProtoError;
use hickory_proto::op::{DnsResponse, Message};
use hickory_resolver::net::NetError;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{
    ClientConfig as QuinnClientConfig, Connection, Endpoint, EndpointConfig, IdleTimeout,
    TransportConfig, VarInt,
};
use rustls::ClientConfig;

use crate::connection::provider::set_socket_mark;
use crate::exp_conn_pool::allowance::TimeAllowance;
use crate::exp_conn_pool::transport::{DialParams, WireQuery};

// RFC 9250 §4.1: the ALPN token identifying DoQ.
const DOQ_ALPN: &[u8] = b"doq";

// Matches the legacy hickory endpoint configuration.
const DOQ_MAX_UDP_PAYLOAD: u16 = 0x45ac;

// RFC 9250 §4.4: clients should negotiate an idle timeout.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn doq_client_config(mut base: ClientConfig) -> ClientConfig {
    base.alpn_protocols = vec![DOQ_ALPN.to_vec()];
    base
}

// RFC 9250 §4.3.3: unidirectional and server-initiated streams are fatal
// protocol errors, so the client accepts no incoming streams. Datagrams are
// disabled to match the legacy hickory transport config.
fn doq_transport_config() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(0));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    transport.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(
        IDLE_TIMEOUT.as_millis() as u32
    ))));
    transport
}

pub(crate) async fn connect_quic(
    addr: SocketAddr,
    server_name: String,
    config: ClientConfig,
    dial: DialParams,
    allowance: TimeAllowance,
) -> Result<DoqConnection, NetError> {
    let socket = std::net::UdpSocket::bind(dial.udp_bind_addr(addr)).map_err(NetError::from)?;
    set_socket_mark(socket.as_raw_fd(), dial.mark_value).map_err(NetError::from)?;
    socket.set_nonblocking(true).map_err(NetError::from)?;

    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.max_udp_payload_size(DOQ_MAX_UDP_PAYLOAD).map_err(NetError::from)?;
    let endpoint = Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))
        .map_err(NetError::from)?;

    let mut quinn_config = QuinnClientConfig::new(Arc::new(QuicClientConfig::try_from(config)?));
    quinn_config.transport_config(Arc::new(doq_transport_config()));

    let connecting =
        endpoint.connect_with(quinn_config, addr, &server_name).map_err(NetError::from)?;
    let conn = allowance.complete_within(connecting).await??;
    Ok(DoqConnection::new(endpoint, conn))
}

pub(crate) struct DoqConnection {
    // Keeps the UDP socket and its driver alive exactly as long as the
    // connection handle.
    _endpoint: Endpoint,
    conn: Connection,
}

impl DoqConnection {
    fn new(endpoint: Endpoint, conn: Connection) -> Self {
        Self { _endpoint: endpoint, conn }
    }
}

impl std::fmt::Debug for DoqConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoqConnection")
            .field("closed", &self.conn.close_reason().is_some())
            .finish()
    }
}

impl DoqConnection {
    pub(crate) async fn query(&self, query: WireQuery) -> Result<DnsResponse, NetError> {
        let conn = self.conn.clone();
        let original_id = query.id();
        let wire = query.wire;
        // RFC 9250 §4.2.1: the stream maps query to response, so the wire
        // ID must be zero; the caller's ID is restored below.
        let len = u16::try_from(wire.len()).map_err(|_| {
            NetError::from(ProtoError::Msg("request exceeds stream frame limit".into()))
        })?;
        let mut frame = Vec::with_capacity(wire.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&wire[2..]);

        let (mut send, mut recv) = conn.open_bi().await.map_err(NetError::from)?;
        send.write_all(&frame).await.map_err(write_error)?;
        // RFC 9250 §4.2: the query must end with STREAM FIN.
        send.finish().map_err(|e| {
            NetError::from(io::Error::new(io::ErrorKind::ConnectionReset, e.to_string()))
        })?;

        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf).await.map_err(read_exact_error)?;
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        recv.read_exact(&mut body).await.map_err(read_exact_error)?;

        let mut message = Message::from_vec(&body).map_err(NetError::from)?;
        // RFC 9250 §4.3.3: a non-zero response ID is a fatal protocol error.
        if message.metadata.id != 0 {
            return Err(NetError::QuicMessageIdNot0(message.metadata.id));
        }
        message.metadata.id = original_id;
        DnsResponse::from_message(message).map_err(NetError::from)
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }

    pub(crate) fn close(&self) {
        // DOQ_NO_ERROR (RFC 9250 §4.3).
        self.conn.close(VarInt::from_u32(0), b"");
    }
}

// Connection loss keeps its `ConnectionError` identity so
// `is_connection_closed` stays truthful; stream lifetime failures surface
// as reset connections.
fn write_error(error: quinn::WriteError) -> NetError {
    match error {
        quinn::WriteError::ConnectionLost(e) => NetError::from(e),
        other => NetError::from(io::Error::new(io::ErrorKind::ConnectionReset, other.to_string())),
    }
}

// Same policy for reads, plus `UnexpectedEof` for a peer FIN mid-frame
// (RFC 9250 §4.3.3 lists it as fatal).
fn read_exact_error(error: quinn::ReadExactError) -> NetError {
    match error {
        quinn::ReadExactError::ReadError(quinn::ReadError::ConnectionLost(e)) => NetError::from(e),
        other => NetError::from(io::Error::new(io::ErrorKind::UnexpectedEof, other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_resolver::net::NetError;
    use quinn::ServerConfig;
    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ClientConfig, RootCertStore};

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

    fn test_cert() -> (rustls::ServerConfig, ClientConfig) {
        let certified = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()]).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap(),
            )
            .unwrap();
        server.alpn_protocols = vec![super::DOQ_ALPN.to_vec()];

        let mut roots = RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let client = ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (server, client)
    }

    fn quic_server(server_config: rustls::ServerConfig) -> (quinn::Endpoint, std::net::SocketAddr) {
        let server_config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap()));
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        (endpoint, addr)
    }

    // DoQ echo upstream: answers each framed request on its own stream,
    // recording the wire IDs it saw so tests can prove the §4.2.1 zeroing.
    async fn spawn_doq_echo_upstream() -> (std::net::SocketAddr, ClientConfig, Arc<Mutex<Vec<u16>>>)
    {
        let (server_config, client_config) = test_cert();
        let (endpoint, addr) = quic_server(server_config);

        let wire_ids: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let ids = wire_ids.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let ids = ids.clone();
                tokio::spawn(async move {
                    loop {
                        let Ok((mut send, mut recv)) = conn.accept_bi().await else { break };
                        let ids = ids.clone();
                        tokio::spawn(async move {
                            let mut len = [0u8; 2];
                            if recv.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                            if recv.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                            let mut message = Message::from_vec(&buf).expect("request decodes");
                            ids.lock().unwrap().push(message.metadata.id);
                            message.metadata.message_type = MessageType::Response;
                            let response = message.to_vec().unwrap();
                            let mut out = Vec::with_capacity(response.len() + 2);
                            out.extend_from_slice(&(response.len() as u16).to_be_bytes());
                            out.extend_from_slice(&response);
                            let _ = send.write_all(&out).await;
                            // RFC 9250 §4.2: FIN after the last response.
                            let _ = send.finish();
                        });
                    }
                });
            }
        });
        (addr, client_config, wire_ids)
    }

    #[tokio::test]
    async fn round_trip_over_quic() {
        let (addr, client_config, wire_ids) = spawn_doq_echo_upstream().await;
        let conn = super::connect_quic(
            addr,
            SERVER_NAME.to_string(),
            super::doq_client_config(client_config),
            localhost_dial(),
            TimeAllowance::new(Duration::from_secs(2)),
        )
        .await
        .unwrap();
        assert!(conn.is_alive());

        let request = query("example.com.");
        let id = request.metadata.id;
        let response = conn.query(wire_query(request)).await.unwrap();
        // The wire ID is zero (RFC 9250 §4.2.1) and the caller's ID is
        // restored on the way back.
        assert_eq!(*wire_ids.lock().unwrap(), vec![0u16]);
        assert_eq!(response.metadata.id, id);
        assert_eq!(response.metadata.message_type, MessageType::Response);
    }

    #[tokio::test]
    async fn concurrent_queries_share_one_connection() {
        let (addr, client_config, _wire_ids) = spawn_doq_echo_upstream().await;
        let conn = super::connect_quic(
            addr,
            SERVER_NAME.to_string(),
            super::doq_client_config(client_config),
            localhost_dial(),
            TimeAllowance::new(Duration::from_secs(2)),
        )
        .await
        .unwrap();

        // RFC 9250 §5.5.1: queries SHOULD run concurrently, one stream
        // each, without waiting for outstanding replies.
        let futures: Vec<_> = ["a.example.", "b.example.", "c.example."]
            .into_iter()
            .map(|name| {
                let request = query(name);
                let id = request.metadata.id;
                let future = conn.query(wire_query(request));
                async move { (id, future.await) }
            })
            .collect();
        for (id, result) in futures_util::future::join_all(futures).await {
            assert_eq!(result.unwrap().metadata.id, id);
        }
    }

    #[tokio::test]
    async fn peer_close_fails_pending_and_marks_dead() {
        let (server_config, client_config) = test_cert();
        let (endpoint, addr) = quic_server(server_config);
        let server = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            // Reads one full query stream, then kills the connection
            // while the client still waits for its answer.
            let (mut _send, mut recv) = conn.accept_bi().await.unwrap();
            let mut len = [0u8; 2];
            recv.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            recv.read_exact(&mut buf).await.unwrap();
            conn.close(quinn::VarInt::from_u32(0), b"");
        });

        let conn = super::connect_quic(
            addr,
            SERVER_NAME.to_string(),
            super::doq_client_config(client_config),
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
    async fn nonzero_response_id_is_rejected() {
        let (server_config, client_config) = test_cert();
        let (endpoint, addr) = quic_server(server_config);
        // The handler returns its connection handle: quinn implicitly
        // closes a connection when its last handle drops, and the stored
        // task output keeps it alive until the client has read the answer.
        let server = tokio::spawn({
            let endpoint = endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.unwrap();
                let conn = incoming.await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let mut len = [0u8; 2];
                recv.read_exact(&mut len).await.unwrap();
                let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                recv.read_exact(&mut buf).await.unwrap();
                let mut message = Message::from_vec(&buf).unwrap();
                // RFC 9250 §4.3.3 violation: answers on a non-zero ID.
                message.metadata.id = 42;
                message.metadata.message_type = MessageType::Response;
                let response = message.to_vec().unwrap();
                let mut out = Vec::with_capacity(response.len() + 2);
                out.extend_from_slice(&(response.len() as u16).to_be_bytes());
                out.extend_from_slice(&response);
                send.write_all(&out).await.unwrap();
                let _ = send.finish();
                conn
            }
        });

        let conn = super::connect_quic(
            addr,
            SERVER_NAME.to_string(),
            super::doq_client_config(client_config),
            localhost_dial(),
            TimeAllowance::new(Duration::from_secs(2)),
        )
        .await
        .unwrap();
        let error = conn.query(wire_query(query("example.com."))).await.unwrap_err();
        assert!(matches!(error, NetError::QuicMessageIdNot0(42)), "unexpected error: {error:?}");
        drop(server.await.unwrap());
        drop(endpoint);
    }

    #[tokio::test]
    async fn handshake_failure_surfaces_as_error() {
        // A silent UDP port: the initial flight never gets a reply, so the
        // allowance must turn the handshake into a timeout. The socket
        // stays alive or the OS would answer with an ICMP error.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let (_server_config, client_config) = test_cert();

        let error = super::connect_quic(
            addr,
            SERVER_NAME.to_string(),
            super::doq_client_config(client_config),
            localhost_dial(),
            TimeAllowance::new(Duration::from_millis(200)),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, NetError::Timeout));
    }
}
