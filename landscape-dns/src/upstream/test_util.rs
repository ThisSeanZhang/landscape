//! Shared test harness for the connection layer: the example.com. zone
//! (used by the plaintext integration tests and the TLS/QUIC upstream
//! tests) and the plaintext UDP+TCP server spawner.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::rdata::{A, SOA, TXT};
use hickory_server::proto::rr::{Name, RData, Record, RecordSet, RecordType, RrKey};
use hickory_server::server::Server;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneType};

/// Builds the example.com. authority handler: an SOA (TTL 3600, MINIMUM
/// 300) plus, with `with_content`, the `www` A record, a TXT record far
/// larger than the client's EDNS payload (forces UDP truncation) and a
/// CNAME alias to `www`.
pub(crate) fn zone_authority(
    with_content: bool,
) -> (Name, Arc<InMemoryZoneHandler<hickory_server::net::runtime::TokioRuntimeProvider>>) {
    let origin = Name::from_str("example.com.").unwrap();
    let soa = Record::from_rdata(
        origin.clone(),
        3600,
        RData::SOA(SOA::new(
            Name::from_str("ns.example.com.").unwrap(),
            Name::from_str("admin.example.com.").unwrap(),
            1,
            3600,
            600,
            86400,
            300,
        )),
    );
    let mut records = BTreeMap::new();
    records.insert(RrKey::new(origin.clone().into(), RecordType::SOA), RecordSet::from(soa));
    if with_content {
        let www_name = Name::from_str("www.example.com.").unwrap();
        let www = Record::from_rdata(www_name.clone(), 60, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        records.insert(RrKey::new(www_name.clone().into(), RecordType::A), RecordSet::from(www));

        let big_txt_name = Name::from_str("big.example.com.").unwrap();
        let big_txt = Record::from_rdata(
            big_txt_name.clone(),
            60,
            RData::TXT(TXT::new(
                "x".repeat(2000)
                    .as_bytes()
                    .chunks(255)
                    .map(|c| String::from_utf8_lossy(c).into_owned())
                    .collect(),
            )),
        );
        records.insert(
            RrKey::new(big_txt_name.clone().into(), RecordType::TXT),
            RecordSet::from(big_txt),
        );

        let alias_name = Name::from_str("alias.example.com.").unwrap();
        let alias = Record::from_rdata(
            alias_name.clone(),
            60,
            RData::CNAME(hickory_server::proto::rr::rdata::CNAME(www_name)),
        );
        records.insert(
            RrKey::new(alias_name.clone().into(), RecordType::CNAME),
            RecordSet::from(alias),
        );
    }
    let authority = Arc::new(
        InMemoryZoneHandler::<hickory_server::net::runtime::TokioRuntimeProvider>::new(
            origin.clone(),
            records,
            ZoneType::Primary,
            AxfrPolicy::Deny,
        )
        .unwrap(),
    );
    (origin, authority)
}

/// Spawns a local plaintext authoritative server on an ephemeral UDP+TCP
/// port pair. `bind_ip` must be a loopback address (Linux lo covers
/// 127.0.0.0/8, so tests can host several servers on the same port
/// number). With `with_content` the zone carries the A/TXT/CNAME records;
/// without, the zone is SOA-only, so every query answers NXDomain.
pub(crate) async fn spawn_plaintext_server(
    bind_ip: Ipv4Addr,
    with_content: bool,
) -> (u16, tokio::task::JoinHandle<()>) {
    spawn_plaintext_server_at(std::net::IpAddr::V4(bind_ip), with_content).await
}

/// Like [`spawn_plaintext_server`], but binding any IP family (the IPv6
/// transport paths need real coverage too).
pub(crate) async fn spawn_plaintext_server_at(
    bind_ip: std::net::IpAddr,
    with_content: bool,
) -> (u16, tokio::task::JoinHandle<()>) {
    let udp_socket = tokio::net::UdpSocket::bind((bind_ip, 0)).await.unwrap();
    let port = udp_socket.local_addr().unwrap().port();
    let tcp_listener = tokio::net::TcpListener::bind((bind_ip, port)).await.unwrap();

    let (origin, authority) = zone_authority(with_content);
    let mut catalog = Catalog::new();
    catalog.upsert(origin.into(), vec![authority]);

    let mut server = Server::new(catalog);
    server.register_socket(udp_socket);
    server.register_listener(tcp_listener, std::time::Duration::from_secs(5), 4096);
    let handle = tokio::spawn(async move {
        let _ = server.block_until_done().await;
    });
    (port, handle)
}

/// One scripted behaviour of [`ScriptedDnsServer`], consumed per received
/// query. UDP and TCP run on separate scripts so fan-out legs (which hit
/// both transports of a plaintext upstream concurrently) stay
/// deterministic.
#[derive(Debug, Clone)]
#[allow(dead_code)] // full harness capability; coverage for these is deferred
pub(crate) enum ScriptedAction {
    /// A normal A answer for the queried name.
    Answer,
    /// An answer carrying the TC bit.
    Truncate,
    /// An explicit error-code answer (SERVFAIL, REFUSED, ...).
    Code(ResponseCode),
    /// For one received query, first send two spoof attempts — a frame with
    /// an unmatched message id and a frame with the right id but a foreign
    /// question, each carrying an alluring answer (6.6.6.6) — and then the
    /// real answer (1.2.3.4). Exercises the client's discard loop: the
    /// spoofed frames must never satisfy the query.
    SpoofThenAnswer,
    /// Undecodable garbage bytes.
    Garbage,
    /// An answer carrying the TC bit with no records at all (the degenerate
    /// stream-phase truncation response).
    TruncateEmpty,
    /// Read the request, then never answer and never close the connection
    /// (TCP: the stream handler parks with the socket ESTABLISHED — a true
    /// half-open peer; UDP: nothing is sent).
    HoldOpen,
    /// Hold the answer for the delay, then answer normally.
    Delay(Duration),
    /// Drop the query silently (UDP: no datagram; TCP: close the stream
    /// with a FIN after reading).
    Drop,
    /// Abort the TCP stream with an RST (SO_LINGER 0).
    Reset,
}

impl ScriptedAction {
    fn next(script: &Mutex<VecDeque<ScriptedAction>>) -> ScriptedAction {
        script
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
            .unwrap_or(ScriptedAction::Answer)
    }
}

/// A plaintext UDP+TCP "upstream" whose every response is scripted: the
/// failure modes a real resolver meets on the wire (spoofed or late frames,
/// RSTs, blackholes, restarts) become reproducible. The server owns no
/// zone; every answer is synthesized from the query.
pub(crate) struct ScriptedDnsServer {
    bind_ip: std::net::IpAddr,
    port: u16,
    udp_script: Arc<Mutex<VecDeque<ScriptedAction>>>,
    tcp_script: Arc<Mutex<VecDeque<ScriptedAction>>>,
    queries: Arc<AtomicU32>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Accepted-stream handler tasks (aborted by `kill` together with the
    /// listeners).
    stream_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl ScriptedDnsServer {
    /// Spawns on an ephemeral port of `bind_ip`.
    pub(crate) async fn spawn(bind_ip: std::net::IpAddr) -> Self {
        Self::bind(
            bind_ip,
            0,
            Arc::new(Mutex::new(VecDeque::new())),
            Arc::new(Mutex::new(VecDeque::new())),
            Arc::new(AtomicU32::new(0)),
        )
        .await
        .expect("bind scripted server")
    }

    async fn bind(
        bind_ip: std::net::IpAddr,
        port: u16,
        udp_script: Arc<Mutex<VecDeque<ScriptedAction>>>,
        tcp_script: Arc<Mutex<VecDeque<ScriptedAction>>>,
        queries: Arc<AtomicU32>,
    ) -> std::io::Result<Self> {
        // SO_REUSEADDR (via socket2) so a restart can re-bind the port
        // while old connections from the previous incarnation sit in
        // TIME_WAIT. The TCP listener MUST bind the UDP socket's actual
        // (possibly ephemeral) port — binding the original `addr` (whose
        // port may be 0) would silently hand TCP a *different* ephemeral
        // port and every scripted TCP action would never run.
        let addr = std::net::SocketAddr::new(bind_ip, port);
        let udp_socket = tokio::net::UdpSocket::bind(addr).await?;
        let port = udp_socket.local_addr()?.port();
        let tcp_addr = std::net::SocketAddr::new(bind_ip, port);
        let std_tcp = {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(tcp_addr),
                socket2::Type::STREAM,
                None,
            )?;
            socket.set_reuse_address(true)?;
            socket.set_nonblocking(true)?;
            socket.bind(&tcp_addr.into())?;
            socket.listen(16)?;
            std::net::TcpListener::from(socket)
        };
        let tcp_listener = tokio::net::TcpListener::from_std(std_tcp)?;
        let stream_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> =
            Arc::new(Mutex::new(Vec::new()));

        let mut tasks = Vec::new();
        {
            let script = udp_script.clone();
            let queries = queries.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let (len, peer) = match udp_socket.recv_from(&mut buf).await {
                        Ok(x) => x,
                        Err(_) => return,
                    };
                    queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(frames) =
                        respond_scripted(&buf[..len], ScriptedAction::next(&script)).await
                    else {
                        continue;
                    };
                    for frame in frames {
                        let _ = udp_socket.send_to(&frame, peer).await;
                    }
                }
            }));
        }
        {
            let script = tcp_script.clone();
            let queries = queries.clone();
            let stream_tasks = stream_tasks.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let (mut stream, _) = match tcp_listener.accept().await {
                        Ok(x) => x,
                        Err(_) => return,
                    };
                    let script = script.clone();
                    let queries = queries.clone();
                    let stream_tasks = stream_tasks.clone();
                    // Tracked so `kill()` can abort in-flight stream
                    // handlers too (they would otherwise outlive the
                    // killed server and keep consuming its scripts).
                    let handle = tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        loop {
                            let mut len = [0u8; 2];
                            if stream.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
                            if stream.read_exact(&mut body).await.is_err() {
                                return;
                            }
                            queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let action = ScriptedAction::next(&script);
                            if matches!(action, ScriptedAction::Reset) {
                                // Abort with an RST instead of a FIN.
                                #[allow(deprecated)] // SO_LINGER ZERO is the only RST trigger
                                let _ = stream.set_linger(Some(Duration::ZERO));
                                return;
                            }
                            if matches!(action, ScriptedAction::HoldOpen) {
                                // Half-open: the peer read the request but
                                // never answers and never closes. Park this
                                // handler (the socket stays ESTABLISHED) so
                                // the client's query can only end via its
                                // own timeout.
                                std::future::pending::<()>().await;
                                return;
                            }
                            let Some(frames) = respond_scripted(&body, action).await else {
                                // Drop: close with a FIN after reading.
                                return;
                            };
                            for frame in frames {
                                let mut framed = frame.len().to_be_bytes().to_vec();
                                framed.extend_from_slice(&frame);
                                if stream.write_all(&framed).await.is_err() {
                                    return;
                                }
                            }
                        }
                    });
                    stream_tasks.lock().unwrap_or_else(|e| e.into_inner()).push(handle);
                }
            }));
        }

        Ok(Self {
            bind_ip,
            port,
            udp_script,
            tcp_script,
            queries,
            tasks,
            stream_tasks,
        })
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn push_udp(&self, action: ScriptedAction) {
        self.udp_script.lock().unwrap_or_else(|e| e.into_inner()).push_back(action);
    }

    pub(crate) fn push_tcp(&self, action: ScriptedAction) {
        self.tcp_script.lock().unwrap_or_else(|e| e.into_inner()).push_back(action);
    }

    /// Queries received on either transport.
    pub(crate) fn queries(&self) -> u32 {
        self.queries.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Kills the server (sockets are dropped by the aborted tasks, so the
    /// port becomes bindable again). In-flight stream handlers are aborted
    /// too — they would otherwise outlive the killed incarnation and keep
    /// consuming its scripts and query counter.
    pub(crate) fn kill(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        let stream_tasks = {
            let mut list = self.stream_tasks.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *list)
        };
        for task in stream_tasks {
            task.abort();
        }
    }

    /// Re-binds the exact same UDP+TCP port pair, keeping the scripts.
    /// Retries briefly: the aborted tasks' socket teardown is asynchronous.
    pub(crate) async fn restart_on_same_port(&mut self) {
        self.kill();
        for _ in 0..50 {
            match Self::bind(
                self.bind_ip,
                self.port,
                self.udp_script.clone(),
                self.tcp_script.clone(),
                self.queries.clone(),
            )
            .await
            {
                Ok(server) => {
                    self.tasks = server.tasks;
                    self.stream_tasks = server.stream_tasks;
                    return;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        panic!("failed to re-bind port {} for restart", self.port);
    }
}

/// Builds the wire frames for one received query under `action`, or `None`
/// when nothing should be sent (`Drop`; `Reset` is handled by the TCP task
/// itself, which owns the stream). Most actions yield one frame;
/// [`ScriptedAction::SpoofThenAnswer`] yields the spoofed frames followed
/// by the real answer.
async fn respond_scripted(query: &[u8], action: ScriptedAction) -> Option<Vec<Vec<u8>>> {
    let message = Message::from_vec(query).ok()?;
    match action {
        ScriptedAction::Answer => Some(vec![answer_for(
            &message,
            ResponseCode::NoError,
            false,
            message.metadata.id,
            None,
            [1, 2, 3, 4],
        )]),
        ScriptedAction::Truncate => Some(vec![answer_for(
            &message,
            ResponseCode::NoError,
            true,
            message.metadata.id,
            None,
            [1, 2, 3, 4],
        )]),
        ScriptedAction::Code(code) => {
            Some(vec![answer_for(&message, code, false, message.metadata.id, None, [1, 2, 3, 4])])
        }
        ScriptedAction::SpoofThenAnswer => {
            let spoof_ip = [6, 6, 6, 6];
            Some(vec![
                answer_for(
                    &message,
                    ResponseCode::NoError,
                    false,
                    message.metadata.id.wrapping_add(1),
                    None,
                    spoof_ip,
                ),
                answer_for(
                    &message,
                    ResponseCode::NoError,
                    false,
                    message.metadata.id,
                    Some(Query::query(
                        Name::from_str("evil.example.com.").unwrap(),
                        RecordType::TXT,
                    )),
                    spoof_ip,
                ),
                answer_for(
                    &message,
                    ResponseCode::NoError,
                    false,
                    message.metadata.id,
                    None,
                    [1, 2, 3, 4],
                ),
            ])
        }
        ScriptedAction::Garbage => Some(vec![b"\xde\xad\xbe\xef".to_vec()]),
        ScriptedAction::TruncateEmpty => {
            let mut response = Message::response(message.metadata.id, OpCode::Query);
            response.queries.clone_from(&message.queries);
            response.metadata.truncation = true;
            Some(vec![response.to_vec().unwrap()])
        }
        // TCP handles `HoldOpen` in the stream handler (the socket must
        // stay open); over UDP it degenerates to silence.
        ScriptedAction::HoldOpen => None,
        ScriptedAction::Delay(delay) => {
            tokio::time::sleep(delay).await;
            Some(vec![answer_for(
                &message,
                ResponseCode::NoError,
                false,
                message.metadata.id,
                None,
                [1, 2, 3, 4],
            )])
        }
        ScriptedAction::Drop | ScriptedAction::Reset => None,
    }
}

/// An answer echoing the query (id, question — or the `foreign` question),
/// carrying an A record for `ip` and the requested code / TC bit.
fn answer_for(
    query: &Message,
    code: ResponseCode,
    truncate: bool,
    id: u16,
    foreign_question: Option<hickory_proto::op::Query>,
    ip: [u8; 4],
) -> Vec<u8> {
    let mut response = Message::response(id, OpCode::Query);
    match foreign_question {
        Some(q) => response.queries.push(q),
        None => response.queries.clone_from(&query.queries),
    }
    response.metadata.response_code = code;
    response.metadata.truncation = truncate;
    let name = query.queries.first().map(|q| q.name().clone()).unwrap_or_else(Name::root);
    response.answers.push(Record::from_rdata(
        name,
        60,
        RData::A(A(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))),
    ));
    response.to_vec().unwrap()
}
