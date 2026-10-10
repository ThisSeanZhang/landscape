//! Length-prefixed stream transport core (RFC 1035 §4.2.2): one persistent
//! ordered stream carrying two-byte-framed DNS messages with pipelined
//! requests. Requests are matched to responses by rewriting the 16-bit
//! message ID: the caller's ID is swapped for a per-connection sequential one
//! and restored on the way back. Sequential IDs are fine because off-path
//! spoofing of a stream is not a realistic threat. Liveness is a direct fact:
//! the reader task flags the connection closed and fails every pending
//! exchange the moment it sees EOF or a hard I/O error.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::oneshot;

use hickory_proto::ProtoError;
use hickory_proto::op::{DnsResponse, Message};
use hickory_resolver::net::NetError;

use crate::connection::provider::set_socket_mark;
use crate::exp_conn_pool::allowance::TimeAllowance;
use crate::exp_conn_pool::transport::{DialParams, WireQuery};

pub(crate) struct StreamConnection<R, W> {
    writer: Arc<tokio::sync::Mutex<W>>,
    state: Arc<ReaderState>,
    _reader: std::marker::PhantomData<fn() -> R>,
}

const PENDING_SHARDS: usize = 16;

type PendingShard = Mutex<HashMap<u16, oneshot::Sender<Message>>>;

struct ReaderState {
    pending: [PendingShard; PENDING_SHARDS],
    closed: AtomicBool,
    next_id: AtomicU16,
}

impl ReaderState {
    fn new() -> Self {
        Self {
            pending: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            closed: AtomicBool::new(false),
            next_id: AtomicU16::new(0),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn shard(&self, id: u16) -> &PendingShard {
        &self.pending[(id as usize) & (PENDING_SHARDS - 1)]
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for shard in &self.pending {
            shard.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
    }

    fn register(&self) -> (u16, oneshot::Receiver<Message>) {
        let (tx, rx) = oneshot::channel();
        loop {
            // Wrapping fetch_add: IDs cycle through the 16-bit space,
            // skipping outstanding ones.
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let mut shard = self.shard(id).lock().unwrap_or_else(|e| e.into_inner());
            if let std::collections::hash_map::Entry::Vacant(entry) = shard.entry(id) {
                entry.insert(tx);
                return (id, rx);
            }
        }
    }

    fn unregister(&self, id: u16) {
        self.shard(id).lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    }

    fn pending_count(&self) -> usize {
        self.pending.iter().map(|shard| shard.lock().unwrap_or_else(|e| e.into_inner()).len()).sum()
    }
}

struct PendingGuard {
    state: Arc<ReaderState>,
    id: u16,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.state.unregister(self.id);
    }
}

impl<R, W> StreamConnection<R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    pub(crate) fn from_halves(reader: R, writer: W) -> Self {
        let state = Arc::new(ReaderState::new());
        tokio::spawn(read_loop(state.clone(), reader));
        Self {
            writer: Arc::new(tokio::sync::Mutex::new(writer)),
            state,
            _reader: std::marker::PhantomData,
        }
    }
}

impl<R, W> std::fmt::Debug for StreamConnection<R, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamConnection")
            .field("closed", &self.state.is_closed())
            .field("pending", &self.state.pending_count())
            .finish()
    }
}

impl<R, W> StreamConnection<R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    pub(crate) async fn query(&self, query: WireQuery) -> Result<DnsResponse, NetError> {
        let writer = self.writer.clone();
        let state = self.state.clone();
        let original_id = query.id();
        let wire = query.wire;

        let (id, rx) = state.register();
        let _guard = PendingGuard { state: state.clone(), id };
        let len = u16::try_from(wire.len()).map_err(|_| {
            NetError::from(ProtoError::Msg("request exceeds stream frame limit".into()))
        })?;
        let mut frame = Vec::with_capacity(wire.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&wire[2..]);

        {
            let mut writer = writer.lock().await;
            if let Err(e) = writer.write_all(&frame).await {
                state.close();
                return Err(NetError::from(e));
            }
        }

        match rx.await {
            Ok(mut message) => {
                message.metadata.id = original_id;
                DnsResponse::from_message(message).map_err(NetError::from)
            }
            Err(_) => Err(NetError::from(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "upstream closed the connection",
            ))),
        }
        // `guard` drops here: the ID frees even if the caller cancels at the
        // allowance.
    }

    pub(crate) fn is_alive(&self) -> bool {
        !self.state.is_closed()
    }

    pub(crate) fn close(&self) {
        self.state.close();
        // Shutdown cannot block a sync method; a short-lived task sends the
        // FIN now instead of at last-reference drop.
        let writer = self.writer.clone();
        tokio::spawn(async move {
            let mut writer = writer.lock().await;
            let _ = writer.shutdown().await;
        });
    }
}

pub(crate) async fn connect_tcp(
    addr: SocketAddr,
    dial: DialParams,
    allowance: TimeAllowance,
) -> Result<StreamConnection<OwnedReadHalf, OwnedWriteHalf>, NetError> {
    let stream = connect_marked_tcp(addr, dial, allowance).await?;
    let (reader, writer) = stream.into_split();
    Ok(StreamConnection::from_halves(reader, writer))
}

pub(crate) async fn connect_marked_tcp(
    addr: SocketAddr,
    dial: DialParams,
    allowance: TimeAllowance,
) -> Result<TokioTcpStream, NetError> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(NetError::from)?;
    if let Some(bind) = dial.bind_for(addr) {
        socket.bind(bind).map_err(NetError::from)?;
    }
    socket.set_nodelay(true).map_err(NetError::from)?;
    set_socket_mark(socket.as_raw_fd(), dial.mark_value).map_err(NetError::from)?;

    Ok(allowance.complete_within(socket.connect(addr)).await??)
}

async fn read_loop<R: AsyncRead + Unpin>(state: Arc<ReaderState>, mut reader: R) {
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(frame) => frame,
            Err(_) => break,
        };
        // Frames stay length-aligned, so skip a malformed message and keep
        // serving.
        let Ok(message) = Message::from_vec(&frame) else { continue };
        if let Some(sender) = state
            .shard(message.metadata.id)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&message.metadata.id)
        {
            let _ = sender.send(message);
        }
        // Unknown IDs are late answers to cancelled queries: drop them.
    }
    state.close();
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, Query};
    use hickory_proto::rr::{Name, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::DialParams;
    use crate::exp_conn_pool::allowance::TimeAllowance;
    use crate::exp_conn_pool::transport::wire_query;

    fn localhost_dial() -> DialParams {
        DialParams { mark_value: 0, bind_addr4: None, bind_addr6: None }
    }

    fn query(name: &str) -> DnsRequest {
        let query = Query::query(Name::parse(name, None).unwrap(), RecordType::A);
        DnsRequest::from_query(query, DnsRequestOptions::default())
    }

    async fn spawn_echo_upstream(
        listener: TcpListener,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { break };
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
                        stream.write_all(&(response.len() as u16).to_be_bytes()).await.unwrap();
                        stream.write_all(&response).await.unwrap();
                    }
                });
            }
        });
        (addr, task)
    }

    #[tokio::test]
    async fn round_trip_and_id_restore() {
        let (addr, _task) =
            spawn_echo_upstream(TcpListener::bind("127.0.0.1:0").await.unwrap()).await;
        let conn =
            super::connect_tcp(addr, localhost_dial(), TimeAllowance::new(Duration::from_secs(2)))
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
    async fn pipelined_queries_keep_ids_apart() {
        let (addr, _task) =
            spawn_echo_upstream(TcpListener::bind("127.0.0.1:0").await.unwrap()).await;
        let conn =
            super::connect_tcp(addr, localhost_dial(), TimeAllowance::new(Duration::from_secs(2)))
                .await
                .unwrap();

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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut buf).await.unwrap();
            drop(stream);
        });

        let conn =
            super::connect_tcp(addr, localhost_dial(), TimeAllowance::new(Duration::from_secs(2)))
                .await
                .unwrap();
        let error = conn.query(wire_query(query("example.com."))).await.unwrap_err();
        assert!(error.is_connection_closed());
        assert!(!conn.is_alive());
        server.await.unwrap();
    }
}
