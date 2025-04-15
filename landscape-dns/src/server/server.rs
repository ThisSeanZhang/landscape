use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::{
    collections::HashMap,
    mem::MaybeUninit,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

use super::response::LandscapeResponse;
use hickory_proto::{
    op::{Header, LowerQuery, MessageType, Query, ResponseCode},
    serialize::binary::{BinDecodable, BinDecoder},
    ProtoError,
};
use hickory_server::{
    authority::MessageRequest,
    server::{Request, RequestHandler, ResponseHandler},
};
use landscape_common::flow::PacketMatchMark;
use socket2::{Domain, MsgHdrMut, Type};
use tokio::sync::RwLock;
use tokio::{io::unix::AsyncFd, sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::server::response::ReportingResponseHandler;
use crate::socket::{RecvDnsMessage, SendDnsMessage};

pub struct DiffFlowServer<T: RequestHandler + Clone> {
    /// flow_id <-> Handler
    handlers: Arc<RwLock<HashMap<u32, T>>>,
    dispatch_rules: Arc<RwLock<HashMap<PacketMatchMark, u32>>>,
    join_set: JoinSet<Result<(), ProtoError>>,
    shutdown_token: CancellationToken,
}

/// Copied and adapted from hickory
impl<T: RequestHandler + Clone> DiffFlowServer<T> {
    pub fn new(
        handlers: Arc<RwLock<HashMap<u32, T>>>,
        dispatch_rules: Arc<RwLock<HashMap<PacketMatchMark, u32>>>,
    ) -> Self {
        Self {
            handlers,
            dispatch_rules,
            join_set: JoinSet::new(),
            shutdown_token: CancellationToken::new(),
        }
    }

    pub fn listen_on(&mut self, socket_addr: SocketAddr) {
        tracing::debug!("registering udp: {:?}", socket_addr);

        let socket2 = if socket_addr.is_ipv4() {
            socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP)).unwrap()
        } else {
            socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(socket2::Protocol::UDP)).unwrap()
        };

        let fd = socket2.as_raw_fd();
        let _ = crate::socket::set_socket_rcvmark(fd).unwrap();
        socket2.set_recv_tos(true).unwrap();
        socket2.set_nonblocking(true).unwrap();
        socket2.bind(&socket_addr.into()).unwrap();

        let async_socket = Arc::new(AsyncFd::new(socket2).unwrap());

        let (recv_msg_tx, mut recv_msg_rc) = tokio::sync::mpsc::channel::<RecvDnsMessage>(1024);
        let (send_msg_tx, mut send_msg_rc) = tokio::sync::mpsc::channel::<SendDnsMessage>(1024);

        let write_fd_clone = async_socket.clone();

        let shutdown = self.shutdown_token.clone();
        let handlers = self.handlers.clone();
        let dispatch_rules = self.dispatch_rules.clone();

        self.join_set.spawn({
            async move {
                while let Some(SendDnsMessage { message, addr }) = send_msg_rc.recv().await {
                    let mut write_socket = tokio::select! {
                        result = write_fd_clone.writable() => match result {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::debug!("writable error: {e}");
                                continue;
                            }
                        },
                        _ = shutdown.cancelled() => {
                            break;
                        },
                    };

                    match write_socket
                        .try_io(|inner| inner.get_ref().send_to(&message, &addr.into()))
                    {
                        Ok(Ok(sent)) => {
                            tracing::debug!("Sent {} bytes to {:?}", sent, addr);
                        }
                        Ok(Err(e)) => {
                            tracing::debug!("Send error: {:?}", e);
                            // 处理错误，可能需要重试或其他逻辑
                        }
                        Err(_) => {
                            // 暂时不可写，下次再尝试
                            continue;
                        }
                    }
                }
                Ok(())
            }
        });

        let shutdown = self.shutdown_token.clone();
        self.join_set.spawn({
            async move {
                let mut inner_join_set = JoinSet::new();
                tracing::info!("start recv_msg_rc");
                loop {
                    let RecvDnsMessage { message, addr, tos, .. } = tokio::select! {
                        result = recv_msg_rc.recv() => match result {
                            Some(c) => c,
                            None => {
                                break;
                            }
                        },
                        _ = shutdown.cancelled() => {
                            break;
                        },
                    };

                    tracing::info!("tos: {tos:?}, addr: {addr:?}, is_ipv4: {}", addr.is_ipv4());
                    let qos = if tos == 0 { None } else { Some(tos) };

                    let ip = match landscape_common::utils::ip::extract_real_ip(addr) {
                        std::net::IpAddr::V4(ipv4_addr) => IpAddr::V4(ipv4_addr),
                        std::net::IpAddr::V6(ipv6_addr) => IpAddr::V6(ipv6_addr),
                    };
                    let find_key = PacketMatchMark { ip, vlan_id: None, qos };
                    let mark = if let Some(mark) = dispatch_rules.read().await.get(&find_key) {
                        let mark = mark.clone();
                        // tracing::debug!("get mark: {mark:?}, using: {find_key:?}");
                        mark
                    } else {
                        // tracing::debug!("can not get mark, using: {find_key:?}");
                        0
                    };

                    if let Some(request_handler) =
                        handlers.read().await.get(&mark).map(Clone::clone)
                    {
                        let send_msg_tx_clone = send_msg_tx.clone();
                        inner_join_set.spawn(async move {
                            handle_raw_request(message, addr, request_handler, send_msg_tx_clone)
                                .await;
                        });
                    } else {
                        tracing::error!(
                            "mark: {mark:?}, can not found handler, addr: {addr:?}, \
                        Or maybe you just forgot to add the DNS rules in this flow config"
                        );
                    }

                    reap_tasks(&mut inner_join_set);
                }

                tracing::error!("handle msg spawn end");
                Ok(())
            }
        });

        let shutdown = self.shutdown_token.clone();
        self.join_set.spawn({
            async move {
                let mut buf = [MaybeUninit::<u8>::uninit(); 1500]; // 存储 UDP 数据
                let mut control_buf = [MaybeUninit::<u8>::uninit(); 512]; // 存储辅助数据
                let mut socket_addr: socket2::SockAddr = SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
                    8080,
                    0,
                    0,
                ))
                .into();

                loop {
                    let mut read_socket = tokio::select! {
                        result = async_socket.readable() => match result {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::debug!("writable error: {e}");
                                continue;
                            }
                        },
                        _ = shutdown.cancelled() => {
                            break;
                        },
                    };

                    let data = {
                        let mut bufs = [socket2::MaybeUninitSlice::new(&mut buf)];
                        let mut msg_hdr = MsgHdrMut::new()
                            .with_buffers(&mut bufs)
                            .with_control(&mut control_buf)
                            .with_addr(&mut socket_addr);

                        match read_socket.try_io(|inner| inner.get_ref().recvmsg(&mut msg_hdr, 0)) {
                            Ok(Ok(size)) => {
                                let mut mark = 0;
                                let mut tos = 0;
                                tracing::debug!("Received {} bytes", size);

                                // 解析辅助数据
                                let control_len = msg_hdr.control_len();
                                tracing::debug!("control_len {}", control_len);
                                // drop(msg_hdr);
                                if control_len > 0 {
                                    // let cmsg =
                                    //     unsafe { libc::CMSG_FIRSTHDR(&msg_hdr as *const _ as *const libc::msghdr) };

                                    let control_ptr = &msg_hdr as *const _ as *const libc::msghdr;
                                    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(control_ptr) };

                                    while !cmsg.is_null() {
                                        let cmsg_ref = unsafe { &*cmsg };
                                        // if cmsg_ref.cmsg_level == libc::SOL_SOCKET
                                        //     && cmsg_ref.cmsg_type == libc::SO_MARK
                                        // {
                                        //     let pktinfo_ptr =
                                        //         unsafe { libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo };
                                        //     let pktinfo = unsafe { &*pktinfo_ptr };
                                        //     tracing::debug!("Received on interface index: {}", pktinfo.ipi_ifindex);
                                        // }
                                        tracing::debug!(
                                            "cmsg_level: {}, cmsg_type: {}",
                                            cmsg_ref.cmsg_level,
                                            cmsg_ref.cmsg_type
                                        );

                                        if cmsg_ref.cmsg_level == libc::SOL_SOCKET
                                            && cmsg_ref.cmsg_type == libc::SO_MARK
                                        {
                                            let mark_ptr =
                                                unsafe { libc::CMSG_DATA(cmsg) } as *const u32;
                                            mark = unsafe { *mark_ptr };
                                            tracing::debug!("Received SO_RCVMARK: {}", mark);
                                        }

                                        if cmsg_ref.cmsg_level == libc::SOL_IP
                                            && cmsg_ref.cmsg_type == libc::IP_TOS
                                        {
                                            let tos_ptr =
                                                unsafe { libc::CMSG_DATA(cmsg) } as *const u8;
                                            tos = unsafe { *tos_ptr };
                                            println!("Received IP_TOS: {}", tos);
                                        }

                                        cmsg = unsafe { libc::CMSG_NXTHDR(control_ptr, cmsg) };
                                    }
                                }

                                drop(msg_hdr);
                                let received_data = unsafe {
                                    // 获取已初始化的数据切片
                                    let initialized_slice =
                                        std::slice::from_raw_parts(buf.as_ptr() as *const u8, size);
                                    // 创建一个Vec<u8>副本
                                    initialized_slice.to_vec()
                                };

                                RecvDnsMessage {
                                    message: received_data,
                                    addr: socket_addr.as_socket().unwrap(),
                                    mark,
                                    tos,
                                }
                            }
                            Ok(Err(e)) => {
                                tracing::debug!("try io error: {e:?}");
                                break;
                            }
                            Err(_) => continue,
                        }
                    };
                    // tracing::info!("data: {data:?}");
                    match recv_msg_tx.try_send(data) {
                        Ok(_) => {
                            tracing::debug!("Message enqueued");
                            // 后续逻辑
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!("Channel full, dropping message");
                            // 可以选择稍后重试或丢弃消息
                        }
                        Err(e) => {
                            tracing::error!("Send error: {:?}", e);
                            break;
                        }
                    }
                }

                if shutdown.is_cancelled() {
                    Ok(())
                } else {
                    // TODO: let's consider capturing all the initial configuration details so that the socket could be recreated...
                    Err(ProtoError::from("unexpected close of UDP socket"))
                }
            }
        });
    }

    pub async fn block_until_done(&mut self) -> Result<(), ProtoError> {
        block_until_done(&mut self.join_set).await
    }

    pub async fn shutdown_gracefully(&mut self) -> Result<(), ProtoError> {
        self.shutdown_token.cancel();

        block_until_done(&mut self.join_set).await
    }
}

async fn block_until_done(
    join_set: &mut JoinSet<Result<(), ProtoError>>,
) -> Result<(), ProtoError> {
    if join_set.is_empty() {
        tracing::warn!("block_until_done called with no pending tasks");
        return Ok(());
    }

    // Now wait for all of the tasks to complete.
    let mut out = Ok(());
    while let Some(join_result) = join_set.join_next().await {
        match join_result {
            Ok(result) => {
                match result {
                    Ok(_) => (),
                    Err(e) => {
                        // Save the last error.
                        out = Err(e);
                    }
                }
            }
            Err(e) => return Err(ProtoError::from(format!("Internal error in spawn: {e}"))),
        }
    }
    out
}

fn reap_tasks(join_set: &mut JoinSet<()>) {
    use futures_util::FutureExt;
    while FutureExt::now_or_never(join_set.join_next()).flatten().is_some() {}
}

pub(crate) async fn handle_raw_request<T: RequestHandler>(
    message: Vec<u8>,
    dst_addr: SocketAddr,
    request_handler: T,
    response_stream: mpsc::Sender<SendDnsMessage>,
) {
    let response_handler = LandscapeResponse::new(dst_addr, response_stream);

    handle_request(&message, dst_addr, request_handler, response_handler).await;
}

pub(crate) async fn handle_request<R: ResponseHandler, T: RequestHandler>(
    // TODO: allow Message here...
    message_bytes: &[u8],
    src_addr: SocketAddr,
    request_handler: T,
    response_handler: R,
) {
    let mut decoder = BinDecoder::new(message_bytes);

    let protocol = hickory_proto::xfer::Protocol::Udp;
    // method to handle the request
    let inner_handle_request = |message: MessageRequest, response_handler: R| async move {
        if message.message_type() == MessageType::Response {
            // Don't process response messages to avoid DoS attacks from reflection.
            return;
        }

        let id = message.id();
        let qflags = message.header().flags();
        let qop_code = message.op_code();
        let message_type = message.message_type();
        let is_dnssec = message.edns().is_some_and(|edns| edns.flags().dnssec_ok);

        let request = Request::new(message, src_addr, protocol);

        tracing::debug!(
            "request:{id} src:{proto}://{addr}#{port} type:{message_type} dnssec:{is_dnssec} {op} qflags:{qflags}",
            id = id,
            proto = protocol,
            addr = src_addr.ip(),
            port = src_addr.port(),
            message_type = message_type,
            is_dnssec = is_dnssec,
            op = qop_code,
            qflags = qflags
        );
        for query in request.queries().iter() {
            tracing::debug!(
                "query:{query}:{qtype}:{class}",
                query = query.name(),
                qtype = query.query_type(),
                class = query.query_class()
            );
        }

        // The reporter will handle making sure to log the result of the request
        let queries = request.queries().to_vec();
        let reporter = ReportingResponseHandler {
            request_header: *request.header(),
            queries,
            protocol,
            src_addr,
            handler: response_handler,
        };

        request_handler.handle_request(&request, reporter).await;
    };

    // method to return an error to the client
    let error_response_handler = |protocol: hickory_proto::xfer::Protocol,
                                  src_addr: SocketAddr,
                                  header: Header,
                                  _query: LowerQuery,
                                  response_code: ResponseCode,
                                  error: Box<ProtoError>,
                                  _response_handler: R| async move {
        // debug for more info on why the message parsing failed
        tracing::debug!(
            "request:{id} src:{proto}://{addr}#{port} type:{message_type} {op}:{response_code}:{error}",
            id = header.id(),
            proto = protocol,
            addr = src_addr.ip(),
            port = src_addr.port(),
            message_type = header.message_type(),
            op = header.op_code(),
            response_code = response_code,
            error = error,
        );

        // The reporter will handle making sure to log the result of the request
        // let mut reporter = ReportingResponseHandler {
        //     request_header: header,
        //     queries: vec![query],
        //     protocol,
        //     src_addr,
        //     handler: response_handler,
        // };

        // let mut decoder = BinDecoder::new(b"");
        // let queries = Queries::read(&mut decoder, 0);
        // let response = MessageResponseBuilder::new(&queries);
        // let result = reporter.send_response(response.error_msg(&header, response_code)).await;

        // if let Err(e) = result {
        //     tracing::warn!("failed to return FormError to client: {}", e);
        // }
    };

    // Attempt to decode the message
    match MessageRequest::read(&mut decoder) {
        Ok(message) => {
            inner_handle_request(message, response_handler).await;
        }
        Err(ProtoError { kind, .. }) if kind.as_form_error().is_some() => {
            // We failed to parse the request due to some issue in the message, but the header is available, so we can respond
            let (header, error) = kind
                .into_form_error()
                .expect("as form_error already confirmed this is a FormError");
            let query = LowerQuery::query(Query::default());

            error_response_handler(
                protocol,
                src_addr,
                header,
                query,
                ResponseCode::FormErr,
                error,
                response_handler,
            )
            .await;
        }
        Err(error) => tracing::info!(
            "request:Failed src:{proto}://{addr}#{port} error:{error}",
            proto = protocol,
            addr = src_addr.ip(),
            port = src_addr.port(),
        ),
    }
}
