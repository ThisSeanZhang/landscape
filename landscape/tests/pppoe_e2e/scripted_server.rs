use super::cmd::{enter_netns, resolve_iface};
use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::PointToPoint;
use landscape_common::net_proto::pppoe::{PPPoEFrame, PPPoETag};
use std::net::Ipv4Addr;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

// ── scripted PPPoE server ────────────────────────────────────────────────────

pub(super) enum ScriptedServerMode {
    /// Full successful session (PADO/PADS, LCP, PAP, IPCP with one Nak
    /// round, IPv6CP).  After establishment it keeps answering LCP echo
    /// requests until the client terminates the session; returns once the
    /// client's LCP Terminate-Request has been answered.
    Success,
    /// Same successful session, but the server disappears right after
    /// establishment (simulates server-side loss: nothing answers the
    /// client's keepalive afterwards).
    SuccessThenVanish,
    /// Rejects PAP via LCP Protocol-Reject (a fatal error for the client).
    ProtocolRejectPap,
}

pub(super) struct ScriptedServerHandle {
    established_rx: Receiver<()>,
    done_rx: Receiver<Result<(), String>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ScriptedServerHandle {
    /// Wait until the server has observed a fully established session
    /// (client acked our IPv6CP peer request).
    pub(super) fn established(&self, timeout: Duration) -> Result<(), String> {
        self.established_rx
            .recv_timeout(timeout)
            .map_err(|e| format!("session never established: {e}"))
    }

    /// Wait for the server script to finish its expected interaction.
    pub(super) fn wait(mut self) -> Result<(), String> {
        let result = self
            .done_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| format!("scripted server did not finish: {e}"))?;
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "scripted server thread panicked".to_string())?;
        }
        result
    }
}

impl Drop for ScriptedServerHandle {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) fn start_scripted_server(
    server_ns: String,
    server_iface: String,
    server_mac: MacAddr,
    mode: ScriptedServerMode,
) -> ScriptedServerHandle {
    let (established_tx, established_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result =
            run_scripted_server(&server_ns, &server_iface, server_mac, mode, established_tx);
        let _ = done_tx.send(result);
    });

    ScriptedServerHandle { established_rx, done_rx, thread: Some(thread) }
}

fn run_scripted_server(
    server_ns: &str,
    server_iface: &str,
    server_mac: MacAddr,
    mode: ScriptedServerMode,
    established_tx: Sender<()>,
) -> Result<(), String> {
    enter_netns(server_ns)?;

    let iface = resolve_iface(server_iface)?;
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(format!("socket AF_PACKET: {}", std::io::Error::last_os_error()));
    }

    // Non-blocking-ish receive so the loop can re-check its deadline.
    let tv = libc::timeval { tv_sec: 0, tv_usec: 500_000 };
    let setopt_result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if setopt_result != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("SO_RCVTIMEO: {err}"));
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_ifindex = iface.index as i32;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    let bind_result = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bind_result != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("bind AF_PACKET: {err}"));
    }

    let result = scripted_server_loop(fd, server_mac, mode, established_tx);
    unsafe { libc::close(fd) };
    result
}

fn scripted_server_loop(
    fd: i32,
    server_mac: MacAddr,
    mode: ScriptedServerMode,
    established_tx: Sender<()>,
) -> Result<(), String> {
    let mut buf = [0_u8; 2048];
    let mut client_mac: Option<MacAddr> = None;
    let mut sent_ipcp_nak = false;
    let mut sent_ipcp_peer_request = false;
    let mut sent_ipv6cp_peer_request = false;
    let mut notified_established = false;
    let session_id = 0x1234;
    let deadline = Instant::now() + Duration::from_secs(60);

    while Instant::now() < deadline {
        let len = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if len <= 0 {
            continue;
        }
        let packet = &buf[..len as usize];
        let broadcast = [0xff_u8; 6];
        if packet.len() < 20 || (packet[0..6] != server_mac.octets() && packet[0..6] != broadcast) {
            continue;
        }

        let Some(frame) = PPPoEFrame::new(&packet[14..]) else {
            continue;
        };
        let source_mac = MacAddr::from_arry(&packet[6..12]).ok_or("invalid client mac")?;
        client_mac = Some(source_mac);

        match frame.code {
            // PADI → PADO
            0x09 => {
                let mut payload = vec![];
                let mut host_uniq = None;
                for tag in PPPoETag::from_bytes(&frame.payload) {
                    if let PPPoETag::HostUniq(id) = tag {
                        host_uniq = Some(id);
                    }
                }
                payload.extend(PPPoETag::ServiceName(vec![]).decode_options());
                if let Some(id) = host_uniq {
                    payload.extend(PPPoETag::HostUniq(id).decode_options());
                }
                send_pppoe(fd, source_mac, server_mac, 0x8863, 0x07, 0, payload)?;
            }
            // PADR → PADS + our LCP config request
            0x19 => {
                let mut payload = vec![];
                for tag in PPPoETag::from_bytes(&frame.payload) {
                    if let PPPoETag::HostUniq(id) = tag {
                        payload.extend(PPPoETag::HostUniq(id).decode_options());
                    }
                }
                send_pppoe(fd, source_mac, server_mac, 0x8863, 0x65, session_id, payload)?;
                let lcp_request = ppp_lcp_request(1, 1492, 0x1020_3040);
                send_session(fd, source_mac, server_mac, session_id, lcp_request)?;
            }
            // Session data
            0x00 => {
                let Some(ppp) = PointToPoint::new(&frame.payload) else {
                    continue;
                };
                if ppp.is_lcp_config() {
                    if ppp.is_request() {
                        send_session(fd, source_mac, server_mac, session_id, ppp.gen_ack())?;
                    }
                    if ppp.is_termination() {
                        send_session(
                            fd,
                            source_mac,
                            server_mac,
                            session_id,
                            ppp.get_termination_ack(),
                        )?;
                        return Ok(());
                    }
                    if ppp.is_echo_request() {
                        send_session(
                            fd,
                            source_mac,
                            server_mac,
                            session_id,
                            ppp.gen_reply_with_magic(0x1020_3040),
                        )?;
                    }
                } else if ppp.is_pap_auth() {
                    if matches!(mode, ScriptedServerMode::ProtocolRejectPap) {
                        send_session(
                            fd,
                            source_mac,
                            server_mac,
                            session_id,
                            ppp_lcp_protocol_reject(3, 0xc023),
                        )?;
                        return Ok(());
                    }
                    send_session(fd, source_mac, server_mac, session_id, ppp_pap_ack(ppp.id))?;
                } else if ppp.is_ipcp() {
                    if ppp.is_request() {
                        if sent_ipcp_nak {
                            send_session(fd, source_mac, server_mac, session_id, ppp.gen_ack())?;
                        } else {
                            sent_ipcp_nak = true;
                            send_session(
                                fd,
                                source_mac,
                                server_mac,
                                session_id,
                                ppp_ipcp_nak(ppp.id, Ipv4Addr::new(10, 0, 0, 100)),
                            )?;
                        }
                        if !sent_ipcp_peer_request {
                            sent_ipcp_peer_request = true;
                            send_session(
                                fd,
                                source_mac,
                                server_mac,
                                session_id,
                                ppp_ipcp_request(7, Ipv4Addr::new(10, 0, 0, 1)),
                            )?;
                        }
                    }
                } else if ppp.is_ipv6cp() {
                    if ppp.is_request() {
                        send_session(fd, source_mac, server_mac, session_id, ppp.gen_ack())?;
                        if !sent_ipv6cp_peer_request {
                            sent_ipv6cp_peer_request = true;
                            send_session(
                                fd,
                                source_mac,
                                server_mac,
                                session_id,
                                ppp_ipv6cp_request(
                                    8,
                                    vec![0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x22],
                                ),
                            )?;
                        }
                    }
                    if ppp.is_ack() && !notified_established {
                        // The client acked our IPv6CP peer request: session
                        // negotiation is complete on the server side.
                        notified_established = true;
                        let _ = established_tx.send(());
                        if matches!(mode, ScriptedServerMode::SuccessThenVanish) {
                            return Ok(());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Err(format!("scripted server timed out; saw_client={}", client_mac.is_some()))
}

fn send_pppoe(
    fd: i32,
    dst: MacAddr,
    src: MacAddr,
    eth_proto: u16,
    code: u8,
    sid: u16,
    payload: Vec<u8>,
) -> Result<(), String> {
    let frame = PPPoEFrame {
        ver: 1,
        t: 1,
        code,
        sid,
        length: payload.len() as u16,
        payload,
    };
    send_eth(fd, dst, src, eth_proto, frame.convert_to_payload())
}

fn send_session(
    fd: i32,
    dst: MacAddr,
    src: MacAddr,
    sid: u16,
    payload: Vec<u8>,
) -> Result<(), String> {
    send_pppoe(fd, dst, src, 0x8864, 0, sid, payload)
}

fn send_eth(
    fd: i32,
    dst: MacAddr,
    src: MacAddr,
    eth_proto: u16,
    payload: Vec<u8>,
) -> Result<(), String> {
    let packet =
        [dst.octets().as_ref(), src.octets().as_ref(), &eth_proto.to_be_bytes(), payload.as_ref()]
            .concat();
    let sent = unsafe { libc::send(fd, packet.as_ptr() as *const libc::c_void, packet.len(), 0) };
    if sent < 0 {
        Err(format!("send raw packet: {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn ppp_lcp_request(id: u8, mru: u16, magic: u32) -> Vec<u8> {
    let mut payload = vec![1, 4];
    payload.extend(mru.to_be_bytes());
    payload.extend([3, 4, 0xc0, 0x23]);
    payload.extend([5, 6]);
    payload.extend(magic.to_be_bytes());
    ppp_payload(0xc021, 1, id, payload)
}

fn ppp_lcp_protocol_reject(id: u8, proto: u16) -> Vec<u8> {
    ppp_payload(0xc021, 8, id, proto.to_be_bytes().to_vec())
}

fn ppp_pap_ack(id: u8) -> Vec<u8> {
    ppp_payload(0xc023, 2, id, vec![2, b'O', b'K'])
}

fn ppp_ipcp_nak(id: u8, ip: Ipv4Addr) -> Vec<u8> {
    let ip = ip.octets();
    ppp_payload(0x8021, 3, id, vec![3, 6, ip[0], ip[1], ip[2], ip[3]])
}

fn ppp_ipcp_request(id: u8, ip: Ipv4Addr) -> Vec<u8> {
    let ip = ip.octets();
    ppp_payload(0x8021, 1, id, vec![3, 6, ip[0], ip[1], ip[2], ip[3]])
}

fn ppp_ipv6cp_request(id: u8, interface_id: Vec<u8>) -> Vec<u8> {
    let mut payload = vec![1, 10];
    payload.extend(interface_id);
    ppp_payload(0x8057, 1, id, payload)
}

fn ppp_payload(proto: u16, code: u8, id: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut result = vec![];
    result.extend(proto.to_be_bytes());
    result.push(code);
    result.push(id);
    result.extend((payload.len() as u16 + 4).to_be_bytes());
    result.extend(payload);
    result
}
