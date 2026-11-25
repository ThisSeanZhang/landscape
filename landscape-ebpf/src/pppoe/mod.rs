use std::{
    io::Read,
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        raw::c_void,
    },
};

use crate::skel::pppoe_client::*;
use landscape_common::concurrency::{spawn_task, task_label};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libc::{
    AF_PACKET, SO_ATTACH_BPF, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_RAW, SOL_SOCKET, socket, socklen_t,
};
use socket2::Socket;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::sync::mpsc;

pub mod pppoe_handle;

const ETH_P_PPP_DISC: u16 = 0x8863;
const ETH_P_PPP_SES: u16 = 0x8864;

fn open_bound_raw_socket(ifindex: u32, protocol: u16, prog_fd: i32) -> std::io::Result<Socket> {
    // Create with protocol = 0 so packet_create() does not register a protocol
    // hook before SO_ATTACH_BPF and bind() scope the socket to (ifindex, protocol).
    let raw_fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
    if raw_fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // Wrap immediately so any subsequent error closes the fd via Drop.
    let socket = unsafe { Socket::from_raw_fd(raw_fd) };

    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_SOCKET,
            SO_ATTACH_BPF,
            (&prog_fd as *const i32).cast::<c_void>(),
            std::mem::size_of_val(&prog_fd) as socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    bind_raw_socket(&socket, ifindex, protocol)?;
    Ok(socket)
}

fn bind_raw_socket(socket: &Socket, ifindex: u32, protocol: u16) -> std::io::Result<()> {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = AF_PACKET as u16;
    addr.sll_ifindex = ifindex as i32;
    addr.sll_protocol = protocol.to_be();

    let storage = unsafe {
        let mut s = std::mem::zeroed::<socket2::SockAddrStorage>();
        std::ptr::copy_nonoverlapping(&addr, (&raw mut s).cast::<libc::sockaddr_ll>(), 1);
        s
    };
    let sockaddr =
        unsafe { socket2::SockAddr::new(storage, std::mem::size_of::<libc::sockaddr_ll>() as u32) };

    socket.bind(&sockaddr).map_err(|e| {
        tracing::error!(
            ifindex,
            protocol = format_args!("0x{protocol:04x}"),
            "pppoe socket bind failed: {e:?}"
        );
        e
    })
}

fn frame_ethertype(frame: &[u8]) -> Option<u16> {
    (frame.len() >= 14).then(|| u16::from_be_bytes([frame[12], frame[13]]))
}

fn select_tx_fd<'a>(
    frame: &[u8],
    disc_fd: &'a AsyncFd<Socket>,
    ses_fd: &'a AsyncFd<Socket>,
) -> &'a AsyncFd<Socket> {
    if frame_ethertype(frame) == Some(ETH_P_PPP_SES) { ses_fd } else { disc_fd }
}

async fn send_raw_frame(async_fd: &AsyncFd<Socket>, data: &[u8]) -> std::io::Result<()> {
    loop {
        let mut guard = async_fd.writable().await?;
        match guard.try_io(|inner| inner.get_ref().send(data)) {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
}

enum RecvOutcome {
    Packet(Vec<u8>),
    WouldBlock,
    Error(std::io::Error),
}

fn try_recv_frame(
    recv_ready: std::io::Result<AsyncFdReadyGuard<'_, Socket>>,
    recv_buf: &mut [u8],
) -> RecvOutcome {
    let mut guard = match recv_ready {
        Ok(guard) => guard,
        Err(e) => return RecvOutcome::Error(e),
    };

    match guard.try_io(|inner| {
        let mut sock = inner.get_ref();
        sock.read(recv_buf)
    }) {
        Ok(Ok(len)) => RecvOutcome::Packet(recv_buf[..len].to_vec()),
        Ok(Err(e)) => RecvOutcome::Error(e),
        Err(_would_block) => RecvOutcome::WouldBlock,
    }
}

pub(crate) type PppoeChannel = (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>);

fn start_with_sockets(disc_socket: Socket, ses_socket: Socket) -> std::io::Result<PppoeChannel> {
    let disc_async_fd = AsyncFd::new(disc_socket).map_err(|e| {
        tracing::error!("pppoe discovery async fd init failed: {e:?}");
        e
    })?;
    let ses_async_fd = AsyncFd::new(ses_socket).map_err(|e| {
        tracing::error!("pppoe session async fd init failed: {e:?}");
        e
    })?;

    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

    spawn_task(task_label::task::PPPOE_CLIENT_RUN, async move {
        let mut recv_buf = [0u8; 2048];

        loop {
            tokio::select! {
                maybe_data = in_rx.recv() => {
                    let Some(data) = maybe_data else {
                        break;
                    };

                    let tx_fd = select_tx_fd(&data, &disc_async_fd, &ses_async_fd);
                    if let Err(e) = send_raw_frame(tx_fd, &data).await {
                        tracing::error!("pppoe socket send failed: {e:?}");
                        return;
                    }
                }
                recv_ready = disc_async_fd.readable() => {
                    match try_recv_frame(recv_ready, &mut recv_buf) {
                        RecvOutcome::Packet(packet) => {
                            if out_tx.send(packet).await.is_err() {
                                break;
                            }
                        }
                        RecvOutcome::WouldBlock => continue,
                        RecvOutcome::Error(e) => {
                            tracing::error!("pppoe discovery socket recv failed: {e:?}");
                            return;
                        }
                    }
                }
                recv_ready = ses_async_fd.readable() => {
                    match try_recv_frame(recv_ready, &mut recv_buf) {
                        RecvOutcome::Packet(packet) => {
                            if out_tx.send(packet).await.is_err() {
                                break;
                            }
                        }
                        RecvOutcome::WouldBlock => continue,
                        RecvOutcome::Error(e) => {
                            tracing::error!("pppoe session socket recv failed: {e:?}");
                            return;
                        }
                    }
                }
            }
        }
    });

    Ok((in_tx, out_rx))
}

pub(crate) fn start_with_filter_fd(index: u32, prog_fd: i32) -> std::io::Result<PppoeChannel> {
    // Bind protocol-specific AF_PACKET sockets instead of ETH_P_ALL:
    // ETH_P_ALL registers on dev->ptype_all, causing dev_queue_xmit_nit() to
    // skb_clone() and run pppoe_pnet_filter on every outgoing WAN packet.
    let disc_socket = open_bound_raw_socket(index, ETH_P_PPP_DISC, prog_fd)?;
    let ses_socket = open_bound_raw_socket(index, ETH_P_PPP_SES, prog_fd)?;
    start_with_sockets(disc_socket, ses_socket)
}

pub async fn start(
    index: u32,
) -> std::io::Result<(mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)> {
    let pppoe_builder = PppoeClientSkelBuilder::default();

    let mut open_object = MaybeUninit::uninit();
    let pppoe_open =
        crate::bpf_ctx!(pppoe_builder.open(&mut open_object), "pppoe_client open skeleton failed")
            .map_err(|e| {
                std::io::Error::other(format!("pppoe_client open skeleton failed: {e}"))
            })?;
    let pppoe_skel = crate::bpf_ctx!(pppoe_open.load(), "pppoe_client load skeleton failed")
        .map_err(|e| std::io::Error::other(format!("pppoe_client load skeleton failed: {e}")))?;

    let pppoe_pnet_filter_fd = pppoe_skel.progs.pppoe_pnet_filter.as_fd().as_raw_fd();
    start_with_filter_fd(index, pppoe_pnet_filter_fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::Duration;

    #[test]
    fn frame_ethertype_extracts_l2_protocol() {
        let mut disc = [0u8; 20];
        disc[12..14].copy_from_slice(&ETH_P_PPP_DISC.to_be_bytes());
        assert_eq!(frame_ethertype(&disc), Some(ETH_P_PPP_DISC));

        let mut ses = [0u8; 22];
        ses[12..14].copy_from_slice(&ETH_P_PPP_SES.to_be_bytes());
        assert_eq!(frame_ethertype(&ses), Some(ETH_P_PPP_SES));

        assert_eq!(frame_ethertype(&[0u8; 13]), None);
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run under unshare -Urn or root)"]
    fn open_bound_raw_socket_rejects_invalid_prog_fd() {
        let err = open_bound_raw_socket(1, ETH_P_PPP_DISC, -1)
            .expect_err("invalid BPF prog fd must fail setsockopt(SO_ATTACH_BPF)");
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN/CAP_NET_RAW (run under unshare -Urn or root)"]
    fn dual_socket_vlan_plumbing_avoids_eth_p_all_and_tx_echo() {
        struct LinkCleanup(String);
        impl Drop for LinkCleanup {
            fn drop(&mut self) {
                let _ = Command::new("ip").args(["link", "del", &self.0]).output();
            }
        }

        let run_ip = |args: &[&str]| {
            let out = Command::new("ip").args(args).output().expect("spawn ip");
            assert!(
                out.status.success(),
                "ip {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            );
        };

        let pid = std::process::id() % 10_000;
        let a = format!("pp{pid}a");
        let b = format!("pp{pid}b");
        let a_vlan = format!("{a}.4091");
        let b_vlan = format!("{b}.4091");
        let _cleanup = LinkCleanup(a.clone());

        run_ip(&[
            "link",
            "add",
            &a,
            "address",
            "02:aa:bb:cc:dd:01",
            "type",
            "veth",
            "peer",
            "name",
            &b,
            "address",
            "02:aa:bb:cc:dd:02",
        ]);
        run_ip(&["link", "add", "link", &a, "name", &a_vlan, "type", "vlan", "id", "4091"]);
        run_ip(&["link", "add", "link", &b, "name", &b_vlan, "type", "vlan", "id", "4091"]);
        for dev in [&a, &b, &a_vlan, &b_vlan] {
            run_ip(&["link", "set", dev, "up"]);
        }

        let a_idx = nix::net::if_::if_nametoindex(a_vlan.as_str()).expect("a_vlan ifindex") as u32;
        let b_idx = nix::net::if_::if_nametoindex(b_vlan.as_str()).expect("b_vlan ifindex") as u32;

        let open_plain = |ifindex: u32, proto: Option<u16>| -> Socket {
            let flags = if proto.is_some() {
                SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC
            } else {
                SOCK_RAW | SOCK_CLOEXEC
            };
            let fd = unsafe { socket(AF_PACKET, flags, 0) };
            assert!(fd >= 0, "socket failed: {}", std::io::Error::last_os_error());
            let sock = unsafe { Socket::from_raw_fd(fd) };
            if let Some(p) = proto {
                bind_raw_socket(&sock, ifindex, p).expect("bind_raw_socket");
            }
            sock
        };

        let send_on = |sock: &Socket, ifindex: u32, frame: &[u8]| {
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            addr.sll_family = AF_PACKET as u16;
            addr.sll_ifindex = ifindex as i32;
            addr.sll_protocol = u16::from_be_bytes([frame[12], frame[13]]).to_be();
            let sent = unsafe {
                libc::sendto(
                    sock.as_raw_fd(),
                    frame.as_ptr().cast::<c_void>(),
                    frame.len(),
                    0,
                    (&raw const addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_ll>() as socklen_t,
                )
            };
            assert_eq!(sent, frame.len() as isize);
        };

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let disc_sock = open_plain(a_idx, Some(ETH_P_PPP_DISC));
            let ses_sock = open_plain(a_idx, Some(ETH_P_PPP_SES));
            let (in_tx, mut out_rx) =
                start_with_sockets(disc_sock, ses_sock).expect("start_with_sockets");

            let ptype = std::fs::read_to_string("/proc/thread-self/net/ptype").unwrap();
            assert!(
                !ptype
                    .lines()
                    .skip(1)
                    .any(|l| { matches!(l.split_whitespace().next(), Some("ALL" | "0003")) }),
                "unexpected ETH_P_ALL entry in /proc/thread-self/net/ptype:\n{ptype}"
            );
            let pkt_tbl = std::fs::read_to_string("/proc/thread-self/net/packet").unwrap();
            let mut has_8863 = false;
            let mut has_8864 = false;
            for line in pkt_tbl.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 5 {
                    assert_ne!(cols[3], "0003", "unexpected ETH_P_ALL in packet table:\n{pkt_tbl}");
                    if cols[4].parse::<u32>().ok() == Some(a_idx) {
                        has_8863 |= cols[3].eq_ignore_ascii_case("8863");
                        has_8864 |= cols[3].eq_ignore_ascii_case("8864");
                    }
                }
            }
            assert!(has_8863 && has_8864, "missing 8863/8864 on {a_vlan}:\n{pkt_tbl}");

            // Outbound PADI (0x8863) and LCP (0x8864) reach peer intact without self-echo.
            let mut padi =
                vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01];
            padi.extend_from_slice(&ETH_P_PPP_DISC.to_be_bytes());
            padi.extend_from_slice(&[0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00]);

            let mut lcp =
                vec![0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01];
            lcp.extend_from_slice(&ETH_P_PPP_SES.to_be_bytes());
            lcp.extend_from_slice(&[
                0x11, 0x00, 0x00, 0x42, 0x00, 0x0a, 0xc0, 0x21, 0x09, 0x01, 0x00, 0x08, 1, 2, 3, 4,
            ]);

            {
                let peer_disc = open_plain(b_idx, Some(ETH_P_PPP_DISC));
                let peer_ses = open_plain(b_idx, Some(ETH_P_PPP_SES));
                in_tx.send(padi.clone()).await.unwrap();
                in_tx.send(lcp.clone()).await.unwrap();

                let mut got_padi = Vec::new();
                let mut got_lcp = Vec::new();
                let mut buf = [0u8; 2048];
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                while got_padi.is_empty() || got_lcp.is_empty() {
                    if got_padi.is_empty()
                        && let Ok(n) = (&peer_disc).read(&mut buf)
                    {
                        got_padi.extend_from_slice(&buf[..n]);
                    }
                    if got_lcp.is_empty()
                        && let Ok(n) = (&peer_ses).read(&mut buf)
                    {
                        got_lcp.extend_from_slice(&buf[..n]);
                    }
                    assert!(tokio::time::Instant::now() < deadline, "peer capture timed out");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert_eq!(got_padi, padi);
                assert_eq!(got_lcp, lcp);
            }
            assert!(tokio::time::timeout(Duration::from_millis(80), out_rx.recv()).await.is_err());

            // Inbound PADO, 20-byte tagless PADT, and LCP arrive on out_rx.
            let mut pado =
                vec![0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02];
            pado.extend_from_slice(&ETH_P_PPP_DISC.to_be_bytes());
            pado.extend_from_slice(&[
                0x11, 0x07, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x04,
                b'A', b'C', b'-', b'1',
            ]);

            let mut padt =
                vec![0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02];
            padt.extend_from_slice(&ETH_P_PPP_DISC.to_be_bytes());
            padt.extend_from_slice(&[0x11, 0xa7, 0x00, 0x42, 0x00, 0x00]);
            assert_eq!(padt.len(), 20);

            let mut rx_lcp =
                vec![0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02];
            rx_lcp.extend_from_slice(&ETH_P_PPP_SES.to_be_bytes());
            rx_lcp.extend_from_slice(&[
                0x11, 0x00, 0x00, 0x42, 0x00, 0x0a, 0xc0, 0x21, 0x09, 0x02, 0x00, 0x08, 5, 6, 7, 8,
            ]);

            let injector = open_plain(b_idx, None);
            send_on(&injector, b_idx, &pado);
            send_on(&injector, b_idx, &padt);
            send_on(&injector, b_idx, &rx_lcp);

            let mut received = Vec::new();
            for _ in 0..3 {
                received.push(
                    tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
                        .await
                        .unwrap()
                        .unwrap(),
                );
            }
            assert!(received.contains(&pado));
            assert!(received.contains(&padt));
            assert!(received.contains(&rx_lcp));

            // 10,000 outbound TX data frames on a_vlan produce zero TX echo on out_rx.
            let tx_sim = open_plain(a_idx, None);
            let mut tx_data =
                vec![0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01];
            tx_data.extend_from_slice(&ETH_P_PPP_SES.to_be_bytes());
            tx_data.extend_from_slice(&[0x11, 0x00, 0x00, 0x42, 0x00, 0x16, 0x00, 0x21]);
            tx_data.extend_from_slice(&[0x45; 20]);
            for _ in 0..10_000 {
                send_on(&tx_sim, a_idx, &tx_data);
            }
            assert!(tokio::time::timeout(Duration::from_millis(80), out_rx.recv()).await.is_err());

            drop(in_tx);
            drop(out_rx);
        });
    }
}
