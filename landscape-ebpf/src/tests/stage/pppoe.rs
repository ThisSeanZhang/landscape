//! Tests for `pppoe_pnet_filter` (`BPF_PROG_TEST_RUN`) and end-to-end PPPoE
//! control-plane socket isolation over an 802.1Q VLAN veth pair.

use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::Duration;

use libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use nix::net::if_::if_nametoindex;
use socket2::Socket;

use crate::skel::pppoe_client::PppoeClientSkelBuilder;
use crate::tests::helper::net::NetNsGuard;

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_PPP_DISC: u16 = 0x8863;
const ETH_P_PPP_SES: u16 = 0x8864;

const PPPOE_CODE_DATA: u8 = 0x00;
const PPPOE_CODE_PADO: u8 = 0x07;
const PPPOE_CODE_PADI: u8 = 0x09;
const PPPOE_CODE_PADS: u8 = 0x65;
const PPPOE_CODE_PADT: u8 = 0xa7;

const PPP_PROTO_IPV4: u16 = 0x0021;
const PPP_PROTO_IPV6: u16 = 0x0057;
const PPP_PROTO_IPCP: u16 = 0x8021;
const PPP_PROTO_IPV6CP: u16 = 0x8057;
const PPP_PROTO_LCP: u16 = 0xc021;
const PPP_PROTO_PAP: u16 = 0xc023;
const PPP_PROTO_CHAP: u16 = 0xc223;

const CLIENT_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01];
const SERVER_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02];
const BROADCAST_MAC: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

fn build_eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn build_pppoe_discovery(
    dst: [u8; 6],
    src: [u8; 6],
    code: u8,
    session_id: u16,
    tags: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(6 + tags.len());
    payload.push(0x11); // ver=1, type=1
    payload.push(code);
    payload.extend_from_slice(&session_id.to_be_bytes());
    payload.extend_from_slice(&(tags.len() as u16).to_be_bytes());
    payload.extend_from_slice(tags);
    build_eth_frame(dst, src, ETH_P_PPP_DISC, &payload)
}

fn build_pppoe_session(
    dst: [u8; 6],
    src: [u8; 6],
    session_id: u16,
    ppp_proto: u16,
    ppp_payload: &[u8],
) -> Vec<u8> {
    let pppoe_len = (2 + ppp_payload.len()) as u16;
    let mut payload = Vec::with_capacity(8 + ppp_payload.len());
    payload.push(0x11); // ver=1, type=1
    payload.push(PPPOE_CODE_DATA);
    payload.extend_from_slice(&session_id.to_be_bytes());
    payload.extend_from_slice(&pppoe_len.to_be_bytes());
    payload.extend_from_slice(&ppp_proto.to_be_bytes());
    payload.extend_from_slice(ppp_payload);
    build_eth_frame(dst, src, ETH_P_PPP_SES, &payload)
}

fn run_ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().expect("spawn ip command");
    assert!(
        out.status.success(),
        "ip {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn open_test_raw_socket(ifindex: u32, bind_proto: Option<u16>) -> Socket {
    let flags = if bind_proto.is_some() {
        libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC
    } else {
        libc::SOCK_RAW | libc::SOCK_CLOEXEC
    };
    let raw_fd = unsafe { libc::socket(libc::AF_PACKET, flags, 0) };
    assert!(raw_fd >= 0, "create AF_PACKET socket failed: {}", std::io::Error::last_os_error());
    let sock = unsafe { Socket::from_raw_fd(raw_fd) };

    if let Some(proto) = bind_proto {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = ifindex as i32;
        addr.sll_protocol = proto.to_be();
        let storage = unsafe {
            let mut s = std::mem::zeroed::<socket2::SockAddrStorage>();
            std::ptr::copy_nonoverlapping(&addr, (&raw mut s).cast::<libc::sockaddr_ll>(), 1);
            s
        };
        let sockaddr = unsafe {
            socket2::SockAddr::new(storage, std::mem::size_of::<libc::sockaddr_ll>() as u32)
        };
        sock.bind(&sockaddr).expect("bind test AF_PACKET socket");
    }

    sock
}

fn send_raw_on_ifindex(sock: &Socket, ifindex: u32, frame: &[u8]) {
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_ifindex = ifindex as i32;
    addr.sll_protocol = ethertype.to_be();

    let sent = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            frame.as_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    assert_eq!(
        sent,
        frame.len() as isize,
        "sendto failed on ifindex {ifindex}: {}",
        std::io::Error::last_os_error()
    );
}

async fn recv_exact_frame(sock: &Socket, timeout: Duration) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    loop {
        let mut s = sock;
        match s.read(&mut buf) {
            Ok(len) => return buf[..len].to_vec(),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out after {timeout:?} waiting for frame on peer socket"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => panic!("recv expected frame failed: {e:?}"),
        }
    }
}

fn enable_bpf_runtime_stats() -> OwnedFd {
    let fd = unsafe { libbpf_sys::bpf_enable_stats(libbpf_sys::BPF_STATS_RUN_TIME) };
    assert!(
        fd >= 0,
        "bpf_enable_stats(BPF_STATS_RUN_TIME) failed: {}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn bpf_prog_run_cnt(prog_fd: i32) -> u64 {
    let mut info: libbpf_sys::bpf_prog_info = unsafe { std::mem::zeroed() };
    let mut info_len = std::mem::size_of::<libbpf_sys::bpf_prog_info>() as u32;
    let ret = unsafe { libbpf_sys::bpf_prog_get_info_by_fd(prog_fd, &mut info, &mut info_len) };
    assert_eq!(ret, 0, "bpf_prog_get_info_by_fd failed: {}", std::io::Error::last_os_error());
    info.run_cnt
}

fn assert_ptype_and_packet_tables(iface_name: &str, ifindex: u32) {
    let ptype = std::fs::read_to_string("/proc/thread-self/net/ptype")
        .expect("read /proc/thread-self/net/ptype");
    for line in ptype.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let proto = cols.next().unwrap_or("");
        assert!(
            proto != "ALL" && proto != "0003",
            "unexpected ETH_P_ALL entry in /proc/thread-self/net/ptype (iface {iface_name}):\n{ptype}"
        );
    }

    let packet = std::fs::read_to_string("/proc/thread-self/net/packet")
        .expect("read /proc/thread-self/net/packet");
    let mut has_disc = false;
    let mut has_ses = false;
    for line in packet.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 {
            continue;
        }
        let proto = cols[3];
        let sock_ifindex: u32 = cols[4].parse().unwrap_or(0);
        assert_ne!(
            proto, "0003",
            "unexpected ETH_P_ALL (0003) socket in /proc/thread-self/net/packet:\n{packet}"
        );
        if sock_ifindex == ifindex {
            if proto.eq_ignore_ascii_case("8863") {
                has_disc = true;
            } else if proto.eq_ignore_ascii_case("8864") {
                has_ses = true;
            }
        }
    }
    assert!(
        has_disc && has_ses,
        "expected both 8863 and 8864 AF_PACKET sockets on ifindex {ifindex} ({iface_name}):\n{packet}"
    );
}

#[test]
fn pppoe_pnet_filter_accepts_control_and_drops_session_data() {
    let builder = PppoeClientSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).expect("open pppoe_client skeleton");
    let skel = open.load().expect("load pppoe_client skeleton");
    let prog = &skel.progs.pppoe_pnet_filter;

    let run = |frame: &[u8]| -> u32 {
        // bpf_prog_test_run_skb() calls eth_type_trans() (pulling 14B ETH_HLEN)
        // and only pushes ETH_HLEN back when is_l2 == true (SCHED_CLS/SCHED_ACT).
        // Prepend a 14B dummy L2 header so SOCKET_FILTER sees skb->data at frame[0]
        // and skb->len == frame.len(), matching AF_PACKET SOCK_RAW packet_rcv().
        let mut test_in = Vec::with_capacity(14 + frame.len());
        test_in.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x63]);
        test_in.extend_from_slice(frame);
        prog.test_run(ProgramInput { data_in: Some(&test_in), ..Default::default() })
            .expect("BPF_PROG_TEST_RUN on pppoe_pnet_filter failed")
            .return_value
    };

    // Accepted PPPoE Discovery frames: PADO with tags, PADS with tags, and 20-byte tagless PADT.
    let pado = build_pppoe_discovery(
        CLIENT_MAC,
        SERVER_MAC,
        PPPOE_CODE_PADO,
        0,
        &[0x01, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x04, b'B', b'R', b'A', b'S'],
    );
    assert_eq!(run(&pado), pado.len() as u32, "PADO must be accepted");

    let pads = build_pppoe_discovery(
        CLIENT_MAC,
        SERVER_MAC,
        PPPOE_CODE_PADS,
        0x0042,
        &[0x01, 0x01, 0x00, 0x00],
    );
    assert_eq!(run(&pads), pads.len() as u32, "PADS must be accepted");

    let tagless_padt = build_pppoe_discovery(CLIENT_MAC, SERVER_MAC, PPPOE_CODE_PADT, 0x0042, &[]);
    assert_eq!(tagless_padt.len(), 20);
    assert_eq!(run(&tagless_padt), 20, "20-byte tagless PADT must be accepted");

    // Truncated PPPoE header (< 20 bytes) must be rejected.
    assert_eq!(run(&tagless_padt[..19]), 0, "truncated 19-byte PPPoE frame must be dropped");

    // Accepted PPPoE Session control frames: LCP, PAP, CHAP, IPCP, IPV6CP.
    let lcp = build_pppoe_session(
        CLIENT_MAC,
        SERVER_MAC,
        0x0042,
        PPP_PROTO_LCP,
        &[0x09, 0x01, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef],
    );
    assert_eq!(run(&lcp), lcp.len() as u32, "LCP must be accepted");

    let pap = build_pppoe_session(
        CLIENT_MAC,
        SERVER_MAC,
        0x0042,
        PPP_PROTO_PAP,
        &[0x02, 0x01, 0x00, 0x05, 0x00],
    );
    assert_eq!(run(&pap), pap.len() as u32, "PAP must be accepted");

    let chap = build_pppoe_session(
        CLIENT_MAC,
        SERVER_MAC,
        0x0042,
        PPP_PROTO_CHAP,
        &[0x03, 0x01, 0x00, 0x04],
    );
    assert_eq!(run(&chap), chap.len() as u32, "CHAP must be accepted");

    let ipcp = build_pppoe_session(
        CLIENT_MAC,
        SERVER_MAC,
        0x0042,
        PPP_PROTO_IPCP,
        &[0x01, 0x01, 0x00, 0x0a, 0x03, 0x06, 198, 51, 100, 1],
    );
    assert_eq!(run(&ipcp), ipcp.len() as u32, "IPCP must be accepted");

    let ipv6cp = build_pppoe_session(
        CLIENT_MAC,
        SERVER_MAC,
        0x0042,
        PPP_PROTO_IPV6CP,
        &[0x01, 0x01, 0x00, 0x0e, 0x01, 0x0a, 0, 1, 2, 3, 4, 5, 6, 7],
    );
    assert_eq!(run(&ipv6cp), ipv6cp.len() as u32, "IPV6CP must be accepted");

    // Rejected PPPoE Session user data frames: IPv4 (0x0021) and IPv6 (0x0057).
    let ppp_ipv4 = build_pppoe_session(CLIENT_MAC, SERVER_MAC, 0x0042, PPP_PROTO_IPV4, &[0x45; 20]);
    assert_eq!(run(&ppp_ipv4), 0, "PPPoE IPv4 data frame must be dropped");

    let ppp_ipv6 = build_pppoe_session(CLIENT_MAC, SERVER_MAC, 0x0042, PPP_PROTO_IPV6, &[0x60; 40]);
    assert_eq!(run(&ppp_ipv6), 0, "PPPoE IPv6 data frame must be dropped");

    // Rejected non-PPPoE Ethernet frames: plain IPv4 (0x0800) and ARP (0x0806).
    let plain_ipv4 = build_eth_frame(CLIENT_MAC, SERVER_MAC, ETH_P_IPV4, &[0x45; 20]);
    assert_eq!(run(&plain_ipv4), 0, "non-PPPoE IPv4 frame must be dropped");

    let arp = build_eth_frame(BROADCAST_MAC, SERVER_MAC, ETH_P_ARP, &[0x00; 28]);
    assert_eq!(run(&arp), 0, "non-PPPoE ARP frame must be dropped");
}

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn pppoe_vlan_e2e_control_path_and_zero_tx_filter_runs() {
    let ns = NetNsGuard::create("pppoe");
    let _enter = ns.enter();

    run_ip(&[
        "link",
        "add",
        "vethA",
        "address",
        "02:aa:bb:cc:dd:01",
        "type",
        "veth",
        "peer",
        "name",
        "vethB",
        "address",
        "02:aa:bb:cc:dd:02",
    ]);
    run_ip(&["link", "add", "link", "vethA", "name", "vethA.4091", "type", "vlan", "id", "4091"]);
    run_ip(&["link", "add", "link", "vethB", "name", "vethB.4091", "type", "vlan", "id", "4091"]);
    for dev in ["vethA", "vethB", "vethA.4091", "vethB.4091"] {
        run_ip(&["link", "set", dev, "up"]);
    }

    let veth_a_vlan_ifindex = if_nametoindex("vethA.4091").expect("vethA.4091 ifindex") as u32;
    let veth_b_vlan_ifindex = if_nametoindex("vethB.4091").expect("vethB.4091 ifindex") as u32;

    // Single-threaded runtime keeps the spawned PPPOE_CLIENT_RUN task inside
    // this thread's isolated network namespace.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread tokio runtime");

    rt.block_on(async move {
        // Smoke-check the public `pppoe::start` entrypoint and verify kernel
        // protocol registrations before running the instrumented filter checks.
        {
            let (pub_tx, pub_rx) =
                crate::pppoe::start(veth_a_vlan_ifindex).await.expect("pppoe::start");
            assert_ptype_and_packet_tables("vethA.4091", veth_a_vlan_ifindex);
            drop(pub_tx);
            drop(pub_rx);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Load pppoe_pnet_filter explicitly so we hold its prog fd to query
        // exact BPF `prog_info.run_cnt` deltas during RX and TX traffic bursts.
        let _stats_fd = enable_bpf_runtime_stats();
        let builder = PppoeClientSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).expect("open pppoe_client skeleton");
        let skel = open.load().expect("load pppoe_client skeleton");
        let prog_fd = skel.progs.pppoe_pnet_filter.as_fd().as_raw_fd();

        let (in_tx, mut out_rx) = crate::pppoe::start_with_filter_fd(veth_a_vlan_ifindex, prog_fd)
            .expect("start_with_filter_fd");

        assert_ptype_and_packet_tables("vethA.4091", veth_a_vlan_ifindex);

        // (a) Outbound PADI (0x8863) and LCP (0x8864) via in_tx must arrive
        // intact on vethB.4091 and must NOT echo back onto out_rx.
        let padi = build_pppoe_discovery(
            BROADCAST_MAC,
            CLIENT_MAC,
            PPPOE_CODE_PADI,
            0,
            &[0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78],
        );
        let outbound_lcp = build_pppoe_session(
            SERVER_MAC,
            CLIENT_MAC,
            0x0042,
            PPP_PROTO_LCP,
            &[0x09, 0x01, 0x00, 0x08, 0xca, 0xfe, 0xba, 0xbe],
        );
        {
            let peer_disc_rx = open_test_raw_socket(veth_b_vlan_ifindex, Some(ETH_P_PPP_DISC));
            let peer_ses_rx = open_test_raw_socket(veth_b_vlan_ifindex, Some(ETH_P_PPP_SES));

            in_tx.send(padi.clone()).await.expect("send PADI");
            in_tx.send(outbound_lcp.clone()).await.expect("send LCP");

            let got_padi = recv_exact_frame(&peer_disc_rx, Duration::from_secs(2)).await;
            let got_lcp = recv_exact_frame(&peer_ses_rx, Duration::from_secs(2)).await;
            assert_eq!(got_padi, padi, "outbound PADI arrived corrupted on vethB.4091");
            assert_eq!(got_lcp, outbound_lcp, "outbound LCP arrived corrupted on vethB.4091");
        }

        // Confirm outbound frames were NOT echoed back onto vethA.4091's out_rx.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), out_rx.recv()).await.is_err(),
            "outbound frames must not be echoed back onto out_rx"
        );

        // (b) Inbound PADO (0x8863), 20-byte tagless PADT (0x8863), and LCP
        // Echo-Request (0x8864, PPP proto 0xc021) injected from vethB.4091
        // must arrive intact on out_rx.
        let pado = build_pppoe_discovery(
            CLIENT_MAC,
            SERVER_MAC,
            PPPOE_CODE_PADO,
            0,
            &[0x01, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x04, b'A', b'C', b'-', b'1'],
        );
        let padt = build_pppoe_discovery(CLIENT_MAC, SERVER_MAC, PPPOE_CODE_PADT, 0x0042, &[]);
        assert_eq!(padt.len(), 20);
        let inbound_lcp = build_pppoe_session(
            CLIENT_MAC,
            SERVER_MAC,
            0x0042,
            PPP_PROTO_LCP,
            &[0x09, 0x02, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef],
        );

        let injector = open_test_raw_socket(veth_b_vlan_ifindex, None);
        send_raw_on_ifindex(&injector, veth_b_vlan_ifindex, &pado);
        send_raw_on_ifindex(&injector, veth_b_vlan_ifindex, &padt);
        send_raw_on_ifindex(&injector, veth_b_vlan_ifindex, &inbound_lcp);

        let mut received = Vec::with_capacity(3);
        for _ in 0..3 {
            let pkt = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
                .await
                .expect("timed out waiting for inbound control frame")
                .expect("out_rx closed unexpectedly");
            received.push(pkt);
        }
        assert!(received.contains(&pado), "missing inbound PADO in {received:?}");
        assert!(received.contains(&padt), "missing inbound 20-byte PADT in {received:?}");
        assert!(received.contains(&inbound_lcp), "missing inbound LCP Echo-Request in {received:?}");

        // (c) Inbound 1,000 ETH_P_PPP_SES IPv4 (0x0021) and IPv6 (0x0057) data
        // frames from vethB.4091 must be 100% filtered in-kernel (out_rx sees 0)
        // while incrementing pppoe_pnet_filter run_cnt (proving BPF stats work).
        let rx_ipv4 = build_pppoe_session(CLIENT_MAC, SERVER_MAC, 0x0042, PPP_PROTO_IPV4, &[0x45; 20]);
        let rx_ipv6 = build_pppoe_session(CLIENT_MAC, SERVER_MAC, 0x0042, PPP_PROTO_IPV6, &[0x60; 40]);

        let rx_runs_before = bpf_prog_run_cnt(prog_fd);
        for batch in 0..10 {
            for _ in 0..50 {
                send_raw_on_ifindex(&injector, veth_b_vlan_ifindex, &rx_ipv4);
                send_raw_on_ifindex(&injector, veth_b_vlan_ifindex, &rx_ipv6);
            }
            if batch < 9 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(150), out_rx.recv()).await.is_err(),
            "inbound PPPoE IPv4/IPv6 data frames must be filtered out"
        );
        let rx_runs_delta = bpf_prog_run_cnt(prog_fd) - rx_runs_before;
        assert!(
            rx_runs_delta >= 1000,
            "expected pppoe_pnet_filter to inspect >= 1000 inbound data frames, got {rx_runs_delta}"
        );

        // (d) Crucial TX zero-clone proof: verify 0 ETH_P_ALL registrations and
        // transmit 10,000 outbound ETH_P_PPP_SES IPv4 data frames out of vethA.4091.
        // Without ETH_P_ALL on dev->ptype_all, dev_queue_xmit_nit() never clones
        // the skb and pppoe_pnet_filter run_cnt delta MUST be exactly 0.
        assert_ptype_and_packet_tables("vethA.4091", veth_a_vlan_ifindex);

        let tx_sim = open_test_raw_socket(veth_a_vlan_ifindex, None);
        let tx_ipv4 =
            build_pppoe_session(SERVER_MAC, CLIENT_MAC, 0x0042, PPP_PROTO_IPV4, &[0x45; 20]);

        let tx_runs_before = bpf_prog_run_cnt(prog_fd);
        for _ in 0..10_000 {
            send_raw_on_ifindex(&tx_sim, veth_a_vlan_ifindex, &tx_ipv4);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), out_rx.recv()).await.is_err(),
            "outbound TX data frames must never be delivered to out_rx"
        );
        let tx_runs_delta = bpf_prog_run_cnt(prog_fd) - tx_runs_before;
        assert_eq!(
            tx_runs_delta, 0,
            "pppoe_pnet_filter must NEVER run on outbound WAN TX data frames (got {tx_runs_delta} runs for 10,000 TX frames)"
        );

        drop(in_tx);
        drop(out_rx);
    });
}
