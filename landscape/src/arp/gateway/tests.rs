use super::*;
use etherparse::{ArpEthIpv4Packet, ArpOperation, PacketBuilder};

const WAN_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const WAN_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 10);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const GATEWAY_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 1);

#[test]
fn matches_only_an_ethernet_ipv4_reply_for_this_exchange() {
    let reply = ArpEthIpv4Packet {
        operation: ArpOperation::REPLY,
        sender_mac: GATEWAY_MAC.octets(),
        sender_ipv4: GATEWAY_IP.octets(),
        target_mac: WAN_MAC.octets(),
        target_ipv4: WAN_IP.octets(),
    };
    let build = |arp: ArpEthIpv4Packet| {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2(arp.sender_mac, arp.target_mac)
            .arp(arp.to_arp_packet())
            .write(&mut frame)
            .unwrap();
        frame
    };
    let parse = |frame: &[u8]| gateway_reply(frame, WAN_MAC, WAN_IP, GATEWAY_IP);
    let mut frame = build(reply.clone());
    assert_eq!(parse(&frame), Some(GATEWAY_MAC));
    assert_eq!(parse(&frame[..41]), None);
    frame[18] = 4; // Ethernet hardware addresses must be six bytes.
    assert_eq!(parse(&frame), None);

    for unrelated in [
        ArpEthIpv4Packet { operation: ArpOperation::REQUEST, ..reply.clone() },
        ArpEthIpv4Packet { sender_ipv4: [192, 0, 2, 2], ..reply.clone() },
        ArpEthIpv4Packet { target_ipv4: [192, 0, 2, 11], ..reply.clone() },
        ArpEthIpv4Packet { target_mac: [2, 0, 0, 0, 0, 11], ..reply.clone() },
        ArpEthIpv4Packet { sender_mac: [0; 6], ..reply.clone() },
        ArpEthIpv4Packet { sender_mac: [1, 0, 0, 0, 0, 1], ..reply },
    ] {
        assert_eq!(parse(&build(unrelated)), None);
    }
}

#[test]
#[ignore = "requires network namespace privileges, CAP_NET_RAW and iproute2"]
fn veth_resolves_gateway_mac_and_times_out_for_another_address() {
    // The namespace and both links disappear when this thread exits, including on panic.
    std::thread::spawn(|| {
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNET) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        let ip = |args: &[&str]| {
            let output = std::process::Command::new("ip").args(args).output().unwrap();
            assert!(
                output.status.success(),
                "ip {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        ip(&["link", "add", "wan0", "type", "veth", "peer", "name", "gw0"]);
        ip(&["link", "set", "wan0", "address", &WAN_MAC.to_string(), "up"]);
        ip(&["link", "set", "gw0", "address", &GATEWAY_MAC.to_string(), "up"]);
        ip(&["addr", "add", "192.0.2.1/24", "dev", "gw0"]);
        let ifindex = unsafe { libc::if_nametoindex(c"wan0".as_ptr()) };
        assert_ne!(ifindex, 0);

        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(
            async {
                let probe = |ip, wait| probe_gateway_mac(ifindex, WAN_MAC, WAN_IP, ip, wait);
                let absent = Ipv4Addr::new(192, 0, 2, 2);
                let (missing, found) = tokio::join!(
                    probe(absent, Duration::from_millis(200)),
                    probe(GATEWAY_IP, Duration::from_secs(2)),
                );
                assert_eq!(found.unwrap(), Some(GATEWAY_MAC));
                assert_eq!(missing.unwrap(), None);

                let new_mac = MacAddr(2, 0, 0, 0, 0, 99);
                ip(&["link", "set", "gw0", "address", &new_mac.to_string()]);
                assert_eq!(probe(GATEWAY_IP, Duration::from_secs(2)).await.unwrap(), Some(new_mac));

                ip(&["link", "del", "wan0"]);
                let error = probe(GATEWAY_IP, Duration::from_secs(2)).await.unwrap_err();
                assert_eq!(error.raw_os_error(), Some(libc::ENODEV));
            },
        );
    })
    .join()
    .unwrap();
}
