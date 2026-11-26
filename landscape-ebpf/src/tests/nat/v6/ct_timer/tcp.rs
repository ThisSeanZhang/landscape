use std::os::fd::AsFd;

use etherparse::{PacketBuilder, TcpHeader};
use libbpf_sys::{XDP_DROP, XDP_PASS};

use super::*;
use crate::skel::xdp_nat6::{XdpNat6Skel, XdpNat6SkelBuilder};

const LAN: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1);
const WAN: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
const PEER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2);
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
const WAIT_TCP_CLOSE: u64 = 41;
const TC_ACT_UNSPEC: i32 = -1;
const TC_ACT_SHOT: i32 = 2;

// Schedule real timers well beyond the test. tick_key drives each callback synchronously.
const TICK_MS: u32 = 60_000;

struct TcpFlow<'a, 'obj> {
    tc: &'a TestNat6V3Skel<'obj>,
    xdp: &'a XdpNat6Skel<'obj>,
    key: Nat6TimerKey,
}

fn with_tcp_flow(test: impl FnOnce(TcpFlow<'_, '_>)) {
    let root = isolated_pin_root("nat6-tcp-aging");
    let prefix = crate::stages::nat6::wan_ro_prefix6(Some(WAN));
    let mut tc_obj = MaybeUninit::uninit();
    let mut builder = TestNat6V3SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&root).unwrap();
    let mut tc = builder.open(&mut tc_obj).unwrap();
    let ro = tc.maps.rodata_data.as_deref_mut().unwrap();
    ro.wan_ro_prefix6.b = prefix;
    ro.REPORT_INTERVAL = u64::from(TICK_MS) * 1_000_000;
    let tc = tc.load().unwrap();

    let mut xdp_obj = MaybeUninit::uninit();
    let mut builder = XdpNat6SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&root).unwrap();
    let mut xdp = builder.open(&mut xdp_obj).unwrap();
    xdp.maps.nat6_mapping_map.reuse_fd(tc.maps.nat6_mapping_map.as_fd()).unwrap();
    xdp.maps.nat6_timer_map.reuse_fd(tc.maps.nat6_timer_map.as_fd()).unwrap();
    let ro = xdp.maps.rodata_data.as_deref_mut().unwrap();
    ro.wan_ro_prefix6.b = prefix;
    ro.REPORT_INTERVAL = u64::from(TICK_MS) * 1_000_000;
    let xdp = xdp.load().unwrap();
    let key = Nat6TimerKey {
        local: Nat6MappingKey {
            client_suffix: LAN.octets()[8..].try_into().unwrap(),
            client_port: 12345u16.to_be(),
            l4_protocol: 6,
            ..Default::default()
        },
        remote_port: 443u16.to_be(),
        remote_addr: PEER.octets(),
        ..Default::default()
    };
    test(TcpFlow { tc: &tc, xdp: &xdp, key });
}

fn tcp_packet(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut header = TcpHeader::new(sport, dport, 1, 4096);
    header.syn = flags & SYN != 0;
    header.fin = flags & FIN != 0;
    header.rst = flags & RST != 0;
    header.ack = flags & ACK != 0;
    let mut frame = Vec::new();
    PacketBuilder::ethernet2([2; 6], [4; 6])
        .ipv6(src.octets(), dst.octets(), 64)
        .tcp_header(header)
        .write(&mut frame, &[])
        .unwrap();
    frame
}

impl TcpFlow<'_, '_> {
    fn tc_egress(&self, flags: u8) -> i32 {
        let frame = tcp_packet(LAN, PEER, 12345, 443, flags);
        self.tc
            .progs
            .handle_ipv6_egress
            .test_run(ProgramInput { data_in: Some(&frame), ..Default::default() })
            .unwrap()
            .return_value as i32
    }

    fn xdp_ingress(&self, flags: u8) -> u32 {
        let frame = tcp_packet(PEER, WAN, 443, 12345, flags);
        self.xdp
            .progs
            .ingress_nat_v6
            .test_run(ProgramInput { data_in: Some(&frame), ..Default::default() })
            .unwrap()
            .return_value
    }

    fn value(&self) -> Nat6TimerValue {
        let raw = self
            .tc
            .maps
            .nat6_timer_map
            .lookup(self.key.as_bytes(), MapFlags::ANY)
            .unwrap()
            .unwrap();
        Nat6TimerValue::read_from_bytes(&raw).unwrap()
    }

    #[track_caller]
    fn expect_idle_wait(&self, ms: u32) {
        for (delay, status) in
            [(TICK_MS, IDLE_CHECK_1), (TICK_MS, IDLE_CHECK_2), (ms, WAIT_TIMEOUT)]
        {
            assert_eq!(tick_key(self.tc, &self.key), delay);
            assert_eq!(self.value().status, status);
        }
    }
}

#[test]
fn half_close_then_peer_fin_blocks_reconnect_across_tc_and_xdp() {
    with_tcp_flow(|flow| {
        assert_eq!(flow.tc_egress(SYN), TC_ACT_UNSPEC);
        assert_eq!(flow.xdp_ingress(SYN | ACK), XDP_PASS);
        assert_eq!(flow.tc_egress(FIN | ACK), TC_ACT_UNSPEC);
        assert_eq!(flow.tc_egress(FIN | ACK), TC_ACT_UNSPEC);
        flow.expect_idle_wait(600_000);

        assert_eq!(flow.xdp_ingress(FIN | ACK), XDP_PASS);
        let closing = flow.value();
        assert_eq!(closing.status, ACTIVE);
        assert_eq!(flow.tc_egress(SYN), TC_ACT_SHOT);
        assert_eq!(flow.xdp_ingress(SYN | ACK), XDP_DROP);
        assert_eq!(flow.value(), closing);

        assert_eq!(tick_key(flow.tc, &flow.key), 6000);
        let waiting = flow.value();
        assert_eq!(waiting.status, WAIT_TCP_CLOSE);
        assert_ne!(waiting.wait_deadline_ns, 0);
        assert_eq!(flow.xdp_ingress(ACK), XDP_PASS);
        assert_eq!(flow.tc_egress(FIN | ACK), TC_ACT_UNSPEC);
        assert_eq!(flow.xdp_ingress(RST), XDP_PASS);
        assert_eq!(flow.tc_egress(SYN), TC_ACT_SHOT);
        assert_eq!(flow.value().wait_deadline_ns, waiting.wait_deadline_ns);
        assert_eq!(flow.value().status, WAIT_TCP_CLOSE);
        assert!(tick_key(flow.tc, &flow.key) <= 6000);
        assert_eq!(flow.value().wait_deadline_ns, waiting.wait_deadline_ns);

        let ct = &flow.tc.maps.nat6_timer_map;
        let expired = Nat6TimerValue { wait_deadline_ns: 1, ..flow.value() };
        ct.update(flow.key.as_bytes(), expired.as_bytes(), MapFlags::EXIST).unwrap();
        assert_eq!(tick_key(flow.tc, &flow.key), 0);
        assert!(ct.lookup(flow.key.as_bytes(), MapFlags::ANY).unwrap().is_none());
        assert_eq!(flow.tc.maps.nat6_mapping_map.keys().count(), 0);
        assert_eq!(flow.tc_egress(SYN), TC_ACT_UNSPEC);
        assert_eq!(flow.value().egress_packets, 1);
    });
}

#[test]
fn unanswered_syn_then_fin_keeps_the_handshake_timeout() {
    with_tcp_flow(|flow| {
        assert_eq!(flow.tc_egress(SYN), TC_ACT_UNSPEC);
        assert_eq!(flow.tc_egress(FIN | ACK), TC_ACT_UNSPEC);
        flow.expect_idle_wait(6000);
    });
}

#[test]
fn rst_preserves_the_handshake_until_a_fresh_syn() {
    with_tcp_flow(|flow| {
        assert_eq!(flow.tc_egress(SYN), TC_ACT_UNSPEC);
        assert_eq!(flow.xdp_ingress(RST), XDP_PASS);
        flow.expect_idle_wait(6000);
        assert_eq!(flow.tc_egress(SYN), TC_ACT_UNSPEC);
        assert_eq!(flow.xdp_ingress(SYN | ACK), XDP_PASS);
        assert_eq!(flow.tc_egress(FIN | ACK), TC_ACT_UNSPEC);
        assert_eq!(flow.xdp_ingress(RST), XDP_PASS);
        let reset = flow.value().tcp_flags;
        assert_eq!(flow.xdp_ingress(SYN | ACK), XDP_PASS);
        assert_eq!(flow.value().tcp_flags, reset);
        flow.expect_idle_wait(600_000);
        assert_eq!(flow.tc_egress(SYN), TC_ACT_UNSPEC);
        flow.expect_idle_wait(6000);
        // The new handshake must have cleared the old LAN FIN.
        assert_eq!(flow.xdp_ingress(SYN | ACK), XDP_PASS);
        assert_eq!(flow.xdp_ingress(FIN | ACK), XDP_PASS);
        flow.expect_idle_wait(600_000);
    });
}
