use landscape_common::net::MacAddr;
use landscape_common::net_proto::dhcp::{
    DhcpV4Message, DhcpV4MessageType as MessageType, DhcpV4OpCode, DhcpV4Option as DhcpOption,
    DhcpV4OptionCode as OptionCode, DhcpV4Options,
};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::Instant;

use super::fsm::{DhcpState, DhcpV4Fsm, FsmAction, FsmEvent, LeaseContext, get_renew_times};

pub(crate) const TEST_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
pub(crate) const OFFER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
pub(crate) const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn new_fsm() -> DhcpV4Fsm {
    DhcpV4Fsm::new(TEST_MAC, "test-host".to_string())
}

fn current_xid(fsm: &DhcpV4Fsm) -> u32 {
    match &fsm.state {
        DhcpState::Discovering { xid, .. } | DhcpState::Requesting { xid, .. } => *xid,
        DhcpState::Bound { lease }
        | DhcpState::Renewing { lease }
        | DhcpState::WaitToRebind { lease }
        | DhcpState::Rebind { lease } => lease.xid,
    }
}

pub(crate) fn server_msg(msg_type: MessageType, xid: u32) -> DhcpV4Message {
    let mut msg = DhcpV4Message::default();
    msg.set_opcode(DhcpV4OpCode::BootReply);
    msg.set_xid(xid);
    msg.opts_mut().insert(DhcpOption::MessageType(msg_type));
    msg
}

pub(crate) fn ack_msg(xid: u32, yiaddr: Ipv4Addr, lease_secs: u32) -> DhcpV4Message {
    let mut msg = server_msg(MessageType::Ack, xid);
    msg.set_yiaddr(yiaddr);
    msg.set_siaddr(SERVER_IP);
    msg.opts_mut().insert(DhcpOption::AddressLeaseTime(lease_secs));
    msg.opts_mut().insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));
    msg
}

fn bound_fsm(renew: u64, rebind: u64, lease: u64) -> DhcpV4Fsm {
    let now = Instant::now();
    let mut fsm = new_fsm();
    fsm.state = DhcpState::Bound {
        lease: LeaseContext {
            xid: 7,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: OFFER_IP,
            siaddr: SERVER_IP,
            options: DhcpV4Options::default(),
            renew_at: now + Duration::from_secs(renew),
            rebind_at: now + Duration::from_secs(rebind),
            lease_at: now + Duration::from_secs(lease),
        },
    };
    fsm
}

fn sends(actions: &[FsmAction]) -> Vec<(&DhcpV4Message, Ipv4Addr)> {
    actions
        .iter()
        .filter_map(|a| match a {
            FsmAction::Send { msg, dest } => Some((msg, *dest)),
            _ => None,
        })
        .collect()
}

fn timers(actions: &[FsmAction]) -> Vec<Duration> {
    actions
        .iter()
        .filter_map(|a| match a {
            FsmAction::ScheduleTimer(d) => Some(*d),
            _ => None,
        })
        .collect()
}

fn bind_lease(actions: &[FsmAction]) -> Option<&super::fsm::LeaseParams> {
    actions.iter().find_map(|a| match a {
        FsmAction::BindLease(p) => Some(p),
        _ => None,
    })
}

pub(crate) fn msg_type_of(msg: &DhcpV4Message) -> Option<MessageType> {
    match msg.opts().get(OptionCode::MessageType) {
        Some(DhcpOption::MessageType(t)) => Some(*t),
        _ => None,
    }
}

fn lease_opts(lease: u32, t1: Option<u32>, t2: Option<u32>) -> DhcpV4Options {
    let mut options = DhcpV4Options::default();
    options.insert(DhcpOption::AddressLeaseTime(lease));
    if let Some(t1) = t1 {
        options.insert(DhcpOption::Renewal(t1));
    }
    if let Some(t2) = t2 {
        options.insert(DhcpOption::Rebinding(t2));
    }
    options
}

#[test]
fn malformed_lease_options_fall_back_to_rfc_defaults() {
    assert_eq!(get_renew_times(&lease_opts(100, None, None)).unwrap(), (50, 87, 100));
    assert_eq!(get_renew_times(&lease_opts(100, Some(0), Some(0))).unwrap(), (50, 87, 100));
    assert_eq!(get_renew_times(&lease_opts(100, Some(10), Some(20))).unwrap(), (10, 20, 100));
    assert_eq!(get_renew_times(&lease_opts(100, Some(90), Some(80))).unwrap(), (90, 91, 100));
    assert_eq!(
        get_renew_times(&lease_opts(u32::MAX, Some(1), Some(2))).unwrap(),
        (1, 2, u32::MAX as u64)
    );
    assert!(get_renew_times(&DhcpV4Options::default()).is_none());
    for (lease, t1, t2) in [
        (0u32, None, None),
        (0, Some(0), Some(0)),
        (1, None, None),
        (2, Some(1), Some(1)),
        (100, Some(90), Some(80)),
        (100, Some(120), Some(200)),
        (100, Some(99), Some(99)),
        (u32::MAX, Some(1), Some(2)),
    ] {
        let (renew, rebind, lease) =
            get_renew_times(&lease_opts(lease, t1, t2)).expect("always resolvable");
        assert!(renew >= 1, "renew must be >= 1s (lease={lease}, t1={t1:?}, t2={t2:?})");
        assert!(rebind > renew, "rebind must exceed renew (lease={lease}, t1={t1:?}, t2={t2:?})");
        assert!(rebind <= lease, "rebind must not exceed the lease (lease={lease})");
    }
}

#[tokio::test(start_paused = true)]
async fn discover_round_waits_then_backoff() {
    let mut fsm = new_fsm();
    let first_xid = current_xid(&fsm);

    // RFC 2131 §4.1: retransmission waits double from 4s and every value is
    // randomized by a uniform -1..=+1 jitter.
    for (n, base) in [(1u64, 4u64), (2, 8), (3, 16), (4, 32)] {
        let actions = fsm.on_event(FsmEvent::TimerFired);
        assert_eq!(sends(&actions).len(), 1, "one discover per timer fire");
        assert_eq!(sends(&actions)[0].1, Ipv4Addr::BROADCAST);
        assert_eq!(msg_type_of(sends(&actions)[0].0), Some(MessageType::Discover));
        assert!(sends(&actions)[0].0.flags().broadcast());
        assert!(sends(&actions)[0].0.opts().get(OptionCode::RequestedIpAddress).is_none());
        let wait = timers(&actions)[0].as_secs();
        assert!(
            (base - 1..=base + 1).contains(&wait),
            "attempt {n} wait {wait}s outside {}-{}s",
            base - 1,
            base + 1
        );
        assert_eq!(fsm.attempts, n);
    }

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert!(sends(&actions).is_empty(), "no discover on backoff fire");
    assert_eq!(timers(&actions), vec![Duration::from_secs(4)]);
    assert_eq!(fsm.connect_failure_count, 1);
    let backoff_xid = current_xid(&fsm);
    assert_ne!(backoff_xid, first_xid);

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1);
    let wait = timers(&actions)[0].as_secs();
    assert!((3..=5).contains(&wait), "post-backoff wait {wait}s outside 3-5s");

    for _ in 0..3 {
        fsm.on_event(FsmEvent::TimerFired);
    }
    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(
        timers(&actions),
        vec![Duration::from_secs(8)],
        "second round failure doubles backoff"
    );
}

#[tokio::test(start_paused = true)]
async fn discover_backoff_caps_at_ten_minutes() {
    let mut fsm = new_fsm();
    let mut last_backoff = Duration::ZERO;
    for _ in 0..40 {
        for _ in 0..4 {
            fsm.on_event(FsmEvent::TimerFired);
        }
        let actions = fsm.on_event(FsmEvent::TimerFired);
        last_backoff = timers(&actions)[0];
    }
    assert_eq!(last_backoff, Duration::from_secs(600));
    assert_eq!(fsm.connect_failure_count, 40);
}

#[tokio::test(start_paused = true)]
async fn discover_with_requested_ip_toggles_broadcast_after_two_attempts() {
    let mut fsm = new_fsm();
    fsm.state = DhcpState::init(Some(OFFER_IP));

    for (n, expect_broadcast) in [(1u64, true), (2, true), (3, false), (4, false)] {
        let actions = fsm.on_event(FsmEvent::TimerFired);
        assert_eq!(fsm.attempts, n);
        let (msg, dest) = sends(&actions)[0];
        assert_eq!(dest, Ipv4Addr::BROADCAST);
        assert_eq!(msg_type_of(msg), Some(MessageType::Discover));
        assert_eq!(
            msg.flags().broadcast(),
            expect_broadcast,
            "attempt {n} broadcast flag must follow use_broadcast"
        );
        // RFC 2131 Table 5: a DISCOVER with a requested address carries it in
        // the option, never in ciaddr.
        assert_eq!(msg.ciaddr(), Ipv4Addr::UNSPECIFIED);
        assert!(matches!(
            msg.opts().get(OptionCode::RequestedIpAddress),
            Some(DhcpOption::RequestedIpAddress(ip)) if *ip == OFFER_IP
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn offer_request_ack_binds_lease() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    let actions = fsm.on_event(FsmEvent::Recv(offer));
    assert_eq!(timers(&actions), vec![Duration::ZERO]);
    assert!(matches!(&fsm.state, DhcpState::Requesting { .. }));

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1);
    assert_eq!(msg_type_of(sends(&actions)[0].0), Some(MessageType::Request));
    let wait = timers(&actions)[0].as_secs();
    assert!((3..=5).contains(&wait), "request retransmit wait {wait}s outside 3-5s");

    let actions = fsm.on_event(FsmEvent::Recv(ack_msg(xid, OFFER_IP, 100)));
    let params = bind_lease(&actions).expect("ack must bind lease");
    assert_eq!(params.yiaddr, OFFER_IP);
    assert_eq!(params.prefix, 24);
    assert_eq!(params.renew_time, 50);
    assert_eq!(params.lease_time, 100);
    assert_eq!(timers(&actions), vec![Duration::from_secs(50)]);
    assert_eq!(fsm.leased_ip(), Some(OFFER_IP));
    assert!(matches!(&fsm.state, DhcpState::Bound { .. }));
    assert_eq!(fsm.connect_failure_count, 0);
}

#[tokio::test(start_paused = true)]
async fn ack_with_mismatched_yiaddr_ignored() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    fsm.on_event(FsmEvent::Recv(offer));

    let actions = fsm.on_event(FsmEvent::Recv(ack_msg(xid, Ipv4Addr::new(192, 0, 2, 99), 100)));
    assert!(actions.is_empty());
    assert!(matches!(&fsm.state, DhcpState::Requesting { .. }));
}

#[tokio::test(start_paused = true)]
async fn nak_restarts_discover_immediately() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    fsm.on_event(FsmEvent::Recv(offer));

    let actions = fsm.on_event(FsmEvent::Recv(server_msg(MessageType::Nak, xid)));
    assert!(sends(&actions).is_empty());
    assert_eq!(timers(&actions), vec![Duration::ZERO]);
    assert!(!actions.iter().any(|a| matches!(a, FsmAction::ReleaseLease)));
    assert_ne!(current_xid(&fsm), xid);

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1);
    assert_eq!(msg_type_of(sends(&actions)[0].0), Some(MessageType::Discover));
}

#[tokio::test(start_paused = true)]
async fn requesting_attempts_exhausted_restarts_discover_with_single_send() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    fsm.on_event(FsmEvent::Recv(offer));

    for _ in 0..3 {
        let actions = fsm.on_event(FsmEvent::TimerFired);
        assert_eq!(msg_type_of(sends(&actions)[0].0), Some(MessageType::Request));
    }

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1, "delegation must issue exactly one send");
    assert_eq!(msg_type_of(sends(&actions)[0].0), Some(MessageType::Discover));
    assert!(matches!(&fsm.state, DhcpState::Discovering { .. }));
}

#[tokio::test(start_paused = true)]
async fn t1_transitions_to_renewing_with_unicast_dest() {
    let mut fsm = bound_fsm(50, 87, 100);
    tokio::time::advance(Duration::from_secs(50)).await;

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1);
    assert_eq!(sends(&actions)[0].1, SERVER_IP);
    assert_eq!(msg_type_of(sends(&actions)[0].0), Some(MessageType::Request));
    assert_eq!(timers(&actions), vec![Duration::from_secs(60)]);
    assert_eq!(fsm.leased_ip(), Some(OFFER_IP));

    match &fsm.state {
        DhcpState::Renewing { lease } => {
            assert_eq!(lease.ciaddr, OFFER_IP);
            assert_eq!(lease.yiaddr, Ipv4Addr::UNSPECIFIED);
            assert_ne!(lease.xid, 7);
        }
        other => panic!("expected Renewing, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn renew_retransmit_waits_half_of_remaining_time_until_t2() {
    let mut fsm = bound_fsm(3600, 7560, 8640);
    tokio::time::advance(Duration::from_secs(3600)).await;

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(timers(&actions), vec![Duration::from_secs(1980)]);
}

#[tokio::test(start_paused = true)]
async fn renew_near_t2_waits_to_rebind_then_broadcasts() {
    let mut fsm = bound_fsm(50, 80, 200);
    tokio::time::advance(Duration::from_secs(50)).await;

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert!(matches!(&fsm.state, DhcpState::Renewing { .. }));
    assert_eq!(timers(&actions), vec![Duration::from_secs(60)]);
    assert_eq!(fsm.leased_ip(), Some(OFFER_IP));

    tokio::time::advance(Duration::from_secs(60)).await;
    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1);
    assert_eq!(timers(&actions), vec![Duration::ZERO]);
    assert!(matches!(&fsm.state, DhcpState::WaitToRebind { .. }));
    assert_eq!(fsm.leased_ip(), Some(OFFER_IP));

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1);
    assert_eq!(sends(&actions)[0].1, Ipv4Addr::BROADCAST);
    assert_eq!(timers(&actions), vec![Duration::from_secs(60)]);
    assert!(matches!(&fsm.state, DhcpState::Rebind { .. }));
    assert_eq!(fsm.leased_ip(), Some(OFFER_IP));

    tokio::time::advance(Duration::from_secs(120)).await;
    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1);
    assert_eq!(msg_type_of(sends(&actions)[0].0), Some(MessageType::Discover));
    assert!(actions.iter().any(|a| matches!(a, FsmAction::ReleaseLease)));
    assert!(matches!(&fsm.state, DhcpState::Discovering { .. }));
    assert_eq!(fsm.leased_ip(), None);
}

#[tokio::test(start_paused = true)]
async fn rebind_request_omits_server_identifier() {
    let mut fsm = bound_fsm(50, 80, 200);
    if let DhcpState::Bound { lease } = &mut fsm.state {
        lease.options.insert(DhcpOption::ServerIdentifier(SERVER_IP));
    }
    tokio::time::advance(Duration::from_secs(50)).await;
    fsm.on_event(FsmEvent::TimerFired);

    tokio::time::advance(Duration::from_secs(60)).await;
    fsm.on_event(FsmEvent::TimerFired);

    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert!(matches!(&fsm.state, DhcpState::Rebind { .. }));
    assert_eq!(sends(&actions).len(), 1);
    let (msg, dest) = sends(&actions)[0];
    assert_eq!(dest, Ipv4Addr::BROADCAST);
    assert!(msg.opts().get(OptionCode::ServerIdentifier).is_none());
    assert_eq!(msg.ciaddr(), OFFER_IP);
    assert_eq!(msg_type_of(msg), Some(MessageType::Request));
    // RFC 2131 §4.3.2 only mandates the IP destination be broadcast (asserted
    // above); §4.1 says a client that can receive unicast datagrams (i.e. holds
    // an address in REBINDING) SHOULD clear the BROADCAST flag.
    assert!(!msg.flags().broadcast(), "REBINDING request must clear the BROADCAST flag");
}

#[tokio::test(start_paused = true)]
async fn requesting_falls_back_to_siaddr_as_server_identifier() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    offer.set_siaddr(SERVER_IP);
    fsm.on_event(FsmEvent::Recv(offer));

    let actions = fsm.on_event(FsmEvent::TimerFired);
    let (msg, _) = sends(&actions)[0];
    assert!(matches!(
        msg.opts().get(OptionCode::ServerIdentifier),
        Some(DhcpOption::ServerIdentifier(ip)) if *ip == SERVER_IP
    ));
}

#[tokio::test(start_paused = true)]
async fn requesting_ignores_hostile_offer_ciaddr() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    offer.set_ciaddr(Ipv4Addr::new(192, 0, 2, 123));
    fsm.on_event(FsmEvent::Recv(offer));

    // RFC 2131 §4.3.2: the SELECTING request sends ciaddr = 0 and the offered
    // address in the option, even if the OFFER carried a nonzero ciaddr.
    let actions = fsm.on_event(FsmEvent::TimerFired);
    let (msg, _) = sends(&actions)[0];
    assert_eq!(msg.ciaddr(), Ipv4Addr::UNSPECIFIED);
    assert!(msg.flags().broadcast());
    assert!(matches!(
        msg.opts().get(OptionCode::RequestedIpAddress),
        Some(DhcpOption::RequestedIpAddress(ip)) if *ip == OFFER_IP
    ));
}

#[tokio::test(start_paused = true)]
async fn requesting_preserves_offer_server_identifier() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    offer.set_siaddr(Ipv4Addr::new(192, 0, 2, 250));
    offer.opts_mut().insert(DhcpOption::ServerIdentifier(SERVER_IP));
    fsm.on_event(FsmEvent::Recv(offer));

    let actions = fsm.on_event(FsmEvent::TimerFired);
    let (msg, _) = sends(&actions)[0];
    assert!(matches!(
        msg.opts().get(OptionCode::ServerIdentifier),
        Some(DhcpOption::ServerIdentifier(ip)) if *ip == SERVER_IP
    ));
}

#[tokio::test(start_paused = true)]
async fn renew_ack_accepts_any_yiaddr() {
    let mut fsm = bound_fsm(50, 87, 100);
    tokio::time::advance(Duration::from_secs(50)).await;
    fsm.on_event(FsmEvent::TimerFired);

    let renew_xid = current_xid(&fsm);
    let new_ip = Ipv4Addr::new(192, 0, 2, 77);
    let actions = fsm.on_event(FsmEvent::Recv(ack_msg(renew_xid, new_ip, 100)));
    let params = bind_lease(&actions).expect("renew ack must bind lease");
    assert_eq!(params.yiaddr, new_ip);
    assert_eq!(fsm.leased_ip(), Some(new_ip));
    assert!(matches!(&fsm.state, DhcpState::Bound { .. }));
}

#[tokio::test(start_paused = true)]
async fn expired_bound_deadline_renews_immediately_without_panicking() {
    let mut fsm = bound_fsm(50, 87, 100);
    if let DhcpState::Bound { lease } = &mut fsm.state {
        lease.renew_at = Instant::now() - Duration::from_secs(10);
    }
    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1);
    assert!(matches!(&fsm.state, DhcpState::Renewing { .. }));
}

#[tokio::test(start_paused = true)]
async fn expired_wait_to_rebind_deadline_rebinds_immediately_without_panicking() {
    let mut fsm = bound_fsm(50, 87, 100);
    if let DhcpState::Bound { lease } = &mut fsm.state {
        lease.renew_at = Instant::now() - Duration::from_secs(20);
        lease.rebind_at = Instant::now() - Duration::from_secs(10);
    }
    fsm.on_event(FsmEvent::TimerFired);
    assert!(matches!(&fsm.state, DhcpState::WaitToRebind { .. }));
    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions).len(), 1);
    assert!(matches!(&fsm.state, DhcpState::Rebind { .. }));
}

#[tokio::test(start_paused = true)]
async fn is_initial_phase_truth_table_across_lifecycle() {
    let mut fsm = new_fsm();
    assert!(fsm.is_initial_phase(), "Discovering must use raw socket");

    let xid = current_xid(&fsm);
    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    fsm.on_event(FsmEvent::Recv(offer));
    assert!(fsm.is_initial_phase(), "Requesting must use raw socket");

    fsm.on_event(FsmEvent::Recv(ack_msg(xid, OFFER_IP, 1000)));
    assert!(matches!(&fsm.state, DhcpState::Bound { .. }));
    assert!(!fsm.is_initial_phase(), "Bound must use udp socket");

    tokio::time::advance(Duration::from_secs(500)).await;
    fsm.on_event(FsmEvent::TimerFired);
    assert!(matches!(&fsm.state, DhcpState::Renewing { .. }));
    assert!(!fsm.is_initial_phase(), "Renewing must use udp socket");

    // t = 900s: past T2 (875s) but before lease expiry, so the next tick
    // lands in WaitToRebind and then Rebind instead of a lease-expired Discover.
    tokio::time::advance(Duration::from_secs(400)).await;
    fsm.on_event(FsmEvent::TimerFired);
    assert!(matches!(&fsm.state, DhcpState::WaitToRebind { .. }));
    assert!(!fsm.is_initial_phase(), "WaitToRebind must use udp socket");

    fsm.on_event(FsmEvent::TimerFired);
    assert!(matches!(&fsm.state, DhcpState::Rebind { .. }));
    assert!(fsm.is_initial_phase(), "Rebind must use raw socket");
}

#[tokio::test(start_paused = true)]
async fn inbound_filters_drop_invalid_packets() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);

    let mut boot_request = server_msg(MessageType::Offer, xid);
    boot_request.set_opcode(DhcpV4OpCode::BootRequest);
    assert!(fsm.on_event(FsmEvent::Recv(boot_request)).is_empty());
    assert!(matches!(&fsm.state, DhcpState::Discovering { .. }));

    let mut no_type = DhcpV4Message::default();
    no_type.set_opcode(DhcpV4OpCode::BootReply);
    no_type.set_xid(xid);
    assert!(fsm.on_event(FsmEvent::Recv(no_type)).is_empty());
    assert!(matches!(&fsm.state, DhcpState::Discovering { .. }));

    let unhandleable = server_msg(MessageType::Ack, xid);
    assert!(fsm.on_event(FsmEvent::Recv(unhandleable)).is_empty());
    assert!(matches!(&fsm.state, DhcpState::Discovering { .. }));

    let mut nak = server_msg(MessageType::Nak, xid);
    nak.set_yiaddr(OFFER_IP);
    assert!(fsm.on_event(FsmEvent::Recv(nak)).is_empty());
    assert!(matches!(&fsm.state, DhcpState::Discovering { .. }));
}

#[tokio::test(start_paused = true)]
async fn ack_with_mismatched_xid_discarded() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    fsm.on_event(FsmEvent::Recv(offer));

    let actions = fsm.on_event(FsmEvent::Recv(ack_msg(xid.wrapping_add(7), OFFER_IP, 100)));
    assert!(actions.is_empty());
    assert!(matches!(&fsm.state, DhcpState::Requesting { .. }));
    assert_eq!(fsm.leased_ip(), None);
}

#[tokio::test(start_paused = true)]
async fn renew_dest_prefers_server_identifier_option_then_siaddr_then_broadcast() {
    // RFC 2131 §4.1: the 'server identifier' option wins over siaddr.
    let mut fsm = bound_fsm(50, 80, 200);
    if let DhcpState::Bound { lease } = &mut fsm.state {
        lease.siaddr = Ipv4Addr::new(192, 0, 2, 250);
        lease.options.insert(DhcpOption::ServerIdentifier(SERVER_IP));
    }
    tokio::time::advance(Duration::from_secs(50)).await;
    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions)[0].1, SERVER_IP);
    assert!(matches!(&fsm.state, DhcpState::Renewing { .. }));

    // siaddr alone is still a valid unicast destination.
    let mut fsm = bound_fsm(50, 80, 200);
    tokio::time::advance(Duration::from_secs(50)).await;
    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions)[0].1, SERVER_IP);
    assert!(matches!(&fsm.state, DhcpState::Renewing { .. }));

    // Neither is known: fall back to broadcast.
    let mut fsm = bound_fsm(50, 80, 200);
    if let DhcpState::Bound { lease } = &mut fsm.state {
        lease.siaddr = Ipv4Addr::UNSPECIFIED;
    }
    tokio::time::advance(Duration::from_secs(50)).await;
    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert_eq!(sends(&actions)[0].1, Ipv4Addr::BROADCAST);
    assert!(matches!(&fsm.state, DhcpState::Renewing { .. }));
}

#[tokio::test(start_paused = true)]
async fn nak_during_renewing_halts_lease() {
    let mut fsm = bound_fsm(50, 87, 100);
    tokio::time::advance(Duration::from_secs(50)).await;
    fsm.on_event(FsmEvent::TimerFired);

    let renew_xid = current_xid(&fsm);
    assert_eq!(fsm.leased_ip(), Some(OFFER_IP));
    let actions = fsm.on_event(FsmEvent::Recv(server_msg(MessageType::Nak, renew_xid)));
    assert_eq!(timers(&actions), vec![Duration::ZERO]);
    assert!(actions.iter().any(|a| matches!(a, FsmAction::ReleaseLease)));
    assert!(matches!(&fsm.state, DhcpState::Discovering { .. }));
    assert_eq!(fsm.leased_ip(), None);
}

#[tokio::test(start_paused = true)]
async fn request_wire_fields_follow_rfc_tables() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);
    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    offer.set_siaddr(SERVER_IP);
    fsm.on_event(FsmEvent::Recv(offer));

    let actions = fsm.on_event(FsmEvent::TimerFired);
    let (msg, _) = sends(&actions)[0];
    assert!(msg.flags().broadcast(), "SELECTING request must set broadcast flag");
    assert_eq!(msg.ciaddr(), Ipv4Addr::UNSPECIFIED);
    assert!(matches!(
        msg.opts().get(OptionCode::RequestedIpAddress),
        Some(DhcpOption::RequestedIpAddress(ip)) if *ip == OFFER_IP
    ));

    let mut fsm = bound_fsm(50, 87, 100);
    tokio::time::advance(Duration::from_secs(50)).await;
    let actions = fsm.on_event(FsmEvent::TimerFired);
    let (msg, _) = sends(&actions)[0];
    assert!(!msg.flags().broadcast(), "RENEWING request must not set broadcast flag");
    assert_eq!(msg.ciaddr(), OFFER_IP);
    assert!(msg.opts().get(OptionCode::RequestedIpAddress).is_none());
}

#[tokio::test(start_paused = true)]
async fn ack_missing_required_options_keeps_requesting() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);
    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    fsm.on_event(FsmEvent::Recv(offer));

    let mut no_lease_time = server_msg(MessageType::Ack, xid);
    no_lease_time.set_yiaddr(OFFER_IP);
    no_lease_time.opts_mut().insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));
    assert!(fsm.on_event(FsmEvent::Recv(no_lease_time)).is_empty());
    assert!(matches!(&fsm.state, DhcpState::Requesting { .. }));

    let mut no_mask = server_msg(MessageType::Ack, xid);
    no_mask.set_yiaddr(OFFER_IP);
    no_mask.opts_mut().insert(DhcpOption::AddressLeaseTime(100));
    assert!(fsm.on_event(FsmEvent::Recv(no_mask)).is_empty());
    assert!(matches!(&fsm.state, DhcpState::Requesting { .. }));
}

#[tokio::test(start_paused = true)]
async fn explicit_t1_t2_flow_to_scheduler() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);
    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    fsm.on_event(FsmEvent::Recv(offer));

    let mut ack = ack_msg(xid, OFFER_IP, 1000);
    ack.opts_mut().insert(DhcpOption::Renewal(200));
    ack.opts_mut().insert(DhcpOption::Rebinding(400));
    let actions = fsm.on_event(FsmEvent::Recv(ack));
    let params = bind_lease(&actions).expect("ack must bind lease");
    assert_eq!(params.renew_time, 200);
    assert_eq!(timers(&actions), vec![Duration::from_secs(200)]);

    tokio::time::advance(Duration::from_secs(200)).await;
    let actions = fsm.on_event(FsmEvent::TimerFired);
    assert!(matches!(&fsm.state, DhcpState::Renewing { .. }));
    // (T2 - T1) / 2 = 100s exceeds the 60s floor, so this pins the explicit
    // T2: the RFC default T2 (875s) would schedule (875 - 200) / 2 = 337s.
    assert_eq!(timers(&actions), vec![Duration::from_secs(100)]);
}

#[tokio::test(start_paused = true)]
async fn request_carries_client_identifier_and_param_list() {
    let mut fsm = new_fsm();
    let xid = current_xid(&fsm);
    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    fsm.on_event(FsmEvent::Recv(offer));

    let actions = fsm.on_event(FsmEvent::TimerFired);
    let (msg, _) = sends(&actions)[0];
    let expected_id: Vec<u8> = std::iter::once(1u8).chain(TEST_MAC.octets()).collect();
    assert!(matches!(
        msg.opts().get(OptionCode::ClientIdentifier),
        Some(DhcpOption::ClientIdentifier(id)) if *id == expected_id
    ));
    assert!(matches!(
        msg.opts().get(OptionCode::ParameterRequestList),
        Some(DhcpOption::ParameterRequestList(list)) if list.len() == 10
    ));
    assert!(matches!(
        msg.opts().get(OptionCode::ClassIdentifier),
        Some(DhcpOption::ClassIdentifier(v)) if v.as_slice() == b"MSFT 5.0"
    ));
}

#[tokio::test(start_paused = true)]
async fn rebind_ack_restores_bound() {
    let mut fsm = bound_fsm(50, 80, 200);
    tokio::time::advance(Duration::from_secs(50)).await;
    fsm.on_event(FsmEvent::TimerFired);

    tokio::time::advance(Duration::from_secs(60)).await;
    fsm.on_event(FsmEvent::TimerFired);
    fsm.on_event(FsmEvent::TimerFired);
    assert!(matches!(&fsm.state, DhcpState::Rebind { .. }));

    let rebind_xid = current_xid(&fsm);
    let actions = fsm.on_event(FsmEvent::Recv(ack_msg(rebind_xid, OFFER_IP, 100)));
    assert!(bind_lease(&actions).is_some());
    assert_eq!(timers(&actions), vec![Duration::from_secs(50)]);
    assert!(matches!(&fsm.state, DhcpState::Bound { .. }));
    assert_eq!(fsm.leased_ip(), Some(OFFER_IP));
}
