use arc_swap::ArcSwap;
use landscape_common::net_proto::dhcp::{
    DhcpV4Message, DhcpV4MessageType as MessageType, DhcpV4OptionCode as OptionCode,
};
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{DhcpV4Runtime, LinkState, LinkStateHandle, V4Runtime};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use uuid::Uuid;

use super::DhcpV4ClientServiceRuntimeConfig;
use super::driver::{DhcpV4Io, DhcpV4SystemOps, run_with};
use super::fsm::LeaseParams;
use super::test_fsm::{OFFER_IP, SERVER_IP, TEST_MAC, ack_msg, msg_type_of, server_msg};

struct MockIo {
    inbox: mpsc::Receiver<DhcpV4Message>,
    sent: Arc<Mutex<Vec<(DhcpV4Message, Ipv4Addr)>>>,
    modes: Arc<Mutex<Vec<bool>>>,
}

#[async_trait::async_trait]
impl DhcpV4Io for MockIo {
    async fn update_mode(&mut self, is_initial: bool) -> io::Result<()> {
        self.modes.lock().unwrap().push(is_initial);
        Ok(())
    }

    async fn send(&self, msg: &DhcpV4Message, dest_ip: Ipv4Addr) -> io::Result<()> {
        self.sent.lock().unwrap().push((msg.clone(), dest_ip));
        Ok(())
    }

    async fn recv(&mut self) -> io::Result<DhcpV4Message> {
        match self.inbox.recv().await {
            Some(msg) => Ok(msg),
            None => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "inbox closed")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum OpsCall {
    Setup,
    Apply { yiaddr: Ipv4Addr, lease_time: u64 },
    Release,
}

struct MockOps {
    calls: Arc<Mutex<Vec<OpsCall>>>,
}

#[async_trait::async_trait]
impl DhcpV4SystemOps for MockOps {
    async fn setup(&mut self, _iface_name: &str) {
        self.calls.lock().unwrap().push(OpsCall::Setup);
    }

    async fn apply_lease(&mut self, params: &LeaseParams) {
        self.calls.lock().unwrap().push(OpsCall::Apply {
            yiaddr: params.yiaddr,
            lease_time: params.lease_time,
        });
    }

    async fn release(&mut self) {
        self.calls.lock().unwrap().push(OpsCall::Release);
    }
}

struct Harness {
    tx: mpsc::Sender<DhcpV4Message>,
    sent: Arc<Mutex<Vec<(DhcpV4Message, Ipv4Addr)>>>,
    modes: Arc<Mutex<Vec<bool>>>,
    ops_calls: Arc<Mutex<Vec<OpsCall>>>,
    link_rx: tokio::sync::watch::Receiver<LinkState>,
    runtime: Arc<ArcSwap<V4Runtime>>,
    status: ServiceHandle,
    task: JoinHandle<()>,
}

fn spawn_driver() -> Harness {
    let (tx, inbox) = mpsc::channel(16);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let modes = Arc::new(Mutex::new(Vec::new()));
    let io = MockIo { inbox, sent: sent.clone(), modes: modes.clone() };
    let ops_calls = Arc::new(Mutex::new(Vec::new()));
    let ops = MockOps { calls: ops_calls.clone() };
    let (link, link_rx) = LinkStateHandle::new(None);
    let runtime = Arc::new(ArcSwap::from_pointee(V4Runtime::Idle));
    let status = ServiceHandle::new();
    let task =
        tokio::spawn(run_with(test_config(), io, ops, Some(link), runtime.clone(), status.clone()));
    Harness {
        tx,
        sent,
        modes,
        ops_calls,
        link_rx,
        runtime,
        status,
        task,
    }
}

fn test_config() -> DhcpV4ClientServiceRuntimeConfig {
    DhcpV4ClientServiceRuntimeConfig {
        link_id: Uuid::new_v4(),
        chain_id: 1,
        ifindex: 42,
        iface_name: "test0".to_string(),
        mac_addr: TEST_MAC,
        client_port: 68,
        hostname: "test-host".to_string(),
        default_router: false,
    }
}

async fn wait_for(cond: impl Fn() -> bool) {
    let mut polls = 0;
    while !cond() {
        polls += 1;
        assert!(polls < 200_000, "condition never met");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn shutdown(h: Harness) {
    h.status.just_change_status(ServiceStatus::Stopping);
    let runtime = h.runtime.clone();
    h.task.await.unwrap();
    assert_eq!(**runtime.load(), V4Runtime::Stopped);
}

fn sent_len(h: &Harness) -> usize {
    h.sent.lock().unwrap().len()
}

fn sent_at(h: &Harness, i: usize) -> (DhcpV4Message, Ipv4Addr) {
    h.sent.lock().unwrap()[i].clone()
}

fn modes_contains(h: &Harness, v: bool) -> bool {
    h.modes.lock().unwrap().contains(&v)
}

fn runtime_now(h: &Harness) -> V4Runtime {
    (**h.runtime.load()).clone()
}

async fn complete_dora(h: &Harness) {
    wait_for(|| sent_len(h) >= 1).await;
    let (discover, dest) = sent_at(h, 0);
    assert_eq!(msg_type_of(&discover), Some(MessageType::Discover));
    assert_eq!(dest, Ipv4Addr::BROADCAST);
    let xid = discover.xid();

    assert!(matches!(runtime_now(h), V4Runtime::Dhcp(DhcpV4Runtime::Discovering { .. })));

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    offer.set_siaddr(SERVER_IP);
    h.tx.send(offer).await.unwrap();
    wait_for(|| sent_len(h) >= 2).await;
    let (request, dest) = sent_at(h, 1);
    assert_eq!(msg_type_of(&request), Some(MessageType::Request));
    assert_eq!(dest, Ipv4Addr::BROADCAST);

    assert_eq!(runtime_now(h), V4Runtime::Dhcp(DhcpV4Runtime::Requesting { offered_ip: OFFER_IP }));

    h.tx.send(ack_msg(xid, OFFER_IP, 100)).await.unwrap();
    wait_for(|| {
        h.ops_calls.lock().unwrap().iter().any(|c| {
            matches!(c, OpsCall::Apply { yiaddr, lease_time } if *yiaddr == OFFER_IP && *lease_time == 100)
        })
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn dora_binds_lease_and_raises_session() {
    let h = spawn_driver();
    complete_dora(&h).await;

    wait_for(|| {
        h.link_rx.borrow().session.is_up()
            && h.link_rx.borrow().session.v4_ip() == Some(IpAddr::V4(OFFER_IP))
    })
    .await;

    let modes = h.modes.lock().unwrap().clone();
    assert_eq!(modes.first(), Some(&true), "discovery must start in raw mode");
    assert!(!*modes.last().unwrap(), "Bound phase must switch to udp mode");
    assert_eq!(h.status.current(), ServiceStatus::Running);

    assert!(
        matches!(runtime_now(&h), V4Runtime::Dhcp(DhcpV4Runtime::Bound { ip, .. }) if ip == OFFER_IP)
    );

    shutdown(h).await;
}

#[tokio::test(start_paused = true)]
async fn renew_timer_fires_unicast_request() {
    let h = spawn_driver();
    complete_dora(&h).await;

    wait_for(|| modes_contains(&h, false)).await;
    tokio::time::advance(Duration::from_secs(50)).await;
    wait_for(|| sent_len(&h) >= 3).await;

    let (renew, dest) = sent_at(&h, 2);
    assert_eq!(msg_type_of(&renew), Some(MessageType::Request));
    assert_eq!(dest, SERVER_IP);
    assert!(renew.opts().get(OptionCode::RequestedIpAddress).is_none());
    assert_eq!(h.link_rx.borrow().session.v4_ip(), Some(IpAddr::V4(OFFER_IP)));

    shutdown(h).await;
}

#[tokio::test(start_paused = true)]
async fn nak_during_requesting_restarts_discover() {
    let h = spawn_driver();

    wait_for(|| sent_len(&h) >= 1).await;
    let (discover, _) = sent_at(&h, 0);
    let xid = discover.xid();

    let mut offer = server_msg(MessageType::Offer, xid);
    offer.set_yiaddr(OFFER_IP);
    h.tx.send(offer).await.unwrap();
    wait_for(|| sent_len(&h) >= 2).await;

    h.tx.send(server_msg(MessageType::Nak, xid)).await.unwrap();
    wait_for(|| sent_len(&h) >= 3).await;

    let (rediscover, dest) = sent_at(&h, 2);
    assert_eq!(msg_type_of(&rediscover), Some(MessageType::Discover));
    assert_eq!(dest, Ipv4Addr::BROADCAST);
    assert_ne!(rediscover.xid(), xid);
    assert!(!h.link_rx.borrow().session.is_up());
    // No address was ever applied, so the NAK must not release anything.
    assert!(!h.ops_calls.lock().unwrap().iter().any(|c| matches!(c, OpsCall::Release)));

    shutdown(h).await;
}

#[tokio::test(start_paused = true)]
async fn nak_during_renewing_releases_lease_and_drops_session() {
    let h = spawn_driver();
    complete_dora(&h).await;
    wait_for(|| modes_contains(&h, false)).await;

    tokio::time::advance(Duration::from_secs(50)).await;
    wait_for(|| sent_len(&h) >= 3).await;
    let (renew, _) = sent_at(&h, 2);
    assert_eq!(msg_type_of(&renew), Some(MessageType::Request));
    assert!(h.link_rx.borrow().session.is_up());

    h.tx.send(server_msg(MessageType::Nak, renew.xid())).await.unwrap();
    wait_for(|| h.ops_calls.lock().unwrap().iter().any(|c| matches!(c, OpsCall::Release))).await;
    wait_for(|| !h.link_rx.borrow().session.is_up()).await;

    shutdown(h).await;
}

#[tokio::test(start_paused = true)]
async fn stop_releases_lease_and_finalizes_status() {
    let h = spawn_driver();
    complete_dora(&h).await;
    wait_for(|| modes_contains(&h, false)).await;

    h.status.just_change_status(ServiceStatus::Stopping);
    let runtime = h.runtime.clone();
    h.task.await.unwrap();

    let calls = h.ops_calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().filter(|c| matches!(c, OpsCall::Release)).count(),
        1,
        "stop path must release the lease exactly once"
    );
    assert_eq!(calls.last(), Some(&OpsCall::Release), "release must be the final ops call");
    assert_eq!(h.status.current(), ServiceStatus::Stop);
    assert_eq!(**runtime.load(), V4Runtime::Stopped);
}
