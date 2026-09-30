use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::sys_service::route_service::LanRouteInfo;
use landscape_common::sys_service::route_service::LanRouteMode;
use landscape_common::sys_service::route_service::RouteTargetInfo;
use landscape_common::wan_service::pppd::PPPDConfig;
use landscape_common::wan_service::pppd::PPPoEPlugin;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::env::{PppIpv4State, PppRouteSink, PppdChild, PppdEnv, PppdTimings, SystemPppdEnv};
use super::supervisor::{PppSessionHealth, PppdRetryController, run_pppd_supervisor};
use super::{PppdConfigStore, create_pppd_thread};

const ATTACH: &str = "eth0";
const PPP: &str = "ppp0";

fn running_status() -> ServiceHandle {
    let status = ServiceHandle::new();
    status.just_change_status(ServiceStatus::Staring);
    status.just_change_status(ServiceStatus::Running);
    status
}

fn fast_timings() -> PppdTimings {
    PppdTimings {
        retry_base: Duration::from_millis(30),
        retry_max: Duration::from_millis(200),
        startup_timeout: Duration::from_millis(150),
        stop_grace: Duration::from_millis(30),
        stop_kill_wait: Duration::from_millis(30),
        poll_interval: Duration::from_millis(5),
    }
}

fn ready(last_octet: u8) -> PppIpv4State {
    PppIpv4State::Ready {
        ifindex: 7,
        local: Ipv4Addr::new(10, 0, 0, last_octet),
        peer: Ipv4Addr::new(10, 0, 0, 1),
    }
}

fn partial(last_octet: u8) -> PppIpv4State {
    PppIpv4State::Partial {
        ifindex: 7,
        local: Some(Ipv4Addr::new(10, 0, 0, last_octet)),
        peer: None,
    }
}

fn dummy_conf() -> PPPDConfig {
    PPPDConfig {
        default_route: true,
        peer_id: "user".to_string(),
        password: "pass".to_string(),
        ac: None,
        plugin: PPPoEPlugin::default(),
    }
}

async fn wait_until<F: FnMut() -> bool>(mut cond: F, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not satisfied within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

// ── fake process / environment ───────────────────────────────

#[derive(Clone, Copy, Default)]
struct FakeConfig {
    spawn_fail_times: usize,
    term_ignored: bool,
    panic_on_spawn: bool,
}

struct FakeState {
    spawn_count: usize,
    spawn_fail_remaining: usize,
    current_addr: PppIpv4State,
    addr_ready_calls: Vec<PppIpv4State>,
    cleanup_calls: usize,
    exits: Vec<CancellationToken>,
    signals: Vec<Vec<i32>>,
}

struct FakeEnv {
    config: FakeConfig,
    state: Arc<Mutex<FakeState>>,
    spawn_tx: mpsc::UnboundedSender<tokio::time::Instant>,
    spawn_rx: Mutex<Option<mpsc::UnboundedReceiver<tokio::time::Instant>>>,
}

impl FakeEnv {
    fn new(config: FakeConfig) -> Self {
        let (spawn_tx, spawn_rx) = mpsc::unbounded_channel();
        Self {
            config,
            state: Arc::new(Mutex::new(FakeState {
                spawn_count: 0,
                spawn_fail_remaining: config.spawn_fail_times,
                current_addr: PppIpv4State::Missing,
                addr_ready_calls: Vec::new(),
                cleanup_calls: 0,
                exits: Vec::new(),
                signals: Vec::new(),
            })),
            spawn_tx,
            spawn_rx: Mutex::new(Some(spawn_rx)),
        }
    }

    fn take_spawn_rx(&self) -> mpsc::UnboundedReceiver<tokio::time::Instant> {
        self.spawn_rx.lock().unwrap().take().expect("spawn rx taken twice")
    }

    fn set_addr(&self, state: PppIpv4State) {
        self.state.lock().unwrap().current_addr = state;
    }

    fn spawn_count(&self) -> usize {
        self.state.lock().unwrap().spawn_count
    }

    fn addr_ready_calls(&self) -> Vec<PppIpv4State> {
        self.state.lock().unwrap().addr_ready_calls.clone()
    }

    fn cleanup_calls(&self) -> usize {
        self.state.lock().unwrap().cleanup_calls
    }

    fn trigger_exit(&self, index: usize) {
        if let Some(token) = self.state.lock().unwrap().exits.get(index).cloned() {
            token.cancel();
        }
    }

    fn signals(&self, index: usize) -> Vec<i32> {
        self.state.lock().unwrap().signals.get(index).cloned().unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl PppdEnv for FakeEnv {
    async fn spawn(&self, _iface: &str) -> io::Result<Box<dyn PppdChild>> {
        if self.config.panic_on_spawn {
            panic!("fake spawn panic");
        }

        let mut state = self.state.lock().unwrap();
        state.spawn_count += 1;
        let _ = self.spawn_tx.send(tokio::time::Instant::now());
        if state.spawn_fail_remaining > 0 {
            state.spawn_fail_remaining -= 1;
            return Err(io::Error::other("fake spawn failure"));
        }

        let index = state.signals.len();
        let exit = CancellationToken::new();
        state.exits.push(exit.clone());
        state.signals.push(Vec::new());
        drop(state);

        Ok(Box::new(FakeChild {
            exit,
            term_ignored: self.config.term_ignored,
            index,
            state: self.state.clone(),
        }))
    }

    async fn poll_addr(&self, _iface: &str) -> PppIpv4State {
        self.state.lock().unwrap().current_addr.clone()
    }

    async fn on_addr_ready(&self, state: &PppIpv4State, _as_router: bool, _iface: &str) {
        self.state.lock().unwrap().addr_ready_calls.push(state.clone());
    }

    async fn cleanup(&self, _iface: &str, _as_router: bool) {
        self.state.lock().unwrap().cleanup_calls += 1;
    }
}

struct FakeChild {
    exit: CancellationToken,
    term_ignored: bool,
    index: usize,
    state: Arc<Mutex<FakeState>>,
}

#[async_trait::async_trait]
impl PppdChild for FakeChild {
    async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.exit.cancelled().await;
        Ok(ExitStatus::from_raw(0))
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.exit.is_cancelled() { Ok(Some(ExitStatus::from_raw(0))) } else { Ok(None) }
    }

    async fn signal_group(&self, signal: i32) -> io::Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            if let Some(v) = state.signals.get_mut(self.index) {
                v.push(signal);
            }
        }

        if signal == libc::SIGKILL || (signal == libc::SIGTERM && !self.term_ignored) {
            self.exit.cancel();
        }
        Ok(())
    }
}

fn spawn_supervisor(
    env: &Arc<FakeEnv>,
    status: ServiceHandle,
    timings: PppdTimings,
) -> tokio::task::JoinHandle<bool> {
    let env_dyn: Arc<dyn PppdEnv> = env.clone();
    tokio::spawn(run_pppd_supervisor(PPP.to_string(), true, status, env_dyn, timings))
}

// ── fake route sink / config store ───────────────────────────

#[derive(Debug, PartialEq)]
enum SinkCall {
    Bind { ifindex: u32, local: Ipv4Addr, peer: Ipv4Addr, mask: u8 },
    WanRoute { iface: String, info: RouteTargetInfo },
    LanRoute { iface: String, info: LanRouteInfo },
    AddDefault(String),
    DelDefault(String),
    RemoveWan(String),
    RemoveLan(String),
}

#[derive(Default)]
struct RecordingRouteSink {
    calls: Mutex<Vec<SinkCall>>,
}

impl RecordingRouteSink {
    fn take(&self) -> Vec<SinkCall> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

#[async_trait::async_trait]
impl PppRouteSink for RecordingRouteSink {
    fn bind_ipv4(&self, ifindex: u32, local: Ipv4Addr, peer: Ipv4Addr, mask: u8) {
        self.calls.lock().unwrap().push(SinkCall::Bind { ifindex, local, peer, mask });
    }

    async fn insert_wan_route(&self, iface: &str, info: RouteTargetInfo) {
        self.calls.lock().unwrap().push(SinkCall::WanRoute { iface: iface.to_string(), info });
    }

    async fn insert_lan_route(&self, iface: &str, info: LanRouteInfo) {
        self.calls.lock().unwrap().push(SinkCall::LanRoute { iface: iface.to_string(), info });
    }

    async fn add_default_route(&self, iface: &str) {
        self.calls.lock().unwrap().push(SinkCall::AddDefault(iface.to_string()));
    }

    async fn del_default_route(&self, iface: &str) {
        self.calls.lock().unwrap().push(SinkCall::DelDefault(iface.to_string()));
    }

    async fn remove_wan_route(&self, iface: &str) {
        self.calls.lock().unwrap().push(SinkCall::RemoveWan(iface.to_string()));
    }

    async fn remove_lan_route(&self, iface: &str) {
        self.calls.lock().unwrap().push(SinkCall::RemoveLan(iface.to_string()));
    }
}

#[derive(Default)]
struct ConfigStoreState {
    writes: usize,
    deletes: usize,
}

struct FakeConfigStore {
    write_fail: bool,
    state: Arc<Mutex<ConfigStoreState>>,
}

impl FakeConfigStore {
    fn new(write_fail: bool) -> Self {
        Self {
            write_fail,
            state: Arc::new(Mutex::new(ConfigStoreState::default())),
        }
    }

    fn writes(&self) -> usize {
        self.state.lock().unwrap().writes
    }

    fn deletes(&self) -> usize {
        self.state.lock().unwrap().deletes
    }
}

impl PppdConfigStore for FakeConfigStore {
    fn write(&self, _conf: &PPPDConfig, _attach: &str, _ppp: &str) -> Result<(), ()> {
        self.state.lock().unwrap().writes += 1;
        if self.write_fail { Err(()) } else { Ok(()) }
    }

    fn delete(&self, _conf: &PPPDConfig, _ppp: &str) {
        self.state.lock().unwrap().deletes += 1;
    }
}

// ── L1: pure logic ───────────────────────────────────────────

#[test]
fn backoff_grows_exponentially_and_caps() {
    let timings = PppdTimings::default();
    assert_eq!(timings.backoff(1), Duration::from_secs(4));
    assert_eq!(timings.backoff(2), Duration::from_secs(8));
    assert_eq!(timings.backoff(3), Duration::from_secs(16));
    assert_eq!(timings.backoff(100), Duration::from_secs(600));
    assert_eq!(timings.backoff(u32::MAX), Duration::from_secs(600));
}

#[test]
fn ppp_ipv4_state_classification() {
    assert_eq!(
        PppIpv4State::from_snapshot(Some((
            7,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        ))),
        ready(2)
    );
    assert!(ready(2).is_ready());

    let partial = PppIpv4State::from_snapshot(Some((7, Some(Ipv4Addr::new(10, 0, 0, 2)), None)));
    assert!(matches!(partial, PppIpv4State::Partial { .. }));
    assert!(!partial.is_ready());

    assert_eq!(PppIpv4State::from_snapshot(None), PppIpv4State::Missing);
}

#[test]
fn retry_controller_resets_after_healthy() {
    let timings = fast_timings();
    let mut controller = PppdRetryController::new();

    assert_eq!(controller.note_failure(&timings), timings.backoff(1));
    assert_eq!(controller.failure_count(), 1);
    assert_eq!(controller.note_failure(&timings), timings.backoff(2));
    assert_eq!(controller.failure_count(), 2);

    controller.note_healthy();
    assert_eq!(controller.failure_count(), 0);
    assert_eq!(controller.note_failure(&timings), timings.backoff(1));
}

#[test]
fn session_health_requires_reset_or_change() {
    let mut health = PppSessionHealth::new(PppIpv4State::Missing);
    assert!(!health.is_healthy());
    assert!(health.observe(&ready(2)));
    assert!(health.is_healthy());
    assert!(!health.observe(&ready(2)));

    let mut health = PppSessionHealth::new(ready(2));
    assert!(!health.observe(&ready(2)));
    assert!(!health.is_healthy());
    assert!(health.observe(&ready(3)));
}

// ── env route logic ──────────────────────────────────────────

#[tokio::test]
async fn system_env_ready_as_router_applies_bind_and_routes() {
    let sink = Arc::new(RecordingRouteSink::default());
    let dyn_sink: Arc<dyn PppRouteSink> = sink.clone();
    let env = SystemPppdEnv::with_sink(dyn_sink);

    env.on_addr_ready(&ready(2), true, PPP).await;
    let calls = sink.take();

    assert_eq!(
        calls[0],
        SinkCall::Bind {
            ifindex: 7,
            local: Ipv4Addr::new(10, 0, 0, 2),
            peer: Ipv4Addr::new(10, 0, 0, 1),
            mask: 32,
        }
    );
    match &calls[1] {
        SinkCall::WanRoute { iface, info } => {
            assert_eq!(iface, PPP);
            assert_eq!(info.ifindex, 7);
            assert_eq!(info.weight, 1);
            assert!(info.default_route);
            assert_eq!(info.iface_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
            assert_eq!(info.gateway_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        }
        other => panic!("unexpected call {other:?}"),
    }
    match &calls[2] {
        SinkCall::LanRoute { iface, info } => {
            assert_eq!(iface, PPP);
            assert_eq!(info.ifindex, 7);
            assert_eq!(info.prefix, 32);
            assert_eq!(info.mode, LanRouteMode::WanReachable);
            assert_eq!(info.iface_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        }
        other => panic!("unexpected call {other:?}"),
    }
    assert_eq!(calls[3], SinkCall::AddDefault(PPP.to_string()));
    assert_eq!(calls.len(), 4);
}

#[tokio::test]
async fn system_env_ready_non_router_clears_default() {
    let sink = Arc::new(RecordingRouteSink::default());
    let dyn_sink: Arc<dyn PppRouteSink> = sink.clone();
    let env = SystemPppdEnv::with_sink(dyn_sink);

    env.on_addr_ready(&ready(2), false, PPP).await;
    let calls = sink.take();

    match &calls[1] {
        SinkCall::WanRoute { info, .. } => assert!(!info.default_route),
        other => panic!("unexpected call {other:?}"),
    }
    assert_eq!(calls[3], SinkCall::DelDefault(PPP.to_string()));
}

#[tokio::test]
async fn system_env_ignores_non_ready() {
    let sink = Arc::new(RecordingRouteSink::default());
    let dyn_sink: Arc<dyn PppRouteSink> = sink.clone();
    let env = SystemPppdEnv::with_sink(dyn_sink);

    env.on_addr_ready(&PppIpv4State::Missing, true, PPP).await;
    env.on_addr_ready(&partial(2), true, PPP).await;

    assert!(sink.take().is_empty());
}

#[tokio::test]
async fn system_env_cleanup_depends_on_router_flag() {
    let sink = Arc::new(RecordingRouteSink::default());
    let dyn_sink: Arc<dyn PppRouteSink> = sink.clone();
    let env = SystemPppdEnv::with_sink(dyn_sink);

    env.cleanup(PPP, true).await;
    assert_eq!(
        sink.take(),
        vec![
            SinkCall::DelDefault(PPP.to_string()),
            SinkCall::RemoveWan(PPP.to_string()),
            SinkCall::RemoveLan(PPP.to_string()),
        ]
    );

    env.cleanup(PPP, false).await;
    assert_eq!(
        sink.take(),
        vec![SinkCall::RemoveWan(PPP.to_string()), SinkCall::RemoveLan(PPP.to_string()),]
    );
}

// ── L2: async supervisor ─────────────────────────────────────

#[tokio::test]
async fn normal_dial_then_graceful_stop() {
    let env = Arc::new(FakeEnv::new(FakeConfig::default()));
    let status = running_status();
    let task = spawn_supervisor(&env, status.clone(), fast_timings());

    wait_until(|| env.spawn_count() == 1, Duration::from_secs(1)).await;
    env.set_addr(ready(2));
    wait_until(|| env.addr_ready_calls() == vec![ready(2)], Duration::from_secs(1)).await;

    status.just_change_status(ServiceStatus::Stopping);
    let graceful = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("supervisor did not stop")
        .unwrap();

    assert!(graceful);
    assert_eq!(env.spawn_count(), 1);
    assert_eq!(env.cleanup_calls(), 1);
    assert!(env.signals(0).contains(&libc::SIGTERM));
    assert!(!env.signals(0).contains(&libc::SIGKILL));
}

#[tokio::test]
async fn unexpected_exit_redials_after_backoff() {
    let env = Arc::new(FakeEnv::new(FakeConfig::default()));
    let status = running_status();
    let task = spawn_supervisor(&env, status.clone(), fast_timings());

    wait_until(|| env.spawn_count() == 1, Duration::from_secs(1)).await;
    env.trigger_exit(0);
    wait_until(|| env.spawn_count() >= 2, Duration::from_secs(1)).await;

    status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap();
    assert_eq!(env.cleanup_calls(), 1);
}

#[tokio::test]
async fn startup_timeout_triggers_restart() {
    let env = Arc::new(FakeEnv::new(FakeConfig::default()));
    let status = running_status();
    let task = spawn_supervisor(&env, status.clone(), fast_timings());

    // Child never exits and address never becomes ready -> startup timeout.
    wait_until(|| env.spawn_count() >= 2, Duration::from_secs(2)).await;

    status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap();
    assert_eq!(env.cleanup_calls(), 1);
}

#[tokio::test]
async fn spawn_failures_retry_with_backoff() {
    let env = Arc::new(FakeEnv::new(FakeConfig { spawn_fail_times: 2, ..FakeConfig::default() }));
    let status = running_status();
    let task = spawn_supervisor(&env, status.clone(), fast_timings());

    wait_until(|| env.spawn_count() >= 3, Duration::from_secs(2)).await;

    status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap();
    assert_eq!(env.cleanup_calls(), 1);
}

#[tokio::test]
async fn stop_during_backoff_does_not_respawn() {
    let env = Arc::new(FakeEnv::new(FakeConfig { spawn_fail_times: 1, ..FakeConfig::default() }));
    let status = running_status();
    let timings = PppdTimings {
        retry_base: Duration::from_secs(5),
        ..fast_timings()
    };
    let task = spawn_supervisor(&env, status.clone(), timings);

    wait_until(|| env.spawn_count() == 1, Duration::from_secs(1)).await;
    status.just_change_status(ServiceStatus::Stopping);

    let graceful = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("stop during backoff should return promptly")
        .unwrap();

    assert!(graceful);
    assert_eq!(env.spawn_count(), 1);
    assert_eq!(env.cleanup_calls(), 1);
}

#[tokio::test]
async fn stop_during_backoff_after_session_end_does_not_respawn() {
    let env = Arc::new(FakeEnv::new(FakeConfig::default()));
    let status = running_status();
    let timings = PppdTimings {
        retry_base: Duration::from_secs(5),
        ..fast_timings()
    };
    let task = spawn_supervisor(&env, status.clone(), timings);

    wait_until(|| env.spawn_count() == 1, Duration::from_secs(1)).await;
    env.trigger_exit(0);
    tokio::time::sleep(Duration::from_millis(50)).await;

    status.just_change_status(ServiceStatus::Stopping);
    let graceful = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("stop during backoff should return promptly")
        .unwrap();

    assert!(graceful);
    assert_eq!(env.spawn_count(), 1);
    assert_eq!(env.cleanup_calls(), 1);
}

#[tokio::test]
async fn address_changes_are_applied_idempotently() {
    let env = Arc::new(FakeEnv::new(FakeConfig::default()));
    let status = running_status();
    let task = spawn_supervisor(&env, status.clone(), fast_timings());

    wait_until(|| env.spawn_count() == 1, Duration::from_secs(1)).await;

    env.set_addr(ready(2));
    wait_until(|| env.addr_ready_calls().len() == 1, Duration::from_secs(1)).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(env.addr_ready_calls().len(), 1, "same address must not re-apply");

    env.set_addr(ready(3));
    wait_until(|| env.addr_ready_calls().len() == 2, Duration::from_secs(1)).await;

    env.set_addr(PppIpv4State::Missing);
    tokio::time::sleep(Duration::from_millis(20)).await;
    env.set_addr(ready(2));
    wait_until(|| env.addr_ready_calls().len() == 3, Duration::from_secs(1)).await;

    status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap();
    assert_eq!(env.cleanup_calls(), 1);
}

#[tokio::test]
async fn missing_partial_ready_transition_applies_once() {
    let env = Arc::new(FakeEnv::new(FakeConfig::default()));
    let status = running_status();
    let task = spawn_supervisor(&env, status.clone(), fast_timings());

    wait_until(|| env.spawn_count() == 1, Duration::from_secs(1)).await;

    env.set_addr(partial(2));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(env.addr_ready_calls().is_empty());

    env.set_addr(ready(2));
    wait_until(|| env.addr_ready_calls().len() == 1, Duration::from_secs(1)).await;

    status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap();
    assert_eq!(env.cleanup_calls(), 1);
}

#[tokio::test]
async fn sigterm_ignored_escalates_to_sigkill() {
    let env = Arc::new(FakeEnv::new(FakeConfig { term_ignored: true, ..FakeConfig::default() }));
    let status = running_status();
    let task = spawn_supervisor(&env, status.clone(), fast_timings());

    wait_until(|| env.spawn_count() == 1, Duration::from_secs(1)).await;
    status.just_change_status(ServiceStatus::Stopping);

    let graceful = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("supervisor did not stop")
        .unwrap();

    assert!(graceful);
    assert_eq!(env.cleanup_calls(), 1);
    assert_eq!(env.signals(0), vec![libc::SIGTERM, libc::SIGKILL]);
}

// ── L2: deterministic timing (paused clock) ──────────────────

#[tokio::test(start_paused = true)]
async fn backoff_durations_are_exact_and_capped() {
    let env = Arc::new(FakeEnv::new(FakeConfig { spawn_fail_times: 5, ..FakeConfig::default() }));
    let mut spawn_rx = env.take_spawn_rx();
    let status = running_status();
    let task = spawn_supervisor(&env, status.clone(), fast_timings());

    let mut times = Vec::new();
    for _ in 0..6 {
        times.push(spawn_rx.recv().await.expect("spawn notification"));
    }

    assert_eq!(times[1] - times[0], Duration::from_millis(30));
    assert_eq!(times[2] - times[1], Duration::from_millis(60));
    assert_eq!(times[3] - times[2], Duration::from_millis(120));
    assert_eq!(times[4] - times[3], Duration::from_millis(200));
    assert_eq!(times[5] - times[4], Duration::from_millis(200));

    status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap();
    assert_eq!(env.cleanup_calls(), 1);
}

// ── L2: panic handling ───────────────────────────────────────

#[tokio::test]
async fn supervisor_panic_returns_false_and_cleans() {
    let env = Arc::new(FakeEnv::new(FakeConfig { panic_on_spawn: true, ..FakeConfig::default() }));
    let status = running_status();

    let graceful = tokio::time::timeout(
        Duration::from_secs(2),
        spawn_supervisor(&env, status, fast_timings()),
    )
    .await
    .expect("supervisor did not stop")
    .unwrap();

    assert!(!graceful);
    assert_eq!(env.cleanup_calls(), 1);
}

// ── lifecycle (create_pppd_thread) ───────────────────────────

#[tokio::test]
async fn lifecycle_normal_stop_sets_stop_and_deletes_config() {
    let env = Arc::new(FakeEnv::new(FakeConfig::default()));
    let store = Arc::new(FakeConfigStore::new(false));
    let status = ServiceHandle::new();

    let env_dyn: Arc<dyn PppdEnv> = env.clone();
    let store_dyn: Arc<dyn PppdConfigStore> = store.clone();
    let task = tokio::spawn(create_pppd_thread(
        ATTACH.to_string(),
        PPP.to_string(),
        dummy_conf(),
        status.clone(),
        env_dyn,
        store_dyn,
    ));

    tokio::time::timeout(
        Duration::from_secs(1),
        status.wait_for(|s| matches!(s, ServiceStatus::Running)),
    )
    .await
    .expect("service did not reach Running");
    assert_eq!(env.spawn_count(), 1);

    status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap();

    assert_eq!(status.current(), ServiceStatus::Stop);
    assert_eq!(store.writes(), 1);
    assert_eq!(store.deletes(), 1);
    assert_eq!(env.cleanup_calls(), 1);
}

#[tokio::test]
async fn config_write_failure_sets_failed_without_side_effects() {
    let env = Arc::new(FakeEnv::new(FakeConfig::default()));
    let store = Arc::new(FakeConfigStore::new(true));
    let status = ServiceHandle::new();

    let env_dyn: Arc<dyn PppdEnv> = env.clone();
    let store_dyn: Arc<dyn PppdConfigStore> = store.clone();
    create_pppd_thread(
        ATTACH.to_string(),
        PPP.to_string(),
        dummy_conf(),
        status.clone(),
        env_dyn,
        store_dyn,
    )
    .await;

    assert_eq!(status.current(), ServiceStatus::Failed);
    assert_eq!(store.writes(), 1);
    assert_eq!(store.deletes(), 0);
    assert_eq!(env.spawn_count(), 0);
    assert_eq!(env.cleanup_calls(), 0);
}

#[tokio::test]
async fn supervisor_panic_sets_failed_and_cleans_up() {
    let env = Arc::new(FakeEnv::new(FakeConfig { panic_on_spawn: true, ..FakeConfig::default() }));
    let store = Arc::new(FakeConfigStore::new(false));
    let status = ServiceHandle::new();

    let env_dyn: Arc<dyn PppdEnv> = env.clone();
    let store_dyn: Arc<dyn PppdConfigStore> = store.clone();
    create_pppd_thread(
        ATTACH.to_string(),
        PPP.to_string(),
        dummy_conf(),
        status.clone(),
        env_dyn,
        store_dyn,
    )
    .await;

    assert_eq!(status.current(), ServiceStatus::Failed);
    assert_eq!(env.cleanup_calls(), 1);
    assert_eq!(store.deletes(), 1);
}
