use super::cmd::enter_netns;
use super::env::ClientIfaceInfo;
use landscape::sys_service::route::IpRouteService;
use landscape::wan_service::pppoe_client::{PPPoEClientConfig, run};
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_ebpf::runtime::EbpfRuntime;
use std::sync::Arc;
use std::time::Duration;

// ── client spec ──────────────────────────────────────────────────────────────

pub(super) struct ClientSpec {
    pub(super) username: String,
    pub(super) password: String,
    pub(super) mtu: u16,
    /// LCP echo interval override (`lcp_echo_interval`); `None` = default.
    pub(super) echo_interval_secs: Option<u64>,
    /// Redial backoff base override (`redial_backoff_base_secs`); `None` =
    /// default 300 s.
    pub(super) redial_backoff_base_secs: Option<u64>,
}

// ── client runner ────────────────────────────────────────────────────────────

pub(super) struct ClientHandle {
    pub(super) status: ServiceHandle,
    done_rx: std::sync::mpsc::Receiver<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ClientHandle {
    /// Request a graceful stop and wait for the client task to finish.
    pub(super) fn stop_and_join(mut self, timeout: Duration) -> Result<(), String> {
        if !self.status.is_exit() {
            self.status.just_change_status(ServiceStatus::Stopping);
        }
        self.join_inner(timeout)
    }

    /// Wait for the client task to finish WITHOUT requesting a stop (for
    /// clients that are expected to exit on their own).
    pub(super) fn join(mut self, timeout: Duration) -> Result<(), String> {
        self.join_inner(timeout)
    }

    fn join_inner(&mut self, timeout: Duration) -> Result<(), String> {
        self.done_rx
            .recv_timeout(timeout)
            .map_err(|e| format!("client task did not finish within {timeout:?}: {e}"))?;
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "client thread panicked".to_string())?;
        }
        Ok(())
    }
}

/// Spawn the REAL PPPoE client (`wan_service::pppoe_client::run`) inside the
/// client network namespace.  `setns(2)` only affects the calling thread, so
/// the client runs on a dedicated OS thread with its own single-threaded
/// tokio runtime; the returned handle lets the (host-side) test thread steer
/// and observe the shared `ServiceHandle`.  `scenario` selects the client's
/// isolated eBPF map space so parallel scenarios never share one.
pub(super) fn start_client(
    client_ns: &str,
    scenario: &str,
    info: &ClientIfaceInfo,
    spec: &ClientSpec,
) -> ClientHandle {
    let status = ServiceHandle::new();
    // Move to `Staring` synchronously before spawning so observers can never
    // mistake the watch channel's initial `Stop` value for a terminal state
    // (run() also sets `Staring`, which is then a harmless no-op warning).
    status.just_change_status(ServiceStatus::Staring);
    let status_for_task = status.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let ns = client_ns.to_string();
    let scenario = scenario.to_string();
    let cfg = PPPoEClientConfig {
        index: info.index,
        iface_name: info.name.clone(),
        iface_mac: info.mac,
        peer_id: spec.username.clone(),
        password: spec.password.clone(),
        default_router: false,
        requested_mru: spec.mtu,
        ac_name: None,
        lcp_echo_interval: spec.echo_interval_secs,
        redial_backoff_base_secs: spec.redial_backoff_base_secs,
    };

    let thread = std::thread::spawn(move || {
        enter_netns(&ns).expect("enter client netns");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime in client ns");
        rt.block_on(async move {
            let ebpf_rt = Arc::new(
                EbpfRuntime::init(&super::test_bpf_map_space(&scenario), None)
                    .expect("ebpf runtime in client ns"),
            );
            let route_service = IpRouteService::new(ebpf_rt.clone().route_table());
            run(cfg, status_for_task, route_service, ebpf_rt.pppoe_dataplane(), None).await;
        });

        let _ = done_tx.send(());
    });

    ClientHandle { status, done_rx, thread: Some(thread) }
}

// ── status observation ───────────────────────────────────────────────────────

#[derive(Debug)]
pub(super) struct StatusOutcome {
    pub(super) ever_running: bool,
    pub(super) final_status: ServiceStatus,
}

/// Wait until the service reaches `Running`.
pub(super) async fn wait_for_running(
    status: &ServiceHandle,
    timeout: Duration,
) -> Result<(), String> {
    tokio::time::timeout(timeout, status.wait_for(|s| matches!(s, ServiceStatus::Running)))
        .await
        .map_err(|_| format!("client did not reach Running within {timeout:?}"))
}

/// Wait until the service reaches a terminal state (`Stop` or `Failed`).
pub(super) async fn wait_for_exit(
    status: &ServiceHandle,
    timeout: Duration,
) -> Result<StatusOutcome, String> {
    tokio::time::timeout(timeout, async {
        let mut ever_running = false;
        loop {
            let current = status.current();
            match current {
                ServiceStatus::Running => ever_running = true,
                ServiceStatus::Stop | ServiceStatus::Failed => {
                    return StatusOutcome { ever_running, final_status: current };
                }
                _ => {}
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| format!("client did not reach a terminal state within {timeout:?}"))
}
