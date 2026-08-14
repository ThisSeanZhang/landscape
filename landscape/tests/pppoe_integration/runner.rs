use super::cmd::enter_netns;
use super::env::{ClientConfig, ClientIfaceInfo};
use landscape::pppoe_client::{self, PPPoEClientConfig};
use landscape_common::service::{ServiceStatus, WatchService};
use std::time::Duration;

// ── client runner ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExpectOutcome {
    /// Client should reach Running and exit successfully.
    Running,
    /// Client should fail WITHOUT ever reaching Running.
    Failure,
    /// Client should reach Running and then later fail/stop.
    FailedAfterRunning { post_run_timeout_secs: u64 },
    /// Client should reach Running, then be triggered to stop gracefully,
    /// and exit with Stop status.
    Stop,
}

/// Run the PPPoE client **inside the client network namespace** and wait for
/// the expected outcome.
///
/// A dedicated OS thread enters the namespace via `setns(2)`, creates its own
/// tokio runtime, and runs `create_pppoe_client` there.  The main thread
/// monitors the shared `WatchService` for status transitions.
///
/// If `on_running` is provided it is called (exactly once) when the client
/// reaches `ServiceStatus::Running`, before the outcome is evaluated.  This
/// lets tests inject side-effects such as tearing down the server link.
pub(super) async fn run_client(
    client_ns: &str,
    client_info: &ClientIfaceInfo,
    cfg: &ClientConfig,
    expect: ExpectOutcome,
    on_running: Option<Box<dyn FnOnce() + Send>>,
) -> Result<(), String> {
    let client_cfg = PPPoEClientConfig::new(
        client_info.index,
        client_info.name.clone(),
        client_info.mac,
        cfg.username.clone(),
        cfg.password.clone(),
        cfg.default_router,
        cfg.mtu,
        None,
    );

    let service_status = WatchService::new();
    let service_status_for_task = service_status.clone();
    let mut status_rx = service_status.subscribe();

    let ns_name = client_ns.to_string();

    // Spawn a dedicated OS thread that enters the client namespace and runs
    // the PPPoE client there.  `setns(2)` only affects the calling thread,
    // so the main thread stays in the host namespace.
    let client_handle = std::thread::spawn(move || {
        enter_netns(&ns_name).expect("enter client netns");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime in client ns");
        rt.block_on(async {
            pppoe_client::create_pppoe_client(client_cfg, service_status_for_task, None).await;
        });
    });

    let timeout = tokio::time::sleep(Duration::from_secs(cfg.timeout_secs));
    tokio::pin!(timeout);

    // `post_run_dur` is only meaningful for `FailedAfterRunning`; the
    // select! guard (`matches!(expect, FailedAfterRunning { .. })`) keeps
    // the arm inactive for other modes regardless of the duration value.
    let post_run_dur = match expect {
        ExpectOutcome::FailedAfterRunning { post_run_timeout_secs } => {
            Duration::from_secs(post_run_timeout_secs)
        }
        _ => Duration::ZERO,
    };
    let post_run_timeout = tokio::time::sleep(post_run_dur);
    tokio::pin!(post_run_timeout);
    let mut seen_running = false;
    let mut on_running = on_running;

    // The select loop monitors the client status.  Instead of `return`-ing
    // directly we `break` with a value so we can join the client thread
    // afterwards and propagate any panic.
    let outcome: Result<(), String> = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break Err("received Ctrl-C".into());
            }
            _ = &mut timeout, if !seen_running => {
                // `seen_running` is still false → the client never reached
                // Running.  This is only expected for `Failure` mode.
                if expect == ExpectOutcome::Failure {
                    break Ok(());
                }
                break Err("timed out waiting for PPPoE connection".into());
            }
            _ = &mut post_run_timeout, if seen_running && matches!(expect, ExpectOutcome::FailedAfterRunning { .. }) => {
                break Err("connection did not fail within post-run timeout".into());
            }
            change_result = status_rx.changed() => {
                if change_result.is_err() {
                    break Err("status channel closed unexpectedly".into());
                }
                let current = status_rx.borrow().clone();
                match current {
                    ServiceStatus::Running => {
                        seen_running = true;
                        if let Some(cb) = on_running.take() {
                            cb();
                        }
                        match expect {
                            ExpectOutcome::Running => {
                                service_status.just_change_status(ServiceStatus::Stopping);
                            }
                            ExpectOutcome::Failure => {
                                break Err("client reached Running but expected Failure".into());
                            }
                            ExpectOutcome::Stop => {
                                // Trigger a graceful client stop.
                                service_status.just_change_status(ServiceStatus::Stopping);
                            }
                            ExpectOutcome::FailedAfterRunning { .. } => {
                                post_run_timeout.as_mut().reset(
                                    tokio::time::Instant::now() + post_run_dur,
                                );
                            }
                        }
                    }
                    ServiceStatus::Failed => {
                        if matches!(expect, ExpectOutcome::FailedAfterRunning { .. })
                            || (expect == ExpectOutcome::Failure && !seen_running)
                        {
                            break Ok(());
                        }
                        break Err("client reached Failed unexpectedly".into());
                    }
                    ServiceStatus::Stop => {
                        if ((matches!(expect, ExpectOutcome::FailedAfterRunning { .. })
                            || expect == ExpectOutcome::Running)
                            && seen_running)
                            || (expect == ExpectOutcome::Stop && seen_running)
                        {
                            break Ok(());
                        }
                    }
                    ServiceStatus::Staring | ServiceStatus::Stopping => {}
                }
            }
        }
    };

    // Propagate any panic from the client thread so it isn't silently lost.
    match client_handle.join() {
        Ok(()) => {}
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".into()
            };
            return Err(format!("client thread panicked: {msg}"));
        }
    }

    outcome
}
