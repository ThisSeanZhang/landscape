use std::{
    collections::BTreeMap,
    future::pending,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use arc_swap::ArcSwapOption;
use landscape_common::{
    concurrency::task_label,
    flow::{DnsListenerRole, FlowSocketRegistrar},
    sys_config::DohRuntimeConfig,
};
use rustls::server::ResolvesServerCert;
use tokio::sync::watch;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::{DohTimeouts, create_tcp_listener, doh, spawn_tracked, tcp};
use crate::server::handler::DnsRequestHandler;

#[derive(Clone)]
pub struct DohSettings {
    pub config: watch::Receiver<DohRuntimeConfig>,
    pub cert_resolver: Arc<dyn ResolvesServerCert>,
}

/// A single DHCP/DDR advertisement covers all active flows.
#[derive(Clone, Default)]
pub(crate) struct DohReadiness {
    state: Arc<Mutex<ReadinessState>>,
    pub advertised: Arc<ArcSwapOption<DohRuntimeConfig>>,
}

#[derive(Default)]
struct ReadinessState {
    flows: BTreeMap<u32, Option<BoundEndpoint>>,
    stopped: bool,
}

struct BoundEndpoint {
    requested_port: u16,
    endpoint: DohRuntimeConfig,
}

impl DohReadiness {
    pub fn set_running(&self, running: bool) {
        let mut state = self.state.lock().unwrap();
        state.stopped = !running;
        self.publish(&state);
    }

    fn update(&self, change: impl FnOnce(&mut BTreeMap<u32, Option<BoundEndpoint>>)) {
        let mut state = self.state.lock().unwrap();
        change(&mut state.flows);
        self.publish(&state);
    }

    fn publish(&self, state: &ReadinessState) {
        let mut endpoints = state.flows.values().map(|bound| bound.as_ref().map(|b| &b.endpoint));
        let common = endpoints
            .next()
            .flatten()
            .filter(|endpoint| !state.stopped && endpoints.all(|other| other == Some(*endpoint)));
        self.advertised.store(common.cloned().map(Arc::new));
    }
}

#[derive(Clone, Default)]
pub(crate) struct FlowListeners {
    pub doh: Option<DohSettings>,
    pub readiness: DohReadiness,
    pub tcp_error: Arc<ArcSwapOption<String>>,
    pub doh_error: Arc<ArcSwapOption<String>>,
}

impl FlowListeners {
    pub fn start(
        &self,
        flow_id: u32,
        addr: SocketAddr,
        handler: DnsRequestHandler,
        registrar: Arc<dyn FlowSocketRegistrar>,
        parent: &CancellationToken,
        tracker: &TaskTracker,
    ) {
        let tcp = Transport::Tcp(addr);
        tcp.supervise(
            flow_id,
            handler.clone(),
            registrar.clone(),
            parent,
            tracker,
            self.tcp_error.clone(),
        );
        if let Some(settings) = self.doh.clone() {
            self.readiness.update(|flows| {
                flows.insert(flow_id, None);
            });
            let doh = Transport::Doh { settings, readiness: self.readiness.clone(), addr };
            doh.supervise(flow_id, handler, registrar, parent, tracker, self.doh_error.clone());
        }
    }
}

enum Transport {
    Tcp(SocketAddr),
    Doh { settings: DohSettings, readiness: DohReadiness, addr: SocketAddr },
}

impl Transport {
    fn withdraw(&self, flow_id: u32) {
        if let Self::Doh { readiness, .. } = self {
            readiness.update(|flows| {
                flows.insert(flow_id, None);
            });
        }
    }

    async fn changed(&mut self) {
        if let Self::Doh { settings, .. } = self
            && settings.config.changed().await.is_ok()
        {
            return;
        }
        // TCP has fixed settings. A closed DoH channel retains its last configuration.
        pending().await
    }

    fn start(
        &mut self,
        flow_id: u32,
        handler: DnsRequestHandler,
        registrar: &dyn FlowSocketRegistrar,
        token: &CancellationToken,
        tasks: &TaskTracker,
    ) -> io::Result<()> {
        match self {
            Self::Tcp(addr) => {
                let (listener, fd) = create_tcp_listener(*addr)?;
                registrar
                    .register_dns_socket(flow_id, fd, DnsListenerRole::Tcp)
                    .map_err(io::Error::other)?;
                tcp::spawn_tcp_listener(flow_id, listener, handler, token.clone(), tasks.clone());
            }
            Self::Doh { settings, readiness, addr } => {
                let desired = settings.config.borrow_and_update().clone();
                let mut state = readiness.state.lock().unwrap();
                // Port zero selects one kernel-assigned port for the whole reuseport group.
                let port = if desired.listen_port == 0 {
                    state
                        .flows
                        .values()
                        .flatten()
                        .find(|bound| bound.requested_port == 0)
                        .map_or(0, |bound| bound.endpoint.listen_port)
                } else {
                    desired.listen_port
                };
                let (listener, fd) = create_tcp_listener(SocketAddr::new(addr.ip(), port))?;
                let actual_port = listener.local_addr()?.port();
                registrar
                    .register_dns_socket(flow_id, fd, DnsListenerRole::Doh)
                    .map_err(io::Error::other)?;
                doh::spawn_doh_listener(
                    flow_id,
                    listener,
                    doh::DohListenerConfig {
                        timeouts: DohTimeouts::default(),
                        server_cert_resolver: settings.cert_resolver.clone(),
                        dns_hostname: None,
                        http_endpoint: desired.http_endpoint.clone(),
                    },
                    handler,
                    token.clone(),
                    tasks.clone(),
                )?;
                state.flows.insert(
                    flow_id,
                    Some(BoundEndpoint {
                        requested_port: desired.listen_port,
                        endpoint: DohRuntimeConfig { listen_port: actual_port, ..desired },
                    }),
                );
                readiness.publish(&state);
            }
        }
        Ok(())
    }

    fn supervise(
        mut self,
        flow_id: u32,
        handler: DnsRequestHandler,
        registrar: Arc<dyn FlowSocketRegistrar>,
        parent: &CancellationToken,
        tracker: &TaskTracker,
        error: Arc<ArcSwapOption<String>>,
    ) {
        let role = match &self {
            Self::Tcp(_) => DnsListenerRole::Tcp,
            Self::Doh { .. } => DnsListenerRole::Doh,
        };
        let parent = parent.clone();
        let owner = parent.clone();
        let bind = move |transport: &mut Self| {
            let token = owner.child_token();
            let tasks = TaskTracker::new();
            let result =
                transport.start(flow_id, handler.clone(), registrar.as_ref(), &token, &tasks);
            tasks.close();
            (result, token, tasks)
        };
        // Bind before returning so a successful start already accepts connections.
        let mut attempt = bind(&mut self);
        spawn_tracked(tracker, task_label::task::DNS_LISTENER_SERVE, async move {
            let mut delay = Duration::from_secs(1);
            loop {
                let (result, token, tasks) = attempt;
                let failure = match result {
                    Ok(()) => {
                        error.store(None);
                        let reconfigure = tokio::select! {
                            biased;
                            _ = token.cancelled() => false,
                            _ = self.changed() => true,
                            _ = tasks.wait() => false,
                        };
                        self.withdraw(flow_id);
                        token.cancel();
                        if tokio::time::timeout(Duration::from_secs(5), tasks.wait()).await.is_err()
                        {
                            error.store(Some(Arc::new("Listener shutdown timed out".into())));
                            tasks.wait().await;
                        }
                        if reconfigure {
                            None
                        } else {
                            Some("Listener exited unexpectedly".to_owned())
                        }
                    }
                    Err(e) => Some(e.to_string()),
                };
                if parent.is_cancelled() {
                    break;
                }
                if let Some(detail) = failure {
                    tracing::warn!(flow_id, ?role, %detail, "DNS transport will retry");
                    error.store(Some(Arc::new(detail)));
                    tokio::select! {
                        biased;
                        _ = parent.cancelled() => break,
                        _ = self.changed() => delay = Duration::from_secs(1),
                        _ = tokio::time::sleep(delay) => delay = (delay * 2).min(Duration::from_secs(30)),
                    }
                } else {
                    delay = Duration::from_secs(1);
                }
                attempt = bind(&mut self);
            }
            if let Self::Doh { readiness, .. } = self {
                readiness.update(|flows| {
                    flows.remove(&flow_id);
                });
            }
        });
    }
}
