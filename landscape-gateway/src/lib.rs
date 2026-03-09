pub mod proxy_service;
pub mod service;
pub mod sni_proxy;

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use arc_swap::ArcSwap;
use landscape_common::config::gateway::config::GatewayRuntimeConfig;
use landscape_common::config::gateway::HttpUpstreamRuleConfig;

use landscape_common::service::{ServiceStatus, WatchService};

pub type SharedRules = Arc<ArcSwap<Vec<HttpUpstreamRuleConfig>>>;

pub struct GatewayManager {
    rules: SharedRules,
    status: WatchService,
    state: Mutex<Option<JoinHandle<()>>>,
    config: GatewayRuntimeConfig,
}

impl GatewayManager {
    pub fn new(initial_rules: Vec<HttpUpstreamRuleConfig>, config: GatewayRuntimeConfig) -> Self {
        Self {
            rules: Arc::new(ArcSwap::new(Arc::new(initial_rules))),
            status: WatchService::new(),
            state: Mutex::new(None),
            config,
        }
    }

    pub fn shared_rules(&self) -> SharedRules {
        self.rules.clone()
    }

    pub fn reload_rules(&self, new_rules: Vec<HttpUpstreamRuleConfig>) {
        self.rules.store(Arc::new(new_rules));
        tracing::info!("Gateway rules reloaded ({} rules)", self.rules.load().len());
    }

    pub fn start(&self) {
        let mut state = self.state.lock().unwrap();
        if self.status.is_running() {
            tracing::warn!("Gateway is already running");
            return;
        }

        self.status.just_change_status(ServiceStatus::Staring);

        let rules = self.rules.clone();
        let http_port = self.config.http_port;
        let status = self.status.clone();

        let handle = std::thread::spawn(move || {
            run_pingora_server(rules, http_port, status);
        });

        *state = Some(handle);
        self.status.just_change_status(ServiceStatus::Running);
        tracing::info!("Gateway started on HTTP port {}", self.config.http_port);
    }

    /// Signal gateway to stop (non-blocking). The thread will actually be
    /// joined when the GatewayManager is dropped (or join() is called).
    pub fn shutdown(&self) {
        if self.status.is_exit() {
            return;
        }
        tracing::info!("Signalling gateway to stop...");
        self.status.just_change_status(ServiceStatus::Stopping);
    }

    /// Block until the Pingora thread has exited. Call after shutdown().
    pub fn join(&self) {
        let mut state = self.state.lock().unwrap();
        if let Some(handle) = state.take() {
            tracing::info!("Waiting for gateway thread to finish...");
            if let Err(e) = handle.join() {
                tracing::error!("Gateway thread panicked: {:?}", e);
            }
            self.status.just_change_status(ServiceStatus::Stop);
            tracing::info!("Gateway stopped");
        }
    }

    pub fn is_running(&self) -> bool {
        self.status.is_running()
    }

    pub fn status(&self) -> ServiceStatus {
        self.status.subscribe().borrow().clone()
    }

    pub fn watch_service(&self) -> WatchService {
        self.status.clone()
    }

    pub fn config(&self) -> &GatewayRuntimeConfig {
        &self.config
    }
}

impl Drop for GatewayManager {
    fn drop(&mut self) {
        self.shutdown();
        self.join();
    }
}

fn run_pingora_server(rules: SharedRules, http_port: u16, status: WatchService) {
    use pingora::server::Server;
    use proxy_service::LandscapeReverseProxy;

    let mut server = Server::new(None).expect("Failed to create Pingora server");
    server.bootstrap();

    let proxy = LandscapeReverseProxy::new(rules);
    let mut http_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    http_service.add_tcp(&format!("0.0.0.0:{http_port}"));
    server.add_service(http_service);

    let run_args = pingora::server::RunArgs {
        shutdown_signal: Box::new(ChannelShutdownWatch { status }),
    };
    server.run(run_args);
}

struct ChannelShutdownWatch {
    status: WatchService,
}

#[async_trait::async_trait]
impl pingora::server::ShutdownSignalWatch for ChannelShutdownWatch {
    async fn recv(&self) -> pingora::server::ShutdownSignal {
        if self.status.is_exit() {
            return pingora::server::ShutdownSignal::FastShutdown;
        }
        let mut rx = self.status.subscribe();
        loop {
            if rx.changed().await.is_err() {
                // Sender dropped, treat as fast shutdown
                return pingora::server::ShutdownSignal::FastShutdown;
            }
            if matches!(*rx.borrow(), ServiceStatus::Stopping | ServiceStatus::Stop) {
                return pingora::server::ShutdownSignal::FastShutdown;
            }
        }
    }
}
