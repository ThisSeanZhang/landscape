use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use landscape_common::route::LanRouteInfo;
use landscape_common::route::LanRouteMode;
use landscape_common::route::RouteTargetInfo;
use tokio::sync::{oneshot, watch};

use landscape_common::database::LandscapeStore;
use landscape_common::global_const::default_router::RouteInfo;
use landscape_common::global_const::default_router::RouteType;
use landscape_common::global_const::default_router::LD_ALL_ROUTERS;
use landscape_common::iface::ppp::PPPDConfig;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::manager::ServiceManager;
use landscape_common::service::ServiceStatus;
use landscape_common::{
    concurrency::{
        short_thread_name, spawn_named_thread, spawn_task_with_resource, task_label, thread_name,
    },
    iface::ppp::PPPDServiceConfig,
    service::{manager::ServiceStarterTrait, WatchService},
};
use landscape_database::pppd::repository::PPPDServiceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;

use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;

const PPPD_RETRY_BASE_SECS: u64 = 4;
const PPPD_RETRY_MAX_SECS: u64 = 10 * 60;
const PPPD_STARTUP_TIMEOUT_SECS: u64 = 90;
const PPPD_STOP_GRACE_SECS: u64 = 5;
const PPPD_STOP_KILL_WAIT_SECS: u64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
enum PppIpv4State {
    Missing,
    Partial { ifindex: u32, local: Option<Ipv4Addr>, peer: Option<Ipv4Addr> },
    Ready { ifindex: u32, local: Ipv4Addr, peer: Ipv4Addr },
}

impl PppIpv4State {
    fn from_snapshot(ip4addr: Option<(u32, Option<Ipv4Addr>, Option<Ipv4Addr>)>) -> Self {
        match ip4addr {
            Some((ifindex, Some(local), Some(peer))) => Self::Ready { ifindex, local, peer },
            Some((ifindex, local, peer)) => Self::Partial { ifindex, local, peer },
            None => Self::Missing,
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

fn calc_pppd_retry_backoff_secs(failure_count: u32) -> u64 {
    let exp = failure_count.saturating_sub(1).min(31);
    let secs = PPPD_RETRY_BASE_SECS.saturating_mul(1u64 << exp);
    secs.min(PPPD_RETRY_MAX_SECS)
}

fn wait_stop_or_timeout(rx: &mut oneshot::Receiver<()>, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    loop {
        match rx.try_recv() {
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            Ok(_) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => return true,
        }

        let now = Instant::now();
        if now >= deadline {
            return false;
        }

        let remain = deadline.saturating_duration_since(now);
        std::thread::sleep(remain.min(Duration::from_millis(200)));
    }
}

fn wait_child_exit(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(Some(status)),
            None => {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn signal_child_process_group(child: &Child, signal: i32) -> io::Result<()> {
    let pid = i32::try_from(child.id()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("child pid {} exceeds i32 range", child.id()),
        )
    })?;

    let result = unsafe { libc::killpg(pid, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn stop_pppd_process(child: &mut Child, ppp_iface_name: &str) {
    match child.try_wait() {
        Ok(Some(status)) => {
            tracing::info!(
                "pppd process for {} already exited before stop handling: {:?}",
                ppp_iface_name,
                status
            );
            return;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("failed to probe pppd child state for {}: {}", ppp_iface_name, e);
        }
    }

    if let Err(e) = signal_child_process_group(child, libc::SIGTERM) {
        tracing::warn!(
            "failed to send SIGTERM to pppd process group for {}: {}",
            ppp_iface_name,
            e
        );
        if let Err(kill_err) = child.kill() {
            tracing::warn!("failed to kill pppd process for {}: {}", ppp_iface_name, kill_err);
        }
    }

    match wait_child_exit(child, Duration::from_secs(PPPD_STOP_GRACE_SECS)) {
        Ok(Some(status)) => {
            tracing::info!(
                "pppd process for {} exited after SIGTERM: {:?}",
                ppp_iface_name,
                status
            );
            return;
        }
        Ok(None) => {
            tracing::warn!(
                "pppd process group for {} did not exit within {}s; escalating to SIGKILL",
                ppp_iface_name,
                PPPD_STOP_GRACE_SECS
            );
        }
        Err(e) => {
            tracing::warn!(
                "failed while waiting for pppd process {} to exit: {}",
                ppp_iface_name,
                e
            );
        }
    }

    if let Err(e) = signal_child_process_group(child, libc::SIGKILL) {
        tracing::warn!(
            "failed to send SIGKILL to pppd process group for {}: {}",
            ppp_iface_name,
            e
        );
        if let Err(kill_err) = child.kill() {
            tracing::warn!(
                "failed to force kill pppd process for {} after SIGKILL failure: {}",
                ppp_iface_name,
                kill_err
            );
        }
    }

    match wait_child_exit(child, Duration::from_secs(PPPD_STOP_KILL_WAIT_SECS)) {
        Ok(Some(status)) => {
            tracing::info!(
                "pppd process for {} exited after SIGKILL: {:?}",
                ppp_iface_name,
                status
            );
        }
        Ok(None) => {
            tracing::error!(
                "pppd process for {} still did not exit after SIGKILL within {}s",
                ppp_iface_name,
                PPPD_STOP_KILL_WAIT_SECS
            );
        }
        Err(e) => {
            tracing::error!(
                "failed while waiting for pppd process {} after SIGKILL: {}",
                ppp_iface_name,
                e
            );
        }
    }
}

#[derive(Clone)]
pub struct PPPDService {
    route_service: IpRouteService,
}

impl PPPDService {
    pub fn new(route_service: IpRouteService) -> Self {
        PPPDService { route_service }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for PPPDService {
    type Config = PPPDServiceConfig;

    async fn start(&self, config: PPPDServiceConfig) -> WatchService {
        let service_status = WatchService::new();
        let route_service = self.route_service.clone();
        if config.enable {
            if let Some(_) = get_iface_by_name(&config.attach_iface_name).await {
                let status_clone = service_status.clone();
                let iface_name = config.iface_name.clone();

                spawn_task_with_resource(
                    task_label::task::PPPD_RUN,
                    iface_name.clone(),
                    async move {
                        create_pppd_thread(
                            config.attach_iface_name,
                            config.iface_name,
                            config.pppd_config,
                            status_clone,
                            route_service,
                        )
                        .await
                    },
                );
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
            }
        }

        service_status
    }
}

pub async fn create_pppd_thread(
    attach_iface_name: String,
    ppp_iface_name: String,
    pppd_conf: PPPDConfig,
    service_status: WatchService,
    route_service: IpRouteService,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let (tx, mut rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<bool>();

    service_status.just_change_status(ServiceStatus::Running);
    let service_status_clone = service_status.clone();
    spawn_task_with_resource(task_label::task::PPPD_STOP, ppp_iface_name.clone(), async move {
        let stop_wait = service_status_clone.wait_to_stopping();
        tracing::debug!("Waiting for external stop signal");
        let _ = stop_wait.await;
        tracing::info!("Received external stop signal");
        let _ = tx.send(());
        tracing::info!("Sent internal stop signal");
    });

    let Ok(_) = pppd_conf.write_config(&attach_iface_name, &ppp_iface_name) else {
        tracing::error!("pppd config write error");
        service_status.just_change_status(ServiceStatus::Failed);
        return;
    };

    let as_router = pppd_conf.default_route;
    let initial_ppp_ipv4_state =
        PppIpv4State::from_snapshot(crate::get_ppp_address(&ppp_iface_name).await);
    let (ppp_ipv4_state_tx, ppp_ipv4_state_rx) = watch::channel(initial_ppp_ipv4_state.clone());

    let (updata_ip, mut updata_ip_rx) = watch::channel(());
    let ppp_iface_name_clone = ppp_iface_name.clone();
    let route_service_clone = route_service.clone();
    let ppp_ipv4_state_tx_clone = ppp_ipv4_state_tx.clone();
    let initial_ppp_ipv4_state_clone = initial_ppp_ipv4_state.clone();
    spawn_task_with_resource(
        task_label::task::PPPD_IP_WATCH,
        ppp_iface_name_clone.clone(),
        async move {
            let mut ip4addr: Option<(u32, Option<Ipv4Addr>, Option<Ipv4Addr>)> = None;
            let mut ppp_ipv4_state = initial_ppp_ipv4_state_clone;
            while let Ok(_) = updata_ip_rx.changed().await {
                let new_ip4addr = crate::get_ppp_address(&ppp_iface_name_clone).await;
                let new_ppp_ipv4_state = PppIpv4State::from_snapshot(new_ip4addr);
                if ppp_ipv4_state != new_ppp_ipv4_state {
                    ppp_ipv4_state_tx_clone.send_replace(new_ppp_ipv4_state.clone());
                    ppp_ipv4_state = new_ppp_ipv4_state;
                }

                if let Some(new_ip4addr) = new_ip4addr {
                    let update = if let Some(data) = ip4addr { data != new_ip4addr } else { true };
                    if update {
                        if let (Some(ip), Some(peer_ip)) = (new_ip4addr.1, new_ip4addr.2) {
                            landscape_ebpf::map_setting::add_ipv4_wan_ip(
                                new_ip4addr.0,
                                ip.clone(),
                                Some(peer_ip.clone()),
                                32,
                                None,
                            );

                            let info = RouteTargetInfo {
                                ifindex: new_ip4addr.0,
                                weight: 1,
                                mac: None,
                                is_docker: false,
                                iface_name: ppp_iface_name_clone.clone(),
                                iface_ip: IpAddr::V4(ip.clone()),
                                default_route: as_router,
                                gateway_ip: IpAddr::V4(peer_ip),
                            };
                            route_service_clone
                                .insert_ipv4_wan_route(&ppp_iface_name_clone, info)
                                .await;

                            route_service_clone
                                .insert_ipv4_lan_route(
                                    &ppp_iface_name_clone,
                                    LanRouteInfo {
                                        ifindex: new_ip4addr.0,
                                        iface_name: ppp_iface_name_clone.clone(),
                                        iface_ip: IpAddr::V4(ip.clone()),
                                        mac: None,
                                        prefix: 32,
                                        mode: LanRouteMode::WanReachable,
                                    },
                                )
                                .await;
                            if as_router {
                                LD_ALL_ROUTERS
                                    .add_route(RouteInfo {
                                        iface_name: ppp_iface_name_clone.clone(),
                                        weight: 1,
                                        route: RouteType::PPP,
                                    })
                                    .await;
                            } else {
                                LD_ALL_ROUTERS.del_route_by_iface(&ppp_iface_name_clone).await;
                            }
                        }
                    }
                    ip4addr = Some(new_ip4addr);
                } else {
                    ip4addr = None;
                }
            }
        },
    );

    tracing::info!("PPPD config written successfully");
    let iface_name = ppp_iface_name.clone();
    let ppp_ipv4_state_rx = ppp_ipv4_state_rx.clone();
    spawn_named_thread(short_thread_name(thread_name::prefix::PPPD, &ppp_iface_name), move || {
        let mut connect_failure_count: u32 = 0;
        let mut should_stop = false;

        'restart: loop {
            if wait_stop_or_timeout(&mut rx, Duration::from_secs(0)) {
                should_stop = true;
                break;
            }

            let baseline_ppp_ipv4_state = ppp_ipv4_state_rx.borrow().clone();
            let mut saw_reset = !baseline_ppp_ipv4_state.is_ready();

            tracing::info!("Starting PPPD");
            let mut command = Command::new("pppd");
            command
                .arg("nodetach")
                .arg("call")
                .arg(&ppp_iface_name)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            unsafe {
                command.pre_exec(|| {
                    let result = libc::setpgid(0, 0);
                    if result == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::last_os_error())
                    }
                });
            }

            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(e) => {
                    connect_failure_count = connect_failure_count.saturating_add(1);
                    let backoff = calc_pppd_retry_backoff_secs(connect_failure_count);
                    tracing::error!(
                        "启动 pppd 失败: {}, {} 秒后重试 (failure_count={})",
                        e,
                        backoff,
                        connect_failure_count
                    );
                    if wait_stop_or_timeout(&mut rx, Duration::from_secs(backoff)) {
                        should_stop = true;
                        break;
                    }
                    continue 'restart;
                }
            };
            let mut check_error_times = 0;
            let mut healthy_once = false;
            let startup_deadline = Instant::now() + Duration::from_secs(PPPD_STARTUP_TIMEOUT_SECS);
            loop {
                std::thread::sleep(Duration::from_secs(1));
                updata_ip.send_replace(());
                match child.try_wait() {
                    Ok(Some(status)) => {
                        tracing::warn!("pppd 退出， 状态码： {:?}", status);
                        break;
                    }
                    Ok(None) => {
                        check_error_times = 0;

                        let current_ppp_ipv4_state = ppp_ipv4_state_rx.borrow().clone();
                        if !current_ppp_ipv4_state.is_ready() {
                            saw_reset = true;
                        }

                        if !healthy_once
                            && current_ppp_ipv4_state.is_ready()
                            && (saw_reset || current_ppp_ipv4_state != baseline_ppp_ipv4_state)
                        {
                            healthy_once = true;
                            connect_failure_count = 0;
                        }

                        if !healthy_once && Instant::now() >= startup_deadline {
                            tracing::warn!(
                                "pppd startup timed out after {}s without acquiring IPv4 local/peer addresses on {}",
                                PPPD_STARTUP_TIMEOUT_SECS,
                                ppp_iface_name
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("pppd error: {e:?}");
                        if check_error_times > 3 {
                            break;
                        }
                        check_error_times += 1;
                    }
                }

                match rx.try_recv() {
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                    Ok(_) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                        tracing::info!("Received stop signal for PPPD");
                        should_stop = true;
                        break;
                    }
                }
            }
            stop_pppd_process(&mut child, &ppp_iface_name);
            if should_stop {
                break;
            }

            connect_failure_count = connect_failure_count.saturating_add(1);
            let backoff = calc_pppd_retry_backoff_secs(connect_failure_count);
            tracing::warn!(
                "pppd 连接中断，{} 秒后重试 (failure_count={})",
                backoff,
                connect_failure_count
            );
            if wait_stop_or_timeout(&mut rx, Duration::from_secs(backoff)) {
                should_stop = true;
                break;
            }
        }

        tracing::info!("Sent worker thread exit signal");
        let _ = other_tx.send(!should_stop);
        pppd_conf.delete_config(&ppp_iface_name);
    })
    .expect("failed to spawn pppd worker thread");

    let exited_with_error = other_rx.await.unwrap_or(true);
    tracing::info!("Worker thread exited");
    if as_router {
        LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
    }
    route_service.remove_ipv4_wan_route(&iface_name).await;
    route_service.remove_ipv4_lan_route(&iface_name).await;
    service_status.just_change_status(if exited_with_error {
        ServiceStatus::Failed
    } else {
        ServiceStatus::Stop
    });
}

#[derive(Clone)]
pub struct PPPDServiceConfigManagerService {
    store: PPPDServiceRepository,
    service: ServiceManager<PPPDService>,
}

impl ControllerService for PPPDServiceConfigManagerService {
    type Id = String;
    type Config = PPPDServiceConfig;
    type DatabseAction = PPPDServiceRepository;
    type H = PPPDService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl PPPDServiceConfigManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        route_service: IpRouteService,
    ) -> Self {
        let store = store_service.pppd_service_store();
        let server_starter = PPPDService::new(route_service);
        let service = ServiceManager::init(store.list().await.unwrap(), server_starter).await;

        Self { service, store }
    }

    pub async fn get_pppd_configs_by_attach_iface_name(
        &self,
        attach_name: String,
    ) -> Vec<PPPDServiceConfig> {
        self.store.get_pppd_configs_by_attach_iface_name(attach_name).await.unwrap()
    }

    pub async fn delete_and_stop_pppd(&self, iface_name: String) -> Option<WatchService> {
        self.delete_and_stop_iface_service(iface_name).await
    }

    pub async fn delete_and_stop_pppds_by_attach_iface_name(&self, attach_name: String) {
        let configs = self.get_pppd_configs_by_attach_iface_name(attach_name).await;
        for each in configs {
            self.delete_and_stop_pppd(each.iface_name).await;
        }
    }
}
