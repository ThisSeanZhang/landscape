use bollard::{
    Docker,
    models::EventMessageTypeEnum,
    query_parameters::{EventsOptions, InspectContainerOptions, InspectNetworkOptions},
};
use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::docker::DockerTargetEnroll;
use landscape_common::docker::error::DockerError;
use landscape_common::{service::ServiceStatus, sys_service::route_service::RouteTargetInfo};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::{io::AsyncReadExt, net::unix::SocketAddr};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::{docker::image::PullManager, sys_service::route::IpRouteService};

pub mod image;
pub mod network;
mod run;
pub mod unix_sock;

use run::DockerRun;

/// Docker Service
#[derive(Clone)]
pub struct LandscapeDockerService {
    /// 当前运行实例:每次 start 创建全新 [`DockerRun`](状态/token/tracker
    /// 与运行实例同生命周期,跨周期不复用),stop 后取出丢弃。
    run: Arc<Mutex<Option<DockerRun>>>,
    route_service: IpRouteService,
    home_path: PathBuf,
    pub pull_manager: PullManager,
    docker_client: Arc<RwLock<Option<Docker>>>,
}

impl LandscapeDockerService {
    pub fn new(home_path: PathBuf, route_service: IpRouteService) -> Self {
        let docker_client = Arc::new(RwLock::new(
            Docker::connect_with_unix_defaults()
                .map_err(|e| tracing::warn!("Docker Connect Fail on init: {e:?}"))
                .ok(),
        ));
        let pull_manager = PullManager::new();
        LandscapeDockerService {
            run: Arc::new(Mutex::new(None)),
            route_service,
            home_path,
            pull_manager,
            docker_client,
        }
    }

    pub fn docker_client(&self) -> Result<Docker, DockerError> {
        self.docker_client.read().unwrap().clone().ok_or(DockerError::DockerClientNotAvailable)
    }

    /// 当前运行的状态快照(无运行实例时为 Stop)
    pub async fn status(&self) -> ServiceStatus {
        self.run.lock().await.as_ref().map(|run| run.current()).unwrap_or(ServiceStatus::Stop)
    }

    /// 请求停止并确定性等待当前运行的全部被追踪任务结束,返回终态。
    ///
    /// 持 run 锁跨 wait_stop(通常毫秒级,最长为单个 handle_event 的
    /// Docker API 时长);与 start 的锁内 wait_stop 共同保证 unix socket
    /// 的 unlink+rebind 不与新 run 重叠。
    pub async fn stop(&self) -> ServiceStatus {
        let mut run = self.run.lock().await;
        match run.take() {
            Some(current) => current.wait_stop().await,
            None => ServiceStatus::Stop,
        }
    }

    /// 启动 docker 事件监听:先确定性等待上一轮运行结束,再以全新运行
    /// 实例开始新一轮监听。
    pub async fn start_to_listen_event(&self) {
        let mut run = self.run.lock().await;
        if let Some(previous) = run.take() {
            previous.wait_stop().await;
        }

        let current = DockerRun::new();
        current.just_change_status(ServiceStatus::Staring);

        let route_service = self.route_service.clone();
        let path = self.home_path.clone();
        let docker_client = self.docker_client.clone();
        let scan_route_service = route_service.clone();
        let scan_docker_client = docker_client.clone();

        // supervisor 块持有自己的克隆,外层保留 `current` 供存回与死亡监视
        let spawn_run = current.clone();
        let spawn_handle = spawn_run.clone();
        let supervisor =
            spawn_handle.spawn_task(task_label::task::DOCKER_EVENT_LISTENER, async move {
                let unix_socket = match unix_sock::listen_unix_sock(path).await {
                    Ok(listener) => listener,
                    Err(e) => {
                        tracing::error!(
                            "docker unix registration socket bind failed: {e:?}; marking service failed"
                        );
                        spawn_run.just_change_status(ServiceStatus::Failed);
                        return;
                    }
                };

                route_service.remove_all_wan_docker().await;

                let unix_run = spawn_run.clone();
                let unix_route_service = route_service.clone();
                let event_docker_client = docker_client.clone();
                let unix_docker_client = docker_client;
                let mut unix_listener =
                    spawn_run.spawn_task(task_label::task::DOCKER_EVENT_UNIX, async move {
                        run_unix_registration_listener(
                            unix_run,
                            unix_route_service,
                            unix_socket,
                            unix_docker_client,
                        )
                        .await;
                    });

                let event_run = spawn_run.clone();
                let docker_route_service = route_service.clone();
                let mut docker_event_listener =
                    spawn_run.spawn_task(task_label::task::DOCKER_EVENT_LISTENER, async move {
                        run_docker_event_loop(event_run, docker_route_service, event_docker_client)
                            .await;
                    });

                // token 为水平触发,先取后置 Running 不存在漏事件问题;
                // 已请求停止则跳过,避免 Stopping -> Running 的非法转换告警
                let stop_token = spawn_run.stop_token();
                if !stop_token.is_cancelled() {
                    spawn_run.just_change_status(ServiceStatus::Running);
                }

                // 运行期同时监视两个子任务:任一在停止信号前退出(panic/意外
                // 返回)即置 Failed,避免状态滞留 Running 而功能已死。
                let failed = supervise_children(
                    &stop_token,
                    &mut unix_listener,
                    &mut docker_event_listener,
                )
                .await;

                tracing::info!("docker service stopping");
                // failed 标志是唯一的异常判据:不能用 is_exit() 判断——
                // wait_stop 已先行置 Stopping,会把干净停止误收敛为 Failed
                if failed {
                    spawn_run.just_change_status(ServiceStatus::Failed);
                } else {
                    spawn_run.just_change_status(ServiceStatus::Stop);
                }
            });

        // 死亡监视:supervisor 意外 panic 时收敛到 Failed,避免状态滞留 Running
        let watch_run = current.clone();
        spawn_task(task_label::task::SERVICE_DEATH_WATCH, async move {
            if let Err(panic) = supervisor.await {
                tracing::error!("docker service supervisor panicked: {panic:?}");
                watch_run.just_change_status(ServiceStatus::Failed);
            }
        });

        // 先存回再扫描:scan(Docker API,秒级)在锁外执行,期间 status()/
        // stop() 可正常响应;stop 并发时 tracker 已有任务,wait_stop 仍能
        // 确定性收尾
        let wait_run = current.clone();
        *run = Some(current);
        drop(run);

        // start 返回前等待运行离开 Staring,使端点不再返回中间态;5s 上限
        // 作为异常情况的安全网。
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(5), wait_run.wait_started()).await;

        scan_all_lan_net(&scan_route_service, &scan_docker_client).await;
    }
}

/// 监视两个长驻子任务,直到停止信号触发或任一子任务提前退出。
///
/// 返回 `true` 表示子任务在未收到停止信号时结束(panic/意外返回),调用方
/// 应置 Failed;返回 `false` 表示停止信号驱动的正常收敛。函数返回时两个
/// 子任务都已被等待结束(若为故障路径,会先取消运行 token 收敛另一侧)。
async fn supervise_children(
    stop_token: &CancellationToken,
    unix_listener: &mut tokio::task::JoinHandle<()>,
    docker_event_listener: &mut tokio::task::JoinHandle<()>,
) -> bool {
    let exited = tokio::select! {
        () = stop_token.cancelled() => None,
        result = &mut *unix_listener => Some((true, result)),
        result = &mut *docker_event_listener => Some((false, result)),
    };

    match exited {
        None => {
            let _ = unix_listener.await;
            let _ = docker_event_listener.await;
            false
        }
        Some((is_unix, result)) => {
            let failed = !stop_token.is_cancelled();
            if failed {
                let name =
                    if is_unix { "unix registration listener" } else { "docker event listener" };
                tracing::error!(
                    "docker {name} exited unexpectedly while running ({result:?}); marking service failed"
                );
                // 收敛另一侧:取消运行 token 使其一并退出
                stop_token.cancel();
            }
            if is_unix {
                let _ = docker_event_listener.await;
            } else {
                let _ = unix_listener.await;
            }
            failed
        }
    }
}

async fn run_unix_registration_listener(
    run: DockerRun,
    route_service: IpRouteService,
    unix_socket: UnixListener,
    docker_client: Arc<RwLock<Option<Docker>>>,
) {
    let stop_token = run.stop_token();

    loop {
        if run.is_exit() {
            tracing::info!("docker registration listener stopping");
            break;
        }

        tokio::select! {
            info = unix_socket.accept() => {
                match info {
                    Ok(conn) => {
                        let ip_route_service = route_service.clone();
                        let registration_client = docker_client.clone();
                        // 注册处理纳入 run tracker:wait_stop 可确定性等待
                        // in-flight 注册(上限 5s 读超时)
                        run.spawn_task(task_label::task::DOCKER_EVENT_UNIX, async move {
                            accept_docker_info(&ip_route_service, conn, &registration_client)
                                .await;
                        });
                    }
                    Err(e) => {
                        tracing::error!("failed to accept docker registration socket connection: {e:?}");
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
            () = stop_token.cancelled() => {
                tracing::info!("docker registration listener stopping");
                break;
            }
        }
    }
}

async fn run_docker_event_loop(
    run: DockerRun,
    route_service: IpRouteService,
    docker_client: Arc<RwLock<Option<Docker>>>,
) {
    let stop_token = run.stop_token();
    let retry_interval = tokio::time::Duration::from_secs(300);

    loop {
        if run.is_exit() {
            break;
        }

        let docker = match Docker::connect_with_unix_defaults() {
            Ok(docker) => {
                *docker_client.write().unwrap() = Some(docker.clone());
                docker
            }
            Err(e) => {
                tracing::warn!("Docker Connect Fail, retrying in {:?}: {e:?}", retry_interval);
                tokio::select! {
                    _ = tokio::time::sleep(retry_interval) => {}
                    () = stop_token.cancelled() => {
                        break;
                    }
                }
                continue;
            }
        };

        if let Err(e) = docker.ping().await {
            tracing::warn!(
                "docker ping failed after connect, retrying in {:?}: {e:?}",
                retry_interval
            );
            tokio::select! {
                _ = tokio::time::sleep(retry_interval) => {}
                () = stop_token.cancelled() => {
                    break;
                }
            }
            continue;
        }

        scan_all_lan_net(&route_service, &docker_client).await;

        let query: Option<EventsOptions> = None;
        let mut event_stream = docker.events(query);
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        let mut timeout_times = 0;

        loop {
            tokio::select! {
                event_msg = event_stream.next() => {
                    match event_msg {
                        Some(Ok(msg)) => {
                            handle_event(&route_service, &docker, msg).await;
                        }
                        Some(Err(e)) => {
                            tracing::warn!(
                                "docker event stream error, reconnecting in {:?}: {e:?}",
                                retry_interval
                            );
                            break;
                        }
                        None => {
                            tracing::warn!(
                                "docker event stream ended, reconnecting in {:?}",
                                retry_interval
                            );
                            break;
                        }
                    }
                }
                () = stop_token.cancelled() => {
                    tracing::info!("docker event listener stopping");
                    return;
                }
                _ = interval.tick() => {
                    if run.is_running() {
                        match docker.ping().await {
                            Ok(_) => {
                                timeout_times = 0;
                            },
                            Err(e) => {
                                timeout_times += 1;
                                tracing::warn!(
                                    "docker ping failed {timeout_times} times, reconnecting in {:?} after 3 failures: {e:?}",
                                    retry_interval
                                );
                                if timeout_times >= 3 {
                                    tracing::error!("docker ping failed repeatedly, reconnecting event listener");
                                    break;
                                }
                            }
                        }
                    }
                    interval.reset();
                }
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(retry_interval) => {}
            () = stop_token.cancelled() => {
                break;
            }
        }
    }
}

/// 处理一次 docker 注册上报(由调用方负责以追踪式任务包裹)。
pub async fn accept_docker_info(
    ip_route_service: &IpRouteService,
    (stream, _addr): (UnixStream, SocketAddr),
    docker_client: &Arc<RwLock<Option<Docker>>>,
) {
    let docker = match docker_client.read().unwrap().clone() {
        Some(d) => d,
        None => {
            tracing::warn!("Docker client not available for registration");
            return;
        }
    };
    let ip_route_service = ip_route_service.clone();

    const MAX_REGISTRATION_BYTES: usize = 4096;

    let mut buf = Vec::with_capacity(256);
    let mut stream = stream.take((MAX_REGISTRATION_BYTES + 1) as u64);
    let read_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.read_to_end(&mut buf))
            .await;

    match read_result {
        Ok(Ok(0)) => {
            tracing::error!("Client disconnected");
        }
        Ok(Ok(n)) => {
            if n > MAX_REGISTRATION_BYTES {
                tracing::error!("docker registration info exceeded {MAX_REGISTRATION_BYTES} bytes");
                return;
            }

            let result = serde_json::from_slice::<DockerTargetEnroll>(&buf);

            tracing::info!("Receive info from sock: {:?}", result);
            let Ok(DockerTargetEnroll { id, ifindex }) = result else {
                tracing::error!("failed to parse docker registration info");
                return;
            };

            let query: Option<InspectContainerOptions> = None;
            let Ok(container_info) = docker.inspect_container(&id, query).await else {
                tracing::error!("can not inspect container id: {id}");
                return;
            };

            let mut container_name = if let Some(container_name) = container_info.name {
                container_name
            } else {
                return;
            };

            if container_name.starts_with('/') {
                container_name = container_name
                    .strip_prefix('/')
                    .map(|n| n.to_string())
                    .unwrap_or(container_name);
            }
            tracing::info!("container_name: {container_name:?}");

            let (ipv4, ipv6) = RouteTargetInfo::docker_new(ifindex, &container_name);

            ip_route_service.insert_ipv4_wan_route(&container_name, ipv4).await;
            ip_route_service.insert_ipv6_wan_route(&container_name, ipv6).await;
            ip_route_service.print_wan_ifaces().await;
        }
        Ok(Err(e)) => {
            tracing::error!("Failed to read from socket: {:?}", e);
        }
        Err(_) => {
            tracing::error!("Timed out reading from docker registration socket");
        }
    }
}

pub async fn handle_event(
    ip_route_service: &IpRouteService,
    docker: &Docker,
    emsg: bollard::models::EventMessage,
) {
    match emsg.typ {
        Some(EventMessageTypeEnum::CONTAINER) => {
            //
            // println!("{:?}", emsg);
            if let Some(action) = emsg.action {
                // "start" => {
                //     if let Some(actor) = emsg.actor {
                //         if let Some(attr) = actor.attributes {
                //             //
                //             if let Some(name) = attr.get("name") {
                //                 inspect_container_and_set_route(name, ip_route_service, docker)
                //                     .await;
                //             }
                //         }
                //     }
                // }
                if action.as_str() == "stop" {
                    // tracing::info!("docker stop");
                    if let Some(actor) = emsg.actor
                        && let Some(attr) = actor.attributes
                    {
                        //
                        if let Some(name) = attr.get("name") {
                            // tracing::info!("docker stop name: {name}");
                            ip_route_service.remove_ipv4_wan_route(name).await;
                            ip_route_service.remove_ipv6_wan_route(name).await;
                        }
                    }
                }
            }
        }
        Some(EventMessageTypeEnum::NETWORK) => {
            println!("{:?}", emsg);

            let Some(action) = emsg.action else {
                return;
            };

            let Some(id) = emsg.actor else {
                return;
            };

            let Some(net_id) = id.id else {
                return;
            };

            match action.as_str() {
                "create" => {
                    let Ok(net_info) =
                        docker.inspect_network(&net_id, None::<InspectNetworkOptions>).await
                    else {
                        return;
                    };

                    // println!("net_info: {:?}", net_info);
                    if let Some(network_info) = network::convert_network(net_info)
                        && let Some(info) = network_info.convert_to_lan_info()
                    {
                        ip_route_service.insert_ipv4_lan_route(&network_info.id, info).await;
                    }
                }
                "destroy" => {
                    println!();
                    // println!("{:?}", emsg);
                    ip_route_service.remove_ipv4_lan_route(&net_id).await;
                    ip_route_service.print_lan_ifaces().await;
                    println!();
                }
                _ => {}
            }
        }
        _ => {
            tracing::error!("{:?}", emsg);
        }
    }
}

async fn scan_all_lan_net(
    ip_route_service: &IpRouteService,
    docker_client: &Arc<RwLock<Option<Docker>>>,
) {
    let Some(docker) = docker_client.read().unwrap().clone() else {
        tracing::warn!("Docker client not available for LAN network scan");
        return;
    };
    let Ok(networks) = network::inspect_all_networks(&docker).await else {
        tracing::warn!("Docker list_networks failed, skip LAN network scan");
        return;
    };
    for network_info in networks {
        if let Some(info) = network_info.convert_to_lan_info() {
            ip_route_service.insert_ipv4_lan_route(&network_info.id, info).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn supervisor_reports_failure_when_child_exits_before_stop() {
        let token = CancellationToken::new();
        let event_token = token.clone();
        let mut unix_listener = tokio::spawn(async {});
        let mut docker_event_listener = tokio::spawn(async move {
            event_token.cancelled().await;
        });

        assert!(supervise_children(&token, &mut unix_listener, &mut docker_event_listener).await);
        // 故障路径会取消运行 token,使另一侧一并退出
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn supervisor_reports_failure_on_child_panic() {
        let token = CancellationToken::new();
        let event_token = token.clone();
        let mut unix_listener = tokio::spawn(async {
            panic!("unix registration listener died");
        });
        let mut docker_event_listener = tokio::spawn(async move {
            event_token.cancelled().await;
        });

        assert!(supervise_children(&token, &mut unix_listener, &mut docker_event_listener).await);
    }

    #[tokio::test]
    async fn supervisor_reports_clean_stop_on_token() {
        let token = CancellationToken::new();
        let unix_token = token.clone();
        let event_token = token.clone();
        let mut unix_listener = tokio::spawn(async move {
            unix_token.cancelled().await;
        });
        let mut docker_event_listener = tokio::spawn(async move {
            event_token.cancelled().await;
        });

        token.cancel();

        assert!(!supervise_children(&token, &mut unix_listener, &mut docker_event_listener).await);
    }
}
