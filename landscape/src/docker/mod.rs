use bollard::{
    models::EventMessageTypeEnum,
    query_parameters::{EventsOptions, InspectContainerOptions, InspectNetworkOptions},
    Docker,
};
use landscape_common::docker::error::DockerError;
use landscape_common::docker::DockerTargetEnroll;
use landscape_common::{
    route::RouteTargetInfo,
    service::{ServiceStatus, WatchService},
};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::net::{UnixListener, UnixStream};
use tokio::{io::AsyncReadExt, net::unix::SocketAddr};
use tokio_stream::StreamExt;

use crate::{docker::image::PullManager, sys_service::route::IpRouteService};

pub mod image;
pub mod network;
pub mod unix_sock;

/// Docker Service
#[derive(Clone)]
pub struct LandscapeDockerService {
    pub status: WatchService,
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
        let status = WatchService::new();
        let pull_manager = PullManager::new();
        LandscapeDockerService {
            status,
            route_service,
            home_path,
            pull_manager,
            docker_client,
        }
    }

    pub fn docker_client(&self) -> Result<Docker, DockerError> {
        self.docker_client.read().unwrap().clone().ok_or(DockerError::DockerClientNotAvailable)
    }

    pub async fn start_to_listen_event(&self) {
        // reset to stop
        self.status.wait_stop().await;
        let status = self.status.clone();
        let route_service = self.route_service.clone();
        let path = self.home_path.clone();
        let docker_client = self.docker_client.clone();

        scan_all_lan_net(&route_service, &docker_client).await;
        tokio::spawn(async move {
            status.just_change_status(ServiceStatus::Staring);

            let unix_socket = unix_sock::listen_unix_sock(path).await;

            route_service.remove_all_wan_docker().await;

            let unix_status = status.clone();
            let unix_route_service = route_service.clone();
            let event_docker_client = docker_client.clone();
            let unix_docker_client = docker_client;
            let unix_listener = tokio::spawn(async move {
                run_unix_registration_listener(
                    unix_status,
                    unix_route_service,
                    unix_socket,
                    unix_docker_client,
                )
                .await;
            });

            let docker_status = status.clone();
            let docker_route_service = route_service.clone();
            let docker_event_listener = tokio::spawn(async move {
                run_docker_event_loop(docker_status, docker_route_service, event_docker_client)
                    .await;
            });

            let mut receiver = status.subscribe();
            status.just_change_status(ServiceStatus::Running);
            loop {
                if let Err(_) = receiver.changed().await {
                    tracing::error!("get change result error. exit loop");
                    break;
                }
                if status.is_exit() {
                    tracing::info!("docker service stopping");
                    break;
                }
            }

            let _ = unix_listener.await;
            let _ = docker_event_listener.await;

            status.just_change_status(ServiceStatus::Stop);
        });
    }
}

async fn run_unix_registration_listener(
    status: WatchService,
    route_service: IpRouteService,
    unix_socket: UnixListener,
    docker_client: Arc<RwLock<Option<Docker>>>,
) {
    let mut receiver = status.subscribe();

    loop {
        if status.is_exit() {
            tracing::info!("docker registration listener stopping");
            break;
        }

        tokio::select! {
            info = unix_socket.accept() => {
                match info {
                    Ok(conn) => accept_docker_info(&route_service, conn, &docker_client).await,
                    Err(e) => {
                        tracing::error!("failed to accept docker registration socket connection: {e:?}");
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
            change_result = receiver.changed() => {
                if let Err(_) = change_result {
                    tracing::error!("docker registration listener status channel closed");
                    break;
                }
                if status.is_exit() {
                    tracing::info!("docker registration listener stopping");
                    break;
                }
            }
        }
    }
}

async fn run_docker_event_loop(
    status: WatchService,
    route_service: IpRouteService,
    docker_client: Arc<RwLock<Option<Docker>>>,
) {
    let mut receiver = status.subscribe();
    let retry_interval = tokio::time::Duration::from_secs(300);

    loop {
        if status.is_exit() {
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
                    change_result = receiver.changed() => {
                        if change_result.is_err() || status.is_exit() {
                            break;
                        }
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
                change_result = receiver.changed() => {
                    if change_result.is_err() || status.is_exit() {
                        break;
                    }
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
                change_result = receiver.changed() => {
                    if let Err(_) = change_result {
                        tracing::error!("docker event listener status channel closed");
                        return;
                    }
                    if status.is_exit() {
                        tracing::info!("docker event listener stopping");
                        return;
                    }
                }
                _ = interval.tick() => {
                    if status.is_running() {
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
            change_result = receiver.changed() => {
                if change_result.is_err() || status.is_exit() {
                    break;
                }
            }
        }
    }
}

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
    tokio::spawn(async move {
        const MAX_REGISTRATION_BYTES: usize = 4096;

        let mut buf = Vec::with_capacity(256);
        let mut stream = stream.take((MAX_REGISTRATION_BYTES + 1) as u64);
        let read_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.read_to_end(&mut buf))
                .await;

        match read_result {
            Ok(Ok(n)) if n == 0 => {
                tracing::error!("Client disconnected");
            }
            Ok(Ok(n)) => {
                if n > MAX_REGISTRATION_BYTES {
                    tracing::error!(
                        "docker registration info exceeded {MAX_REGISTRATION_BYTES} bytes"
                    );
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
    });
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
                match action.as_str() {
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
                    "stop" => {
                        // tracing::info!("docker stop");
                        if let Some(actor) = emsg.actor {
                            if let Some(attr) = actor.attributes {
                                //
                                if let Some(name) = attr.get("name") {
                                    // tracing::info!("docker stop name: {name}");
                                    ip_route_service.remove_ipv4_wan_route(name).await;
                                    ip_route_service.remove_ipv6_wan_route(name).await;
                                }
                            }
                        }
                    }
                    _ => {}
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
                    if let Some(network_info) = network::convert_network(net_info) {
                        if let Some(info) = network_info.convert_to_lan_info() {
                            ip_route_service.insert_ipv4_lan_route(&network_info.id, info).await;
                        }
                    }
                }
                "destroy" => {
                    println!("");
                    // println!("{:?}", emsg);
                    ip_route_service.remove_ipv4_lan_route(&net_id).await;
                    ip_route_service.print_lan_ifaces().await;
                    println!("");
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
