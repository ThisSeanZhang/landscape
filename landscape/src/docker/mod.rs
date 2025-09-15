use bollard::{
    secret::{ContainerSummary, EventMessageTypeEnum},
    Docker,
};
use landscape_common::docker::DockerTargetEnroll;
use landscape_common::{
    route::RouteTargetInfo,
    service::{DefaultWatchServiceStatus, ServiceStatus},
};
use regex::Regex;
use serde::Serialize;
use std::{fs::File, io::BufRead, path::PathBuf};
use tokio::net::UnixStream;
use tokio::{io::AsyncWriteExt, net::unix::SocketAddr};
use tokio_stream::StreamExt;

use crate::{get_all_devices, route::IpRouteService};

pub mod network;
pub mod unix_sock;

/// Docker Service
#[derive(Serialize, Clone)]
pub struct LandscapeDockerService {
    pub status: DefaultWatchServiceStatus,
    #[serde(skip)]
    route_service: IpRouteService,
    #[serde(skip)]
    home_path: PathBuf,
}

impl LandscapeDockerService {
    pub fn new(home_path: PathBuf, route_service: IpRouteService) -> Self {
        let status = DefaultWatchServiceStatus::new();
        LandscapeDockerService { status, route_service, home_path }
    }

    pub async fn start_to_listen_event(&self) {
        // reset to stop
        self.status.wait_stop().await;
        let status = self.status.clone();
        let route_service = self.route_service.clone();
        let path = self.home_path.clone();
        tokio::spawn(async move {
            status.just_change_status(ServiceStatus::Staring);
            let docker = Docker::connect_with_socket_defaults();
            let docker = docker.unwrap();

            let unix_socket = unix_sock::listen_unix_sock(path).await;

            route_service.remove_all_wan_docker().await;
            // scan_and_set_all_docker(&route_service, &docker).await;

            let mut event_stream = docker.events::<String>(None);
            let mut receiver = status.subscribe();
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
            let mut timeout_times = 0;
            status.just_change_status(ServiceStatus::Running);
            loop {
                tokio::select! {
                    event_msg = event_stream.next() => {
                        if let Some(e) = event_msg {
                            if let Ok(msg) = e {
                                handle_event(&route_service ,&docker, msg).await;
                            } else {
                                tracing::error!("err event loop: event_msg");
                            }
                        } else {
                            break;
                        }
                    },
                    info = unix_socket.accept() => {
                        if let Ok(conn) = info {
                            accept_docker_info(&route_service, &docker, conn).await
                        }
                    },
                    change_result = receiver.changed() => {
                        if let Err(_) = change_result {
                            tracing::error!("get change result error. exit loop");
                            break;
                        }
                        if status.is_exit() {
                            tracing::error!("stop exit");
                            break;
                        }

                    }
                    _ = interval.tick() => {
                        if status.is_running() {
                            match docker.ping().await {
                                Ok(_) => {
                                    // println!("docker event loop ok event: {msg:?}");
                                },
                                Err(e) => {
                                    timeout_times += 1;
                                    if timeout_times >= 3 {
                                        tracing::error!("exit docker event listen, cause ping error: {e:?}");
                                        break;
                                    }
                                }
                            }
                        }
                        interval.reset();
                    }
                };
            }

            status.just_change_status(ServiceStatus::Stop);
        });
    }
}

pub async fn scan_and_set_all_docker(ip_route: &IpRouteService, docker: &Docker) {
    let containers = get_docker_continer_summary(&docker).await;

    tracing::debug!("containers: {containers:?}");
    for container in containers {
        if let Some(name) = container.names.and_then(|d| d.get(0).cloned()) {
            if let Some(name) = name.strip_prefix("/") {
                inspect_container_and_set_route(&name, ip_route, docker).await;
            }
        }
    }
    ip_route.print_wan_ifaces().await;
}

pub async fn get_docker_continer_summary(docker: &Docker) -> Vec<ContainerSummary> {
    let mut container_summarys: Vec<ContainerSummary> = vec![];
    if let Ok(containers) = docker.list_containers::<String>(None).await {
        container_summarys = containers;
    }
    container_summarys
}

pub async fn accept_docker_info(
    ip_route_service: &IpRouteService,
    docker: &Docker,
    (mut stream, _addr): (UnixStream, SocketAddr),
) {
    let ip_route_service = ip_route_service.clone();
    let docker = docker.clone();
    tokio::spawn(async move {
        //
        let mut buf = vec![0u8; 1024];
        let Ok(_) = stream.readable().await else {
            return;
        };

        match stream.try_read(&mut buf) {
            Ok(n) if n == 0 => {
                tracing::error!("Client disconnected");
            }
            Ok(n) => {
                let result = serde_json::from_slice::<DockerTargetEnroll>(&buf[..n]);

                tracing::info!("Receive info from sock: {:?}", result);
                if let Ok(DockerTargetEnroll { id, ifindex }) = result {
                    let Ok(container_info) = docker.inspect_container(&id, None).await else {
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
            }
            Err(e) => {
                tracing::error!("Failed to read from socket: {:?}", e);
            }
        }

        let _ = stream.shutdown().await;
    });
}

pub async fn handle_event(
    ip_route_service: &IpRouteService,
    _docker: &Docker,
    emsg: bollard::secret::EventMessage,
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
        // Some(EventMessageTypeEnum::NETWORK) => {
        //     let Some(action) = emsg.action else {
        //         return;
        //     };

        //     let Some(id) = emsg.actor else {
        //         return;
        //     };

        //     let Some(net_id) = id.id else {
        //         return;
        //     };

        //     // println!("{:?}", emsg);

        //     match action.as_str() {
        //         "create" => {
        //             let Ok(net_info) = docker.inspect_network::<String>(&net_id, None).await else {
        //                 return;
        //             };

        //             println!("");
        //             println!("{:?}", net_info);
        //             println!("");
        //         }
        //         "destroy" => {
        //             println!("");
        //             // println!("{:?}", emsg);
        //             ip_route_service.remove_ipv4_lan_route(net_id).await;
        //             println!("");
        //         }
        //         _ => {}
        //     }
        // }
        _ => {
            tracing::error!("{:?}", emsg);
        }
    }
}

pub async fn create_docker_event_spawn(ip_route_service: IpRouteService) {
    let docker = Docker::connect_with_socket_defaults();
    let docker = docker.unwrap();

    // ip_route_service.remove_all_wan_docker().await;
    // scan_and_set_all_docker(&ip_route_service, &docker).await;

    tokio::spawn(async move {
        let mut event_stream = docker.events::<String>(None);

        while let Some(e) = event_stream.next().await {
            if let Ok(msg) = e {
                // println!("{:?}", msg);
                handle_event(&ip_route_service, &docker, msg).await;
            }
        }
    });
}

// fn get_all_container_info() {}

// pub struct ContainerConfig {
//     /// 开机启动
//     pub start_in_boot: bool,
//     /// 容器名称
//     pub name: String,
//     /// 使用的镜像名称
//     pub image: String,
// }

// type ConfigStore = Arc<Mutex<StoreFileManager>>;

async fn inspect_container_and_set_route(
    name: &str,
    ip_route_service: &IpRouteService,
    docker: &Docker,
) {
    let Ok(container_info) = docker.inspect_container(name, None).await else {
        tracing::error!("can not inspect container: {name}");
        return;
    };

    if let Some(state) = container_info.state {
        if let Some(pid) = state.pid {
            let file_path = format!("/proc/{:?}/net/igmp", pid);
            if let Ok(Some(if_id)) = read_igmp_index(&file_path) {
                tracing::debug!("inner if id: {if_id:?}");

                let devs = get_all_devices().await;
                for dev in devs {
                    if let Some(peer_id) = dev.peer_link_id {
                        if if_id == peer_id {
                            let (ipv4, ipv6) = RouteTargetInfo::docker_new(dev.index, name);
                            ip_route_service.insert_ipv4_wan_route(name, ipv4).await;
                            ip_route_service.insert_ipv6_wan_route(name, ipv6).await;
                            // let info = FlowTargetPair {
                            //     key: redirect_id as u32,
                            //     value: TargetInterfaceInfo::new_docker(dev.index),
                            // };
                            // landscape_ebpf::map_setting::flow_target::add_flow_target_info(
                            //     info
                            // );
                            // tracing::debug!("peer_id is :{:?}", dev.index);
                        }
                    }
                }
            }
        }
    }
}

fn read_igmp_index(file_path: &str) -> std::io::Result<Option<u32>> {
    let file = File::open(file_path)?;
    let reader = std::io::BufReader::new(file);

    let re = Regex::new(r"\d+").unwrap();
    let mut result = None;
    for line in reader.lines() {
        let line = line?;

        // 1. 去掉非数字起始的行
        if !line.chars().next().unwrap_or(' ').is_digit(10) {
            continue;
        }

        // 2. 去掉包含 "lo" 的行
        if line.contains("lo") {
            continue;
        }

        // 3. 提取第一个数字并转换为 u32
        if let Some(capture) = re.find(&line) {
            let number_str = capture.as_str();
            if let Ok(number) = number_str.parse::<u32>() {
                result = Some(number);
                break;
            }
        }
    }

    Ok(result)
}
