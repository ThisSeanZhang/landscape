use landscape_common::{
    route::RouteTargetInfo,
    service::{DefaultWatchServiceStatus, ServiceStatus},
};
use regex::Regex;
use serde::Serialize;
use std::{fs::File, io::BufRead};

use bollard::{
    secret::{EventActor, EventMessageTypeEnum},
    Docker,
};
use tokio_stream::StreamExt;

use crate::{get_all_devices, route::IpRouteService};

pub mod network;

/// docker 监听服务的状态结构体
#[derive(Serialize, Clone)]
pub struct LandscapeDockerService {
    pub status: DefaultWatchServiceStatus,
    #[serde(skip)]
    route_service: IpRouteService,
}

impl LandscapeDockerService {
    pub fn new(route_service: IpRouteService) -> Self {
        let status = DefaultWatchServiceStatus::new();
        LandscapeDockerService { status, route_service }
    }

    pub async fn start_to_listen_event(&self) {
        // 检测是否已经启动了
        self.status.wait_stop().await;
        let status = self.status.clone();
        let route_service = self.route_service.clone();
        tokio::spawn(async move {
            status.just_change_status(ServiceStatus::Staring);
            let docker = Docker::connect_with_socket_defaults();
            let docker = docker.unwrap();
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

pub async fn handle_event(
    ip_route_service: &IpRouteService,
    docker: &Docker,
    emsg: bollard::secret::EventMessage,
) {
    match emsg.typ {
        Some(EventMessageTypeEnum::CONTAINER) => {
            //
            // println!("{:?}", emsg);
            if let Some(action) = emsg.action {
                match action.as_str() {
                    "start" => {
                        if let Some(actor) = emsg.actor {
                            handle_redirect_id_set(ip_route_service, docker, actor).await;
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {
            tracing::error!("{:?}", emsg);
        }
    }
}
pub async fn create_docker_event_spawn(ip_route_service: IpRouteService) {
    let docker = Docker::connect_with_socket_defaults();
    let docker = docker.unwrap();

    tokio::spawn(async move {
        let mut event_stream = docker.events::<String>(None);

        while let Some(e) = event_stream.next().await {
            if let Ok(msg) = e {
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

pub async fn handle_redirect_id_set(
    ip_route_service: &IpRouteService,
    docker: &Docker,
    actor: EventActor,
) {
    if let Some(attr) = actor.attributes {
        //
        match attr.get("name") {
            Some(name) => {
                // let redirect_id = redirect_id.parse::<u8>().unwrap();
                let result = docker.inspect_container(name, None).await.unwrap();
                if let Some(state) = result.state {
                    if let Some(pid) = state.pid {
                        let file_path = format!("/proc/{:?}/net/igmp", pid);
                        if let Ok(Some(if_id)) = read_igmp_index(&file_path) {
                            tracing::debug!("inner if id: {if_id:?}");

                            let devs = get_all_devices().await;
                            for dev in devs {
                                if let Some(peer_id) = dev.peer_link_id {
                                    if if_id == peer_id {
                                        ip_route_service
                                            .insert_wan_route(
                                                name,
                                                RouteTargetInfo::docker_new(dev.index, name),
                                            )
                                            .await;
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
            _ => {}
        }
    }
}

fn read_igmp_index(file_path: &str) -> std::io::Result<Option<u32>> {
    let file = File::open(file_path)?;
    let reader = std::io::BufReader::new(file);

    // 正则表达式用于匹配数字
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
