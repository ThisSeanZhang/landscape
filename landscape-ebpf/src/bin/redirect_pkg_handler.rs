use clap::{Parser, ValueEnum};
use landscape_common::docker::DockerTargetEnroll;
use landscape_common::{NAMESPACE_REGISTER_SOCK, NAMESPACE_REGISTER_SOCK_PATH_IN_DOCKER};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use std::fs;
use std::io::{self, BufRead, ErrorKind};

use landscape_ebpf::landscape::TcHookProxy;
use landscape_ebpf::tproxy::landscape_tproxy::*;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::TC_INGRESS;
use tracing_subscriber::filter::LevelFilter;

#[derive(Debug, Clone, Serialize, Deserialize, ValueEnum, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HandleMode {
    Tproxy,
    Route,
    MultipleTproxy,
}

#[derive(Debug, Parser)]
pub struct CmdParams {
    #[arg(short = 's', long = "saddr", default_value = "0.0.0.0", env = "LAND_PROXY_SERVER_ADDR")]
    tproxy_server_address: Ipv4Addr,

    #[arg(long = "saddr6", default_value = "::", env = "LAND_PROXY_SERVER_ADDR_V6")]
    tproxy_server_address_v6: Ipv6Addr,

    #[arg(short = 'p', long = "sport", default_value_t = 12345, env = "LAND_PROXY_SERVER_PORT")]
    tproxy_server_port: u16,

    #[arg(short = 'm', long = "mode", value_enum, default_value_t = HandleMode::Tproxy, env = "LAND_PROXY_HANDLE_MODE")]
    handle_mode: HandleMode,

    #[arg(long = "sock_path", env = "LAND_SOCK_PATH")]
    sock_path: Option<PathBuf>,

    #[arg(long = "log-level", default_value_t = LevelFilter::INFO, env = "LAND_REDIRECT_LOG_LEVEL")]
    log_level: LevelFilter,
}

// fn bump_memlock_rlimit() {
//     let rlimit = libc::rlimit { rlim_cur: 128 << 20, rlim_max: 128 << 20 };

//     if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
//         panic!("Failed to increase rlimit");
//     }
// }

// ip netns exec tpns cargo run --package landscape-ebpf --bin redirect_pkg_handler
/// cargo build --package landscape-ebpf --bin redirect_pkg_handler
#[tokio::main]
async fn main() {
    let params = CmdParams::parse();

    init_tracing(params.log_level);
    landscape_ebpf::setting_libbpf_log();

    // bump_memlock_rlimit();

    let container_id = match get_container_id() {
        Some(id) => id,
        None => panic!("Not running in a container or ID not found."),
    };

    let (ifname, ifindex, peer_ifindex) = match get_first_non_loopback_with_peer() {
        Ok(index) => index,
        Err(err) => {
            tracing::info!("Error: {:?}", err);
            return;
        }
    };

    tracing::info!("attach at: {ifname}, ifindex: {ifindex}, peer_ifindex: {peer_ifindex}");

    let proxy_addr: u32 = params.tproxy_server_address.into();
    let proxy_ipv6_addr: u128 = params.tproxy_server_address_v6.into();

    let skel_builder = TproxySkelBuilder::default();
    // skel_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object).unwrap();

    let rodata_data =
        open_skel.maps.rodata_data.as_deref_mut().expect("`rodata` is not memery mapped");
    // Set constants
    rodata_data.proxy_addr = proxy_addr.to_be();
    rodata_data.proxy_ipv6_addr = proxy_ipv6_addr.to_be_bytes();
    if HandleMode::MultipleTproxy == params.handle_mode {
        // Using Flow id to find server port
        rodata_data.proxy_port = 0;
    } else {
        rodata_data.proxy_port = params.tproxy_server_port.to_be();
    }

    // Load into kernel
    let skel = open_skel.load().unwrap();

    let handler_function = match params.handle_mode {
        HandleMode::Tproxy => skel.progs.tproxy_ingress,
        HandleMode::Route => skel.progs.route_mode_ingress,
        HandleMode::MultipleTproxy => skel.progs.tproxy_ingress,
    };

    // let tproxy_egress = skel.progs.tproxy_egress;
    let mut tproxy_ingress_hook = TcHookProxy::new(&handler_function, ifindex, TC_INGRESS, 1);
    // let mut tproxy_egress_hook = TcHookProxy::new(&tproxy_egress, ifindex, TC_EGRESS, 1);

    tproxy_ingress_hook.attach();
    // tproxy_egress_hook.attach();

    let socket_path = params
        .sock_path
        .unwrap_or(PathBuf::from(format!("/{}", NAMESPACE_REGISTER_SOCK_PATH_IN_DOCKER)))
        .join(NAMESPACE_REGISTER_SOCK);
    let enroll_info = DockerTargetEnroll { id: container_id, ifindex: peer_ifindex as u32 };
    tokio::select! {
        _ = run_connection_loop(socket_path, enroll_info) => {
            tracing::info!("report exit");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down...");
        }
    }

    drop(tproxy_ingress_hook);
    // drop(tproxy_egress_hook);
}

fn init_tracing(log_level: LevelFilter) {
    static TRACING_INIT: std::sync::Once = std::sync::Once::new();
    static TRACING_GUARD: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> =
        std::sync::OnceLock::new();

    TRACING_INIT.call_once(|| {
        let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
        let _ = TRACING_GUARD.set(guard);
        let _ = tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .try_init();
    });
}

fn get_first_non_loopback_with_peer() -> Result<(String, i32, i32), io::Error> {
    let net_dir = fs::read_dir("/sys/class/net")?;

    for entry in net_dir {
        let entry = entry?;
        let iface_name = entry.file_name().to_string_lossy().into_owned();

        if iface_name == "lo" {
            continue;
        }

        let iface_path = entry.path();

        // 读取 ifindex
        let ifindex: i32 = fs::read_to_string(iface_path.join("ifindex"))?
            .trim()
            .parse()
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid ifindex"))?;

        // 读取 iflink
        let iflink: i32 = fs::read_to_string(iface_path.join("iflink"))?
            .trim()
            .parse()
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid iflink"))?;

        // 判断是否是成对接口（如 veth）：ifindex != iflink
        if ifindex != iflink {
            return Ok((iface_name, ifindex, iflink));
        }
    }

    Err(io::Error::new(ErrorKind::NotFound, "No interface with peer ifindex found"))
}

async fn run_connection_loop(socket_path: PathBuf, enroll: DockerTargetEnroll) {
    let data = serde_json::to_vec(&enroll).unwrap();
    let loop_interval = 60;
    loop {
        match UnixStream::connect(&socket_path).await {
            Ok(mut stream) => match stream.write_all(&data).await {
                Ok(()) => {
                    let _ = stream.shutdown().await;
                    tracing::info!(
                        "send success: {:?}, {} bytes to {:?}",
                        enroll,
                        data.len(),
                        socket_path
                    );
                }
                Err(e) => {
                    tracing::error!("write error to {:?}: {:?}", socket_path, e);
                }
            },
            Err(e) => {
                tracing::warn!("Error registering Edge to Landscape via {:?}. The next registration attempt will be in {loop_interval} seconds. Error: {:?}", socket_path, e);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(loop_interval)).await;
    }
}

pub fn get_container_id() -> Option<String> {
    // Step 1: 判断是否为 cgroup v2（cgroup.controllers 文件是否存在）
    if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        // 如果是 cgroup v1，直接返回 None
        return None;
    }

    // Step 2: 打开 /proc/self/mountinfo
    let file = fs::File::open("/proc/self/mountinfo").ok()?;
    let reader = io::BufReader::new(file);

    // Step 3: 逐行查找包含 "containers" 的路径
    for line in reader.lines().flatten() {
        if line.contains("containers") && !line.contains("subvolumes") {
            // mountinfo 格式中第5列是 mount point，第4列是 root（路径）
            // 示例：38 29 0:31 /docker/abcdef1234567890 /sys/fs/cgroup/containers/docker/abcdef1234567890 ...

            // 拆分出路径部分尝试提取容器 ID
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 5 {
                let root = fields[3]; // 第4列（root 路径）
                                      // 查找路径中是否包含容器 ID（64位或12位）
                if let Some(id) = extract_container_id_from_path(root) {
                    return Some(id);
                }
            }
        }
    }

    None
}

/// Simple extraction of docker-like container ID from path (matches 64 or 12 hex characters)
fn extract_container_id_from_path(path: &str) -> Option<String> {
    use regex::Regex;

    // Matches a 64-bit or 12-bit hexadecimal ID
    let re = Regex::new(r"([a-f0-9]{64}|[a-f0-9]{12})").ok()?;
    re.captures(path).and_then(|cap| cap.get(1)).map(|m| m.as_str().to_string())
}
