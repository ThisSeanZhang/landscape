use std::net::SocketAddr;

use axum::{
    handler::HandlerWithoutStateExt,
    http::StatusCode,
    routing::{get, post},
    Router,
};

use colored::Colorize;
use landscape::boot::{boot_check, log::init_logger, InitConfig};
use landscape_common::{
    args::{LAND_ARGS, LAND_HOME_PATH, LAND_LOG_ARGS, LAND_WEB_ARGS},
    error::LdResult,
    store::storev2::StoreFileManager,
};
use serde::{Deserialize, Serialize};
use tower_http::{services::ServeDir, trace::TraceLayer};

mod auth;
mod docker;
mod dump;
mod error;
mod flow;
mod global_mark;
mod iface;
mod service;
mod sysinfo;

use service::{
    dhcp_v4::get_dhcp_v4_service_paths, firewall::get_firewall_service_paths,
    packet_mark::get_iface_packet_mark_paths,
};
use service::{icmp_ra::get_iface_icmpv6ra_paths, nat::get_iface_nat_paths};
use service::{ipconfig::get_iface_ipconfig_paths, ipvpd::get_iface_pdclient_paths};
use service::{pppd::get_iface_pppd_paths, wifi::get_wifi_service_paths};
use tracing::{error, info};

#[derive(Clone, Serialize, Deserialize)]
struct SimpleResult {
    success: bool,
}

#[tokio::main]
async fn main() -> LdResult<()> {
    if let Err(e) = init_logger() {
        panic!("init log error: {e:?}");
    }
    banner();

    let home_path = LAND_HOME_PATH.clone();

    let dev_obs = landscape::observer::dev_observer().await;
    let mut iface_store = StoreFileManager::new(home_path.clone(), "iface".to_string());
    let mut iface_ipconfig_store =
        StoreFileManager::new(home_path.clone(), "iface_ipconfig".to_string());
    let mut iface_nat_store = StoreFileManager::new(home_path.clone(), "iface_nat".to_string());

    let mut iface_mark_store = StoreFileManager::new(home_path.clone(), "iface_mark".to_string());

    let mut iface_pppd_store = StoreFileManager::new(home_path.clone(), "iface_pppd".to_string());

    let mut flow_store = StoreFileManager::new(home_path.clone(), "flow_rule".to_string());
    let mut dns_store = StoreFileManager::new(home_path.clone(), "dns_rule".to_string());

    let mut lan_ip_mark_store = StoreFileManager::new(home_path.clone(), "lan_ip_mark".to_string());

    let mut wan_ip_mark_store = StoreFileManager::new(home_path.clone(), "wan_ip_mark".to_string());

    let mut ipv6pd_store = StoreFileManager::new(home_path.clone(), "ipv6pd_service".to_string());
    let mut dhcpv4_service_store =
        StoreFileManager::new(home_path.clone(), "dhcpv4_service".to_string());
    let mut icmpv6ra_store =
        StoreFileManager::new(home_path.clone(), "icmpv6ra_service".to_string());

    let mut firewall_store =
        StoreFileManager::new(home_path.clone(), "firewall_service".to_string());

    let mut firewall_rules_store =
        StoreFileManager::new(home_path.clone(), "firewall_rules".to_string());

    let mut wifi_config_store = StoreFileManager::new(home_path.clone(), "iface_wifi".to_string());

    let need_init_config = boot_check(&home_path)?;

    let home_log_str = format!("{}", home_path.display()).bright_green();
    if !LAND_ARGS.log_output_in_terminal {
        let log_path = format!("{}", LAND_LOG_ARGS.log_path.display()).green();
        println!("Log Folder path: {}", log_path);
        println!("All Config Home path: {home_log_str}");
    }
    info!("config path: {home_log_str}");
    info!("init config: {need_init_config:#?}");

    // TDDO: 使用宏进行初始化
    if let Some(InitConfig {
        ifaces,
        ipconfigs,
        nats,
        marks,
        pppds,
        flow_rules,
        dns_rules,
        lan_ip_mark,
        wan_ip_mark,
        dhcpv6pds,
        icmpras,
        firewalls,
        firewall_rules,
        wifi_configs,
        dhcpv4_services,
    }) = need_init_config
    {
        iface_store.truncate();
        iface_ipconfig_store.truncate();
        iface_nat_store.truncate();
        iface_mark_store.truncate();
        iface_pppd_store.truncate();
        flow_store.truncate();
        dns_store.truncate();
        lan_ip_mark_store.truncate();
        wan_ip_mark_store.truncate();
        ipv6pd_store.truncate();
        icmpv6ra_store.truncate();
        firewall_store.truncate();
        firewall_rules_store.truncate();
        wifi_config_store.truncate();
        dhcpv4_service_store.truncate();

        for each_config in ifaces {
            iface_store.set(each_config);
        }

        for each_config in ipconfigs {
            iface_ipconfig_store.set(each_config);
        }

        for each_config in nats {
            iface_nat_store.set(each_config);
        }

        for each_config in marks {
            iface_mark_store.set(each_config);
        }

        for each_config in pppds {
            iface_pppd_store.set(each_config);
        }

        for each_config in flow_rules {
            flow_store.set(each_config);
        }
        for each_config in dns_rules {
            dns_store.set(each_config);
        }

        for each_config in lan_ip_mark {
            lan_ip_mark_store.set(each_config);
        }

        for each_config in wan_ip_mark {
            wan_ip_mark_store.set(each_config);
        }

        for each_config in dhcpv6pds {
            ipv6pd_store.set(each_config);
        }

        for each_config in icmpras {
            icmpv6ra_store.set(each_config);
        }

        for each_config in firewalls {
            firewall_store.set(each_config);
        }
        for each_config in firewall_rules {
            firewall_rules_store.set(each_config);
        }

        for each_config in wifi_configs {
            wifi_config_store.set(each_config);
        }
        for each_config in dhcpv4_services {
            dhcpv4_service_store.set(each_config);
        }
    }

    // need iproute2
    if let Err(e) =
        std::process::Command::new("iptables").args(["-A", "FORWARD", "-j", "ACCEPT"]).output()
    {
        error!("iptables cmd exec err: {e:#?}");
    }

    // need procps
    if let Err(e) =
        std::process::Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output()
    {
        error!("sysctl cmd exec err: {e:#?}");
    }

    if let Err(e) =
        std::process::Command::new("sysctl").args(["-w", "net.ipv6.conf.all.forwarding=1"]).output()
    {
        error!("sysctl cmd exec err: {e:#?}");
    }

    if let Err(e) = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.default.forwarding=1"])
        .output()
    {
        error!("sysctl cmd exec err: {e:#?}");
    }

    let addr = SocketAddr::from((LAND_WEB_ARGS.address, LAND_WEB_ARGS.port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    // let _ = landscape_dns::connection::set_socket_mark(
    //     std::os::fd::AsFd::as_fd(&listener).as_raw_fd(),
    //     landscape_common::mark::PacketMark::LandscapeSys.into(),
    // )
    // .unwrap();

    let service = handle_404.into_service();

    let web_root_str = format!("{}", LAND_WEB_ARGS.web_root.display()).green();
    let listen_at_str = format!("{:?}:{:?}", LAND_ARGS.address, LAND_ARGS.port).green();
    if !LAND_ARGS.log_output_in_terminal {
        println!("Web Root path: {}", web_root_str);
        println!("Listen   on: {}", listen_at_str);
    }

    info!("Web Root path: {}", web_root_str);
    info!("Listen   on: {}", listen_at_str);
    let serve_dir = ServeDir::new(&LAND_WEB_ARGS.web_root).not_found_service(service);

    auth::output_sys_token().await;
    let source_route = Router::new()
        .nest("/docker", docker::get_docker_paths(home_path.clone()).await)
        .nest("/iface", iface::get_network_paths(iface_store).await)
        .nest("/global_mark", global_mark::get_global_mark_paths(firewall_rules_store).await)
        .nest("/flow", flow::get_flow_paths(flow_store, dns_store, wan_ip_mark_store).await)
        .nest(
            "/services",
            Router::new()
                .merge(get_firewall_service_paths(firewall_store, dev_obs.resubscribe()).await)
                .merge(get_iface_ipconfig_paths(iface_ipconfig_store, dev_obs.resubscribe()).await)
                .merge(get_dhcp_v4_service_paths(dhcpv4_service_store, dev_obs.resubscribe()).await)
                .merge(get_wifi_service_paths(wifi_config_store, dev_obs.resubscribe()).await)
                .merge(get_iface_pppd_paths(iface_pppd_store).await)
                .merge(get_iface_pdclient_paths(ipv6pd_store, dev_obs.resubscribe()).await)
                .merge(get_iface_icmpv6ra_paths(icmpv6ra_store).await)
                .merge(get_iface_nat_paths(iface_nat_store, dev_obs.resubscribe()).await)
                .merge(get_iface_packet_mark_paths(iface_mark_store, dev_obs).await),
        )
        .nest("/sysinfo", sysinfo::get_sys_info_route())
        .route_layer(axum::middleware::from_fn(auth::auth_middleware));

    let auth_route = Router::new().route("/login", post(auth::login_handler));
    let api_route = Router::new()
        // 资源路由
        .nest("/src", source_route)
        // 认证路由
        .nest("/auth", auth_route);
    let app = Router::new()
        .nest("/api", api_route)
        .nest("/sock", dump::get_tump_router())
        .route("/foo", get(|| async { "Hi from /foo" }))
        .fallback_service(serve_dir);

    axum::serve(listener, app.layer(TraceLayer::new_for_http())).await.unwrap();
    Ok(())
}

/// NOT Found
async fn handle_404() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}

fn banner() {
    let banner = r#"
██╗      █████╗ ███╗   ██╗██████╗ ███████╗ ██████╗ █████╗ ██████╗ ███████╗
██║     ██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
██║     ███████║██╔██╗ ██║██║  ██║███████╗██║     ███████║██████╔╝█████╗  
██║     ██╔══██║██║╚██╗██║██║  ██║╚════██║██║     ██╔══██║██╔═══╝ ██╔══╝  
███████╗██║  ██║██║ ╚████║██████╔╝███████║╚██████╗██║  ██║██║     ███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝
                                                                          
██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗                        
██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗                       
██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██████╔╝                       
██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗                       
██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║                       
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝                       
    "#;
    let args = LAND_ARGS.clone();
    let banner = banner.bright_blue().bold();
    let args_str = format!("{args:#?}").green();
    info!("{}", banner);
    info!("Using Args: {}", args_str);
    if !args.log_output_in_terminal {
        // 当日志不在 terminal 直接展示时, 仅输出一些信息
        println!("{}", banner);
        println!("Using Args: {}", args_str);
    }
}
