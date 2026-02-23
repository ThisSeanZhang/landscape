use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};

use landscape_common::{
    dhcp::v4_server::config::DHCPv4ServiceConfig, dhcp::v4_server::status::ArpScanInfo,
    service::DefaultWatchServiceStatus,
};
use landscape_common::{
    dhcp::v4_server::status::DHCPv4OfferInfo, service::controller_service_v2::ControllerService,
};

use landscape_common::dhcp::DhcpError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_dhcp_v4_service_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/dhcp_v4/status", get(get_all_iface_service_status))
        .route("/dhcp_v4", post(handle_service_config))
        .route("/dhcp_v4/assigned_ips", get(get_all_iface_assigned_ips))
        .route("/dhcp_v4/arp_scan_info", get(get_all_iface_arp_scan_info))
        .route(
            "/dhcp_v4/{iface_name}",
            get(get_iface_service_conifg).delete(delete_and_stop_iface_service),
        )
        .route("/dhcp_v4/{iface_name}/assigned_ips", get(get_assigned_ips_by_iface_name))
        .route("/dhcp_v4/{iface_name}/arp_scan_info", get(get_arp_scan_info_by_iface_name))
    // .route("/dhcp_v4/{iface_name}/restart", post(restart_mark_service_status))
}

async fn get_all_iface_assigned_ips(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DHCPv4OfferInfo>> {
    LandscapeApiResp::success(state.dhcp_v4_server_service.get_assigned_ips().await)
}

async fn get_assigned_ips_by_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DHCPv4OfferInfo>> {
    LandscapeApiResp::success(
        state.dhcp_v4_server_service.get_assigned_ips_by_iface_name(iface_name).await,
    )
}

async fn get_all_iface_arp_scan_info(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, Vec<ArpScanInfo>>> {
    LandscapeApiResp::success(state.dhcp_v4_server_service.get_arp_scan_info().await)
}

async fn get_arp_scan_info_by_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<Vec<ArpScanInfo>>> {
    LandscapeApiResp::success(
        state.dhcp_v4_server_service.get_arp_scan_ips_by_iface_name(iface_name).await,
    )
}

async fn get_all_iface_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.dhcp_v4_server_service.get_all_status().await)
}

async fn get_iface_service_conifg(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<DHCPv4ServiceConfig> {
    if let Some(iface_config) = state.dhcp_v4_server_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(DhcpError::ConfigNotFound("DHCPv4".into()))?
    }
}

async fn handle_service_config(
    State(state): State<LandscapeApp>,
    Json(config): Json<DHCPv4ServiceConfig>,
) -> LandscapeApiResult<()> {
    if let Err(conflict_msg) = state.dhcp_v4_server_service.check_ip_range_conflict(&config).await {
        return Err(DhcpError::IpConflict(conflict_msg))?;
    }

    state.dhcp_v4_server_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(
        state.dhcp_v4_server_service.delete_and_stop_iface_service(iface_name).await,
    )
}
