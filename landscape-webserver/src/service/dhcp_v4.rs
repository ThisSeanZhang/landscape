use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};

use landscape_common::{
    config::dhcp_v4_server::DHCPv4ServiceConfig, service::DefaultWatchServiceStatus,
};
use landscape_common::{dhcp::DHCPv4OfferInfo, service::controller_service_v2::ControllerService};

use serde_json::Value;

use crate::{error::LandscapeApiError, LandscapeApp, SimpleResult};

pub async fn get_dhcp_v4_service_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/dhcp_v4/status", get(get_all_iface_service_status))
        .route("/dhcp_v4", post(handle_service_config))
        .route("/dhcp_v4/assigned_ips", get(get_all_iface_assigned_ips))
        .route(
            "/dhcp_v4/:iface_name",
            get(get_iface_service_conifg).delete(delete_and_stop_iface_service),
        )
        .route("/dhcp_v4/:iface_name/assigned_ips", get(get_all_iface_assigned_ips_by_iface_name))
    // .route("/dhcp_v4/:iface_name/restart", post(restart_mark_service_status))
}

async fn get_all_iface_assigned_ips(
    State(state): State<LandscapeApp>,
) -> Json<HashMap<String, DHCPv4OfferInfo>> {
    Json(state.dhcp_v4_server_service.get_assigned_ips().await)
}

async fn get_all_iface_assigned_ips_by_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> Json<Option<DHCPv4OfferInfo>> {
    Json(state.dhcp_v4_server_service.get_assigned_ips_by_iface_name(iface_name).await)
}

async fn get_all_iface_service_status(State(state): State<LandscapeApp>) -> Json<Value> {
    let result = serde_json::to_value(state.dhcp_v4_server_service.get_all_status().await);
    Json(result.unwrap())
}

async fn get_iface_service_conifg(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> Result<Json<DHCPv4ServiceConfig>, LandscapeApiError> {
    if let Some(iface_config) = state.dhcp_v4_server_service.get_config_by_name(iface_name).await {
        Ok(Json(iface_config))
    } else {
        Err(LandscapeApiError::NotFound("can not find".into()))
    }
}

async fn handle_service_config(
    State(state): State<LandscapeApp>,
    Json(config): Json<DHCPv4ServiceConfig>,
) -> Result<Json<SimpleResult>, LandscapeApiError> {
    if config.enable {
        if let Err(conflict_msg) =
            state.dhcp_v4_server_service.check_ip_range_conflict(&config).await
        {
            return Err(LandscapeApiError::DHCPConflict(conflict_msg));
        }
    }

    state.dhcp_v4_server_service.handle_service_config(config).await;

    let result = SimpleResult { success: true };
    Ok(Json(result))
}

async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> Json<Option<DefaultWatchServiceStatus>> {
    Json(state.dhcp_v4_server_service.delete_and_stop_iface_service(iface_name).await)
}
