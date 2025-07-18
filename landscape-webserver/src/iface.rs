use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape::iface::IfaceManagerService;
use landscape_common::{
    config::iface::WifiMode,
    iface::{AddController, ChangeZone},
};
use landscape_common::{
    config::iface::{IfaceCpuSoftBalance, NetworkIfaceConfig},
    iface::BridgeCreate,
};
use landscape_database::provider::LandscapeDBServiceProvider;
use serde_json::Value;

use crate::SimpleResult;

pub async fn get_network_paths(store: LandscapeDBServiceProvider) -> Router {
    let share_state = IfaceManagerService::new(store).await;
    Router::new()
        .route("/", get(get_ifaces))
        .route("/wan_configs", get(get_wan_ifaces))
        .route("/manage/:iface_name", post(manage_ifaces))
        .route("/bridge", post(create_bridge))
        .route("/controller", post(set_controller))
        .route("/zone", post(change_zone))
        .route("/:iface_name/status/:status", post(change_dev_status))
        .route("/:iface_name/wifi_mode/:mode", post(change_wifi_mode))
        .route("/:iface_name/cpu_balance", get(get_cpu_balance).post(set_cpu_balance))
        .with_state(share_state)
}

async fn get_wan_ifaces(State(state): State<IfaceManagerService>) -> Json<Vec<NetworkIfaceConfig>> {
    let result = state.get_all_wan_iface_config().await;
    Json(result)
}

async fn manage_ifaces(
    State(state): State<IfaceManagerService>,
    Path(iface_name): Path<String>,
) -> Json<Value> {
    state.manage_dev(iface_name).await;

    let result = serde_json::to_value(SimpleResult { success: true });
    Json(result.unwrap())
}

async fn get_ifaces(State(state): State<IfaceManagerService>) -> Json<Value> {
    let result = state.old_read_ifaces().await;

    let result = serde_json::to_value(&result);
    Json(result.unwrap())
}

async fn create_bridge(
    State(state): State<IfaceManagerService>,
    Json(bridge_create_request): Json<BridgeCreate>,
) -> Json<SimpleResult> {
    state.create_bridge(bridge_create_request).await;
    let result = SimpleResult { success: true };
    Json(result)
}

async fn set_controller(
    State(state): State<IfaceManagerService>,
    Json(controller): Json<AddController>,
) -> Json<SimpleResult> {
    state.set_controller(controller).await;
    let result = SimpleResult { success: true };
    Json(result)
}

// 切换 网卡 所属区域
async fn change_zone(
    State(state): State<IfaceManagerService>,
    Json(change_zone): Json<ChangeZone>,
) -> Json<SimpleResult> {
    state.change_zone(change_zone).await;
    let result = SimpleResult { success: true };
    Json(result)
}

async fn change_wifi_mode(
    State(state): State<IfaceManagerService>,
    Path((iface_name, mode)): Path<(String, WifiMode)>,
) -> Json<SimpleResult> {
    state.change_wifi_mode(iface_name, mode).await;
    let result = SimpleResult { success: true };
    Json(result)
}

async fn change_dev_status(
    State(state): State<IfaceManagerService>,
    Path((iface_name, enable_in_boot)): Path<(String, bool)>,
) -> Json<SimpleResult> {
    state.change_dev_status(iface_name, enable_in_boot).await;
    let result = SimpleResult { success: true };
    Json(result)
}

async fn get_cpu_balance(
    State(state): State<IfaceManagerService>,
    Path(iface_name): Path<String>,
) -> Json<Option<IfaceCpuSoftBalance>> {
    let iface = state.get_iface_config(iface_name).await;
    Json(iface.and_then(|iface| iface.xps_rps))
}

async fn set_cpu_balance(
    State(state): State<IfaceManagerService>,
    Path(iface_name): Path<String>,
    Json(balance): Json<Option<IfaceCpuSoftBalance>>,
) -> Json<SimpleResult> {
    state.change_cpu_balance(iface_name, balance).await;
    let result = SimpleResult { success: true };
    Json(result)
}
