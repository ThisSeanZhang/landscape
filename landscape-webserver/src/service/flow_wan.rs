use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape::service::flow_wan_service::FlowWanServiceManagerService;
use landscape_common::service::controller_service::ControllerService;
use landscape_common::{
    config::flow::FlowWanServiceConfig, observer::IfaceObserverAction,
    service::DefaultWatchServiceStatus,
};
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::broadcast;

use landscape_common::service::ServiceConfigError;

use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_iface_flow_wan_paths(
    store: LandscapeDBServiceProvider,
    dev_observer: broadcast::Receiver<IfaceObserverAction>,
) -> Router {
    let share_state = FlowWanServiceManagerService::new(store, dev_observer).await;

    Router::new()
        .route("/packet_marks/status", get(get_all_nat_status))
        .route("/packet_marks", post(handle_iface_nat_status))
        .route(
            "/packet_marks/:iface_name",
            get(get_iface_nat_conifg).delete(delete_and_stop_iface_nat),
        )
        // .route("/packet_marks/:iface_name/restart", post(restart_mark_service_status))
        .with_state(share_state)
}

async fn get_all_nat_status(
    State(state): State<FlowWanServiceManagerService>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.get_all_status().await)
}

async fn get_iface_nat_conifg(
    State(state): State<FlowWanServiceManagerService>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<FlowWanServiceConfig> {
    if let Some(iface_config) = state.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "Flow Wan" })?
    }
}

async fn handle_iface_nat_status(
    State(state): State<FlowWanServiceManagerService>,
    Json(config): Json<FlowWanServiceConfig>,
) -> LandscapeApiResult<()> {
    state.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

async fn delete_and_stop_iface_nat(
    State(state): State<FlowWanServiceManagerService>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.delete_and_stop_iface_service(iface_name).await)
}
