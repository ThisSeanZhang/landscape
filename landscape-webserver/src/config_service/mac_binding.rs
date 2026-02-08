use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::{
    config::ConfigId,
    mac_binding::{IpMacBinding, ValidateIpPayload},
};

use crate::{api::LandscapeApiResp, error::LandscapeApiResult, LandscapeApp};

pub async fn get_mac_binding_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/mac_bindings", get(list_mac_bindings).post(push_mac_binding))
        .route("/mac_bindings/validate_ip", post(handle_validate_ip))
        .route(
            "/mac_bindings/{id}",
            get(get_mac_binding).put(update_mac_binding).delete(delete_mac_binding),
        )
}

async fn handle_validate_ip(
    State(app): State<LandscapeApp>,
    Json(payload): Json<ValidateIpPayload>,
) -> LandscapeApiResult<bool> {
    let result = app
        .mac_binding_service
        .validate_ip_range(payload.iface_name, payload.ipv4)
        .await
        .map_err(crate::error::LandscapeApiError::BadRequest)?;
    LandscapeApiResp::success(result)
}

async fn list_mac_bindings(
    State(app): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IpMacBinding>> {
    let result = app.mac_binding_service.list().await;
    LandscapeApiResp::success(result)
}

async fn get_mac_binding(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<Option<IpMacBinding>> {
    let result = app.mac_binding_service.get(id.into()).await;
    LandscapeApiResp::success(result)
}

async fn push_mac_binding(
    State(app): State<LandscapeApp>,
    Json(payload): Json<IpMacBinding>,
) -> LandscapeApiResult<()> {
    app.mac_binding_service
        .push(payload)
        .await
        .map_err(crate::error::LandscapeApiError::BadRequest)?;
    LandscapeApiResp::success(())
}

async fn update_mac_binding(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    Json(mut payload): Json<IpMacBinding>,
) -> LandscapeApiResult<()> {
    payload.id = id.into();
    app.mac_binding_service
        .push(payload)
        .await
        .map_err(crate::error::LandscapeApiError::BadRequest)?;
    LandscapeApiResp::success(())
}

async fn delete_mac_binding(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    app.mac_binding_service
        .delete(id.into())
        .await
        .map_err(crate::error::LandscapeApiError::BadRequest)?;
    LandscapeApiResp::success(())
}
