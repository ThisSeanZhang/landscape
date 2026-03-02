use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::cert::order::CertOrderConfig;
use landscape_common::cert::CertError;
use landscape_common::config::ConfigId;
use landscape_common::service::controller::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_cert_order_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_cert_orders, create_cert_order))
        .routes(routes!(get_cert_order, delete_cert_order))
}

#[utoipa::path(
    get,
    path = "/orders",
    tag = "Certificate Orders",
    responses((status = 200, body = CommonApiResp<Vec<CertOrderConfig>>))
)]
async fn list_cert_orders(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<CertOrderConfig>> {
    let result = state.cert_order_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/orders",
    tag = "Certificate Orders",
    request_body = CertOrderConfig,
    responses((status = 200, body = CommonApiResp<CertOrderConfig>))
)]
async fn create_cert_order(
    State(state): State<LandscapeApp>,
    JsonBody(order): JsonBody<CertOrderConfig>,
) -> LandscapeApiResult<CertOrderConfig> {
    let result = state.cert_order_service.checked_set(order).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/orders/{id}",
    tag = "Certificate Orders",
    params(("id" = Uuid, Path, description = "Certificate order ID")),
    responses(
        (status = 200, body = CommonApiResp<CertOrderConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_cert_order(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<CertOrderConfig> {
    let result = state.cert_order_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(CertError::OrderNotFound(id))?
    }
}

#[utoipa::path(
    delete,
    path = "/orders/{id}",
    tag = "Certificate Orders",
    params(("id" = Uuid, Path, description = "Certificate order ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn delete_cert_order(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.cert_order_service.delete(id).await;
    LandscapeApiResp::success(())
}
