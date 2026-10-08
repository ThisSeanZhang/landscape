use std::net::IpAddr;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape::netlink::address::addresses_by_iface_name;
use serde::Serialize;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct RuntimeIpAddress {
    #[schema(value_type = String)]
    address: IpAddr,
    prefix_length: u8,
    is_permanent: bool,
}

/// Read-only runtime address view; the writable per-iface IP config CRUD
/// moved to the WAN link service (`wan_links` table).
pub fn get_iface_ipconfig_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().routes(routes!(get_runtime_ip_addresses))
}

#[utoipa::path(
    get,
    path = "/ip/runtime-addresses/{iface_name}",
    tag = "IP Config",
    operation_id = "get_runtime_ip_addresses",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<RuntimeIpAddress>>))
)]
async fn get_runtime_ip_addresses(
    State(_state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Vec<RuntimeIpAddress>> {
    if iface_name == "lo" {
        return LandscapeApiResp::success(Vec::new());
    }

    LandscapeApiResp::success(
        addresses_by_iface_name(iface_name)
            .await
            .into_iter()
            .map(|address| RuntimeIpAddress {
                address: address.address,
                prefix_length: address.prefix_len,
                is_permanent: address.is_permanent,
            })
            .collect(),
    )
}
