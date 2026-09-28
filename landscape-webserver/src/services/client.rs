use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::net::MacAddr;
use landscape_common::sys_service::client::CallerLookupSource;
use landscape_common::utils::ip::extract_real_ip;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_client_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().routes(routes!(get_client_caller))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CallerIpVersion {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Serialize, ToSchema)]
struct CallerIdentityResponse {
    pub ip: String,
    pub ip_version: CallerIpVersion,
    #[schema(nullable = false)]
    pub mac: Option<MacAddr>,
    #[schema(nullable = false)]
    pub iface_name: Option<String>,
    #[schema(nullable = false)]
    pub source: Option<CallerLookupSource>,
    #[schema(nullable = false)]
    pub hostname: Option<String>,
}

#[utoipa::path(
    get,
    path = "/client/caller",
    tag = "Client",
    operation_id = "get_client_caller",
    responses((status = 200, description = "Success", body = CommonApiResp<CallerIdentityResponse>))
)]
async fn get_client_caller(
    State(state): State<LandscapeApp>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> LandscapeApiResult<CallerIdentityResponse> {
    let ip = extract_real_ip(addr);

    let (ip_version, matched) = match ip {
        IpAddr::V4(ipv4) => (
            CallerIpVersion::Ipv4,
            state.dhcp_v4_server_service.resolve_client_match_by_ipv4(ipv4).await,
        ),
        IpAddr::V6(ipv6) => {
            (CallerIpVersion::Ipv6, state.lan_ipv6_service.resolve_client_match_by_ipv6(ipv6).await)
        }
    };

    LandscapeApiResp::success(CallerIdentityResponse {
        ip: ip.to_string(),
        ip_version,
        mac: matched.as_ref().and_then(|item| item.mac),
        iface_name: matched.as_ref().map(|item| item.iface_name.clone()),
        source: matched.as_ref().map(|item| item.source.clone()),
        hostname: matched.and_then(|item| item.hostname),
    })
}
