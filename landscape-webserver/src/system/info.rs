use std::sync::Arc;

use axum::extract::Path;
use axum::{extract::State, routing::get, Router};
use landscape_ebpf::maps::LandscapeMapPath;

use landscape::sys_service::routerstatus::get_sys_running_status;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::dev::{get_interface_index_by_name, LandscapeInterface};
use landscape_common::service::ServiceConfigError;
use landscape_common::sys_service::info::{
    LandscapeStatus, LandscapeSystemInfo, WatchResource, XdpRedirectAbleInfo, LAND_SYS_BASE_INFO,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

/// API state for the sysinfo router: live status snapshots plus the eBPF
/// map paths (for redirect-able queries).
type SysStatus = (WatchResource<LandscapeStatus>, Arc<LandscapeMapPath>);

/// Build the OpenApiRouter for spec generation only (no state applied).
pub fn build_sysinfo_openapi_router() -> OpenApiRouter<SysStatus> {
    OpenApiRouter::new()
        .routes(routes!(basic_sys_info))
        .routes(routes!(interval_fetch_info))
        .routes(routes!(get_cpu_count))
        .routes(routes!(net_dev))
        .routes(routes!(get_xdp_redirect_able_all))
        .routes(routes!(get_xdp_redirect_able))
}

/// return SYS base info — actual router with WatchResource state
pub fn get_sys_info_route(ebpf_paths: Arc<LandscapeMapPath>) -> Router {
    let watchs = get_sys_running_status();

    Router::new()
        .route("/info", get(basic_sys_info))
        .route("/info/interval", get(interval_fetch_info))
        .route("/info/cpu_count", get(get_cpu_count))
        .route("/info/net_dev", get(net_dev))
        .route("/info/xdp_redirect_able", get(get_xdp_redirect_able_all))
        .route("/info/xdp_redirect_able/{ifname}", get(get_xdp_redirect_able))
        .with_state((watchs, ebpf_paths))
}

#[utoipa::path(
    get,
    path = "/info/net_dev",
    tag = "System Info",
    operation_id = "get_net_dev",
    responses((status = 200, body = CommonApiResp<Vec<LandscapeInterface>>))
)]
async fn net_dev() -> LandscapeApiResult<Vec<LandscapeInterface>> {
    let devs = landscape::get_all_devices().await;
    LandscapeApiResp::success(devs)
}

#[utoipa::path(
    get,
    path = "/info",
    tag = "System Info",
    operation_id = "get_basic_sys_info",
    responses((status = 200, body = CommonApiResp<LandscapeSystemInfo>))
)]
async fn basic_sys_info() -> LandscapeApiResult<LandscapeSystemInfo> {
    LandscapeApiResp::success(LAND_SYS_BASE_INFO.clone())
}

#[utoipa::path(
    get,
    path = "/info/interval",
    tag = "System Info",
    operation_id = "get_interval_fetch_info",
    responses((status = 200, body = CommonApiResp<LandscapeStatus>))
)]
async fn interval_fetch_info(
    State(state): State<SysStatus>,
) -> LandscapeApiResult<WatchResource<LandscapeStatus>> {
    LandscapeApiResp::success(state.0)
}

#[utoipa::path(
    get,
    path = "/info/cpu_count",
    tag = "System Info",
    operation_id = "get_cpu_count",
    responses((status = 200, body = CommonApiResp<usize>))
)]
async fn get_cpu_count(State(state): State<SysStatus>) -> LandscapeApiResult<usize> {
    let cpu_count = state.0 .0.borrow().cpus.len();
    LandscapeApiResp::success(cpu_count)
}

#[utoipa::path(
    get,
    path = "/info/xdp_redirect_able",
    tag = "System Info",
    operation_id = "get_xdp_redirect_able_all",
    responses((status = 200, body = CommonApiResp<Vec<XdpRedirectAbleInfo>>))
)]
async fn get_xdp_redirect_able_all(
    State(state): State<SysStatus>,
) -> LandscapeApiResult<Vec<XdpRedirectAbleInfo>> {
    let devs = landscape::get_all_devices().await;
    let ifindexes: Vec<u32> = devs.iter().map(|d| d.index).collect();
    let able_map =
        landscape_ebpf::maps::redirect_able::batch_query_xdp_redirect_able(&state.1, &ifindexes);
    let redirect_able = devs
        .into_iter()
        .map(|dev| XdpRedirectAbleInfo {
            ifname: dev.name,
            redirect_able: able_map.get(&dev.index).copied().unwrap_or(false),
        })
        .collect();
    LandscapeApiResp::success(redirect_able)
}

#[utoipa::path(
    get,
    path = "/info/xdp_redirect_able/{ifname}",
    tag = "System Info",
    operation_id = "get_xdp_redirect_able",
    params(
        ("ifname" = String, Path, description = "Interface name")
    ),
    responses(
        (status = 200, body = CommonApiResp<XdpRedirectAbleInfo>),
        (status = 404, description = "Interface not found")
    )
)]
async fn get_xdp_redirect_able(
    State(state): State<SysStatus>,
    Path(ifname): Path<String>,
) -> LandscapeApiResult<XdpRedirectAbleInfo> {
    let ifindex = get_interface_index_by_name(&ifname)
        .ok_or_else(|| ServiceConfigError::IfaceNotFound { iface_name: ifname.clone() })?;
    let redirect_able =
        landscape_ebpf::maps::redirect_able::is_xdp_redirect_able(&state.1, ifindex);
    LandscapeApiResp::success(XdpRedirectAbleInfo { ifname, redirect_able })
}
