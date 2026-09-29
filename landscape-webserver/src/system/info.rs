use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::extract::Path;
use axum::{Router, extract::State, routing::get};
use landscape_ebpf::maps::LandscapeMapPath;

use landscape::sys_service::routerstatus::get_sys_running_status;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::dev::{LandscapeInterface, get_interface_index_by_name};
use landscape_common::service::ServiceConfigError;
use landscape_common::sys_service::capability::Capability;
use landscape_common::sys_service::info::{
    LAND_SYS_BASE_INFO, LandscapeStatus, LandscapeSystemInfo, XdpRedirectAbleInfo,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

/// API state for the sysinfo router: live status snapshots plus the eBPF
/// map paths (for redirect-able queries).
type SysStatus = (Arc<ArcSwap<LandscapeStatus>>, Arc<LandscapeMapPath>);

/// Build the OpenApiRouter for spec generation only (no state applied).
pub fn build_sysinfo_openapi_router() -> OpenApiRouter<SysStatus> {
    OpenApiRouter::new()
        .routes(routes!(basic_sys_info))
        .routes(routes!(interval_fetch_info))
        .routes(routes!(get_cpu_count))
        .routes(routes!(net_dev))
        .routes(routes!(get_capabilities))
        .routes(routes!(get_xdp_redirect_able_all))
        .routes(routes!(get_xdp_redirect_able))
}

/// return SYS base info — actual router with shared status state
pub fn get_sys_info_route(ebpf_paths: Arc<LandscapeMapPath>) -> Router {
    let watchs = get_sys_running_status();

    Router::new()
        .route("/info", get(basic_sys_info))
        .route("/info/interval", get(interval_fetch_info))
        .route("/info/cpu_count", get(get_cpu_count))
        .route("/info/net_dev", get(net_dev))
        .route("/info/capabilities", get(get_capabilities))
        .route("/info/xdp_redirect_able", get(get_xdp_redirect_able_all))
        .route("/info/xdp_redirect_able/{ifname}", get(get_xdp_redirect_able))
        .with_state((watchs, ebpf_paths))
}

#[utoipa::path(
    get,
    path = "/info/net_dev",
    tag = "System Info",
    operation_id = "get_net_dev",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<LandscapeInterface>>))
)]
async fn net_dev() -> LandscapeApiResult<Vec<LandscapeInterface>> {
    let devs = landscape::get_all_devices().await;
    LandscapeApiResp::success(devs)
}

/// Capabilities supported by this backend build, gated by compile-time features.
fn enabled_capabilities() -> Vec<Capability> {
    let mut capabilities = Vec::new();
    if cfg!(feature = "gateway") {
        capabilities.push(Capability::Gateway);
    }
    if cfg!(feature = "metric-persistent") {
        capabilities.push(Capability::MetricPersistent);
    }
    if cfg!(feature = "mem-track") {
        capabilities.push(Capability::MemTrack);
    }
    capabilities
}

#[utoipa::path(
    get,
    path = "/info/capabilities",
    tag = "System Info",
    operation_id = "get_capabilities",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<Capability>>))
)]
async fn get_capabilities() -> LandscapeApiResult<Vec<Capability>> {
    LandscapeApiResp::success(enabled_capabilities())
}

#[utoipa::path(
    get,
    path = "/info",
    tag = "System Info",
    operation_id = "get_basic_sys_info",
    responses((status = 200, description = "Success", body = CommonApiResp<LandscapeSystemInfo>))
)]
async fn basic_sys_info() -> LandscapeApiResult<LandscapeSystemInfo> {
    LandscapeApiResp::success(LAND_SYS_BASE_INFO.clone())
}

#[utoipa::path(
    get,
    path = "/info/interval",
    tag = "System Info",
    operation_id = "get_interval_fetch_info",
    responses((status = 200, description = "Success", body = CommonApiResp<LandscapeStatus>))
)]
async fn interval_fetch_info(
    State(state): State<SysStatus>,
) -> LandscapeApiResult<LandscapeStatus> {
    LandscapeApiResp::success(state.0.load_full().as_ref().clone())
}

#[utoipa::path(
    get,
    path = "/info/cpu_count",
    tag = "System Info",
    operation_id = "get_cpu_count",
    responses((status = 200, description = "Success", body = CommonApiResp<usize>))
)]
async fn get_cpu_count(State(state): State<SysStatus>) -> LandscapeApiResult<usize> {
    let cpu_count = state.0.load().cpus.len();
    LandscapeApiResp::success(cpu_count)
}

#[utoipa::path(
    get,
    path = "/info/xdp_redirect_able",
    tag = "System Info",
    operation_id = "get_xdp_redirect_able_all",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<XdpRedirectAbleInfo>>))
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
        (status = 200, description = "Success", body = CommonApiResp<XdpRedirectAbleInfo>),
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
