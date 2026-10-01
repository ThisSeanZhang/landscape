use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::extract::{ConnectInfo, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::net::MacAddr;
use landscape_common::sys_service::client::{CallerLookupMatch, CallerLookupSource};
use landscape_common::utils::ip::extract_real_ip;
use landscape_core::lan_device::{AddressSourceV4, AddressSourceV6, LanDeviceDirectory};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_client_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().routes(routes!(get_client_caller))
}

/// Caller identity from the LAN device directory (live-table point read).
/// Static and lease IPv4 both count as managed DHCP-style assignments.
fn lookup_match_by_ipv4(directory: &LanDeviceDirectory, ip: Ipv4Addr) -> Option<CallerLookupMatch> {
    let entry = directory.entry_by_ipv4(&ip)?;
    Some(CallerLookupMatch {
        iface_name: entry.iface_name.clone().unwrap_or_default(),
        mac: entry.mac,
        hostname: entry.hostname.clone(),
        source: match entry.ipv4_source {
            Some(AddressSourceV4::Arp) => CallerLookupSource::Arp,
            // Lease and static both count as managed DHCP-style assignments;
            // a missing tag (stale index) maps defensively to the same.
            Some(AddressSourceV4::Lease) | Some(AddressSourceV4::Static) | None => {
                CallerLookupSource::DhcpV4
            }
        },
    })
}

/// A static IPv6 suffix is assigned through the managed (IA_NA) path, so it
/// reports the same source as DHCPv6.
fn lookup_match_by_ipv6(directory: &LanDeviceDirectory, ip: Ipv6Addr) -> Option<CallerLookupMatch> {
    let entry = directory.entry_by_ipv6(&ip)?;
    let source = entry.ipv6_addrs.get(&ip)?;
    Some(CallerLookupMatch {
        iface_name: entry.iface_name.clone().unwrap_or_default(),
        mac: entry.mac,
        hostname: entry.hostname.clone(),
        source: match source {
            AddressSourceV6::Slaac => CallerLookupSource::Ipv6Ra,
            AddressSourceV6::Dhcpv6 | AddressSourceV6::Static => CallerLookupSource::DhcpV6,
        },
    })
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
        IpAddr::V4(ipv4) => {
            (CallerIpVersion::Ipv4, lookup_match_by_ipv4(&state.lan_device_directory, ipv4))
        }
        IpAddr::V6(ipv6) => {
            (CallerIpVersion::Ipv6, lookup_match_by_ipv6(&state.lan_device_directory, ipv6))
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
