use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::PathItem;
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;

use crate::auth::get_auth_openapi_router;
use crate::devices::get_enrolled_device_config_paths;
use crate::dns::redirects::get_dns_redirect_config_paths;
use crate::dns::rules::get_dns_rule_config_paths;
use crate::dns::service::get_dns_service_paths;
use crate::dns::upstreams::get_dns_upstream_config_paths;
use crate::docker::get_docker_paths;
use crate::firewall::blacklists::get_firewall_blacklist_config_paths;
use crate::flow::dst_ip_rules::get_dst_ip_rule_config_paths;
use crate::flow::rules::get_flow_rule_config_paths;
use crate::geo::ips::get_geo_ip_config_paths;
use crate::geo::sites::get_geo_site_config_paths;
use crate::interfaces::get_iface_paths;
use crate::metrics::get_metric_paths;
use crate::nat::static_mappings::get_static_nat_mapping_config_paths;
use crate::services::dhcp_v4::get_dhcp_v4_service_paths;
use crate::services::firewall::get_firewall_service_paths;
use crate::services::icmp_ra::get_iface_icmpv6ra_paths;
use crate::services::ip::get_iface_ipconfig_paths;
use crate::services::ipv6pd::get_iface_pdclient_paths;
use crate::services::lan::get_route_lan_paths;
use crate::services::mss_clamp::get_mss_clamp_service_paths;
use crate::services::nat::get_iface_nat_paths;
use crate::services::pppoe::get_iface_pppd_paths;
use crate::services::routing::get_route_paths;
use crate::services::wan::get_route_wan_paths;
use crate::services::wifi::get_wifi_service_paths;
use crate::system::config::get_sys_config_paths;
use crate::LandscapeApp;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some("Login via /api/auth/login, then paste the token here"))
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    security(("bearer_auth" = [])),
    info(
        title = "Landscape Router API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Landscape Router REST API"
    ),
    tags(
        (name = "Auth", description = "Authentication"),
        (name = "Interfaces", description = "Network interface management"),
        (name = "System Config", description = "System configuration management"),
        (name = "System Info", description = "System information and status"),
        (name = "Route", description = "Route tracing and cache management"),
        (name = "Route WAN", description = "WAN route service management"),
        (name = "Route LAN", description = "LAN route service management"),
        (name = "MSS Clamp", description = "MSS clamping service"),
        (name = "Firewall Service", description = "Interface firewall service"),
        (name = "IP Config", description = "Interface IP configuration service"),
        (name = "DHCPv4", description = "DHCPv4 server service"),
        (name = "PPPoE", description = "PPPoE service"),
        (name = "WiFi", description = "WiFi service"),
        (name = "IPv6 PD", description = "IPv6 prefix delegation service"),
        (name = "ICMPv6 RA", description = "ICMPv6 router advertisement service"),
        (name = "NAT Service", description = "NAT service"),
        (name = "DNS Service", description = "DNS service management"),
        (name = "DNS Rules", description = "DNS rule configuration"),
        (name = "DNS Redirects", description = "DNS redirect configuration"),
        (name = "DNS Upstreams", description = "DNS upstream configuration"),
        (name = "Firewall Blacklists", description = "Firewall blacklist configuration"),
        (name = "Flow Rules", description = "Flow rule configuration"),
        (name = "Destination IP Rules", description = "Destination IP rule configuration"),
        (name = "Static NAT Mappings", description = "Static NAT mapping configuration"),
        (name = "Geo Sites", description = "Geo site configuration"),
        (name = "Geo IPs", description = "Geo IP configuration"),
        (name = "Enrolled Devices", description = "Enrolled device management"),
        (name = "Docker", description = "Docker container management"),
        (name = "Docker Images", description = "Docker image management"),
        (name = "Docker Networks", description = "Docker network management"),
        (name = "Metric", description = "Metric data and statistics"),
    ),
    components(schemas(
        landscape_common::config::geo::GeoFileCacheKey,
        landscape_common::config::geo::QueryGeoKey,
        landscape_common::config::geo::GeoDomainConfig,
        landscape_common::config::geo::GeoIpConfig,
        // Auth types
        landscape_common::auth::LoginResult,
        // Schemas referenced by IntoParams but not auto-registered
        landscape_common::metric::connect::ConnectSortKey,
        landscape_common::metric::connect::SortOrder,
        landscape_common::metric::dns::DnsSortKey,
        landscape_common::metric::dns::DnsResultStatus,
        landscape_common::config::dns::LandscapeDnsRecordType,
        // WebSocket types (no endpoint, registered for ORVAL codegen)
        landscape_common::docker::image::ImgPullEvent,
        landscape_common::pty::SessionStatus,
        landscape_common::pty::LandscapePtySize,
        landscape_common::pty::LandscapePtyConfig,
        landscape_common::pty::PtyInMessage,
        landscape_common::pty::PtyOutMessage,
    ))
)]
pub struct ApiDoc;

// ── Domain-based OpenApiRouter builders ──────────────────────────────

/// /interfaces — network interface management
pub fn build_interfaces_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().merge(get_iface_paths())
}

/// /system — system info + global config (sysinfo has its own state type, handled separately)
pub fn build_system_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().merge(get_sys_config_paths())
}

/// /services — per-interface network services
pub fn build_services_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .merge(get_route_paths())
        .merge(get_route_wan_paths())
        .merge(get_route_lan_paths())
        .merge(get_mss_clamp_service_paths())
        .merge(get_firewall_service_paths())
        .merge(get_iface_ipconfig_paths())
        .merge(get_dhcp_v4_service_paths())
        .merge(get_iface_pppd_paths())
        .merge(get_wifi_service_paths())
        .merge(get_iface_pdclient_paths())
        .merge(get_iface_icmpv6ra_paths())
        .merge(get_iface_nat_paths())
}

/// /dns — DNS service + rules + redirects + upstreams
pub fn build_dns_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .merge(get_dns_service_paths())
        .merge(get_dns_rule_config_paths())
        .merge(get_dns_redirect_config_paths())
        .merge(get_dns_upstream_config_paths())
}

/// /firewall — firewall blacklists (rules temporarily disabled)
pub fn build_firewall_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().merge(get_firewall_blacklist_config_paths())
}

/// /flow — flow rules + destination IP rules
pub fn build_flow_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().merge(get_flow_rule_config_paths()).merge(get_dst_ip_rule_config_paths())
}

/// /nat — static NAT mappings
pub fn build_nat_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().merge(get_static_nat_mapping_config_paths())
}

/// /geo — geo sites + geo IPs
pub fn build_geo_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().merge(get_geo_site_config_paths()).merge(get_geo_ip_config_paths())
}

/// /devices — enrolled devices
pub fn build_devices_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().merge(get_enrolled_device_config_paths())
}

/// /docker — Docker service + containers + images + networks
pub fn build_docker_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().merge(get_docker_paths())
}

/// /metrics — monitoring metrics
pub fn build_metrics_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().merge(get_metric_paths())
}

// ── OpenAPI spec assembly ────────────────────────────────────────────

/// Prepend a prefix to all OpenAPI paths in the spec.
fn prefix_paths(openapi: &mut utoipa::openapi::OpenApi, prefix: &str) {
    let old_paths: std::collections::BTreeMap<String, PathItem> =
        std::mem::take(&mut openapi.paths.paths);
    for (path, item) in old_paths {
        openapi.paths.paths.insert(format!("{prefix}{path}"), item);
    }
}

/// Build the full OpenAPI spec with correct URL prefixes matching actual served routes.
pub fn build_full_openapi_spec() -> utoipa::openapi::OpenApi {
    // We need one router that carries the ApiDoc base spec
    let (_, mut spec) =
        OpenApiRouter::<LandscapeApp>::with_openapi(ApiDoc::openapi()).split_for_parts();

    // Auth (state = Arc<AuthRuntimeConfig>)
    let (_, mut auth_openapi) = get_auth_openapi_router().split_for_parts();
    prefix_paths(&mut auth_openapi, "/api/auth");
    spec.merge(auth_openapi);

    // /api/v1/system — system config (LandscapeApp state)
    let (_, mut system_openapi) = build_system_openapi_router().split_for_parts();
    prefix_paths(&mut system_openapi, "/api/v1/system");
    spec.merge(system_openapi);

    // /api/v1/system — sysinfo (special WatchResource state)
    let (_, mut sysinfo_openapi) =
        crate::system::info::build_sysinfo_openapi_router().split_for_parts();
    prefix_paths(&mut sysinfo_openapi, "/api/v1/system");
    spec.merge(sysinfo_openapi);

    // /api/v1/interfaces
    let (_, mut interfaces_openapi) = build_interfaces_openapi_router().split_for_parts();
    prefix_paths(&mut interfaces_openapi, "/api/v1/interfaces");
    spec.merge(interfaces_openapi);

    // /api/v1/services
    let (_, mut services_openapi) = build_services_openapi_router().split_for_parts();
    prefix_paths(&mut services_openapi, "/api/v1/services");
    spec.merge(services_openapi);

    // /api/v1/dns
    let (_, mut dns_openapi) = build_dns_openapi_router().split_for_parts();
    prefix_paths(&mut dns_openapi, "/api/v1/dns");
    spec.merge(dns_openapi);

    // /api/v1/firewall
    let (_, mut firewall_openapi) = build_firewall_openapi_router().split_for_parts();
    prefix_paths(&mut firewall_openapi, "/api/v1/firewall");
    spec.merge(firewall_openapi);

    // /api/v1/flow
    let (_, mut flow_openapi) = build_flow_openapi_router().split_for_parts();
    prefix_paths(&mut flow_openapi, "/api/v1/flow");
    spec.merge(flow_openapi);

    // /api/v1/nat
    let (_, mut nat_openapi) = build_nat_openapi_router().split_for_parts();
    prefix_paths(&mut nat_openapi, "/api/v1/nat");
    spec.merge(nat_openapi);

    // /api/v1/geo
    let (_, mut geo_openapi) = build_geo_openapi_router().split_for_parts();
    prefix_paths(&mut geo_openapi, "/api/v1/geo");
    spec.merge(geo_openapi);

    // /api/v1/devices
    let (_, mut devices_openapi) = build_devices_openapi_router().split_for_parts();
    prefix_paths(&mut devices_openapi, "/api/v1/devices");
    spec.merge(devices_openapi);

    // /api/v1/docker
    let (_, mut docker_openapi) = build_docker_openapi_router().split_for_parts();
    prefix_paths(&mut docker_openapi, "/api/v1/docker");
    spec.merge(docker_openapi);

    // /api/v1/metrics
    let (_, mut metrics_openapi) = build_metrics_openapi_router().split_for_parts();
    prefix_paths(&mut metrics_openapi, "/api/v1/metrics");
    spec.merge(metrics_openapi);

    // Add x-tagGroups for Scalar UI sidebar grouping
    let tag_groups = serde_json::json!([
        {
            "name": "Auth",
            "tags": ["Auth"]
        },
        {
            "name": "System",
            "tags": [
                "System Config",
                "System Info"
            ]
        },
        {
            "name": "Network Interfaces",
            "tags": ["Interfaces"]
        },
        {
            "name": "Interface Services",
            "tags": [
                "Route",
                "Route WAN",
                "Route LAN",
                "MSS Clamp",
                "Firewall Service",
                "IP Config",
                "DHCPv4",
                "PPPoE",
                "WiFi",
                "IPv6 PD",
                "ICMPv6 RA",
                "NAT Service"
            ]
        },
        {
            "name": "DNS",
            "tags": [
                "DNS Service",
                "DNS Rules",
                "DNS Redirects",
                "DNS Upstreams"
            ]
        },
        {
            "name": "Firewall",
            "tags": [
                "Firewall Blacklists"
            ]
        },
        {
            "name": "Flow",
            "tags": [
                "Flow Rules",
                "Destination IP Rules"
            ]
        },
        {
            "name": "NAT",
            "tags": ["Static NAT Mappings"]
        },
        {
            "name": "Geo",
            "tags": [
                "Geo Sites",
                "Geo IPs"
            ]
        },
        {
            "name": "Devices",
            "tags": ["Enrolled Devices"]
        },
        {
            "name": "Docker",
            "tags": [
                "Docker",
                "Docker Images",
                "Docker Networks"
            ]
        },
        {
            "name": "Metrics",
            "tags": ["Metric"]
        }
    ]);
    spec.extensions
        .get_or_insert_with(Default::default)
        .insert("x-tagGroups".to_string(), tag_groups);

    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_openapi_json() {
        let openapi = build_full_openapi_spec();
        let json = openapi.to_pretty_json().expect("Failed to serialize OpenAPI spec");

        let out_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../landscape-types/openapi.json");
        std::fs::write(&out_path, json).expect("Failed to write openapi.json");
        println!("OpenAPI spec written to {}", out_path.display());
    }
}
