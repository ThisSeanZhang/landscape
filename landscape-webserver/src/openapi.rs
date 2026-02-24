use utoipa::openapi::PathItem;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::auth::get_auth_openapi_router;
use crate::config_service::dns_redirect::get_dns_redirect_config_paths;
use crate::config_service::dns_rule::get_dns_rule_config_paths;
use crate::config_service::dns_upstream::get_dns_upstream_config_paths;
use crate::config_service::dst_ip_rule::get_dst_ip_rule_config_paths;
use crate::config_service::enrolled_device::get_enrolled_device_config_paths;
use crate::config_service::firewall_blacklist::get_firewall_blacklist_config_paths;
use crate::config_service::firewall_rule::get_firewall_rule_config_paths;
use crate::config_service::flow_rule::get_flow_rule_config_paths;
use crate::config_service::geo_ip::get_geo_ip_config_paths;
use crate::config_service::geo_site::get_geo_site_config_paths;
use crate::config_service::static_nat_mapping::get_static_nat_mapping_config_paths;
use crate::LandscapeApp;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Landscape Router API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Landscape Router REST API"
    ),
    tags(
        (name = "Auth", description = "Authentication"),
        (name = "DNS Rules", description = "DNS rule configuration"),
        (name = "DNS Redirects", description = "DNS redirect configuration"),
        (name = "DNS Upstreams", description = "DNS upstream configuration"),
        (name = "Flow Rules", description = "Flow rule configuration"),
        (name = "Firewall Rules", description = "Firewall rule configuration"),
        (name = "Firewall Blacklists", description = "Firewall blacklist configuration"),
        (name = "Destination IP Rules", description = "Destination IP rule configuration"),
        (name = "Static NAT Mappings", description = "Static NAT mapping configuration"),
        (name = "Enrolled Devices", description = "Enrolled device management"),
        (name = "Geo Sites", description = "Geo site configuration"),
        (name = "Geo IPs", description = "Geo IP configuration"),
    ),
    components(schemas(
        landscape_common::config::geo::GeoFileCacheKey,
        landscape_common::config::geo::QueryGeoKey,
        landscape_common::config::geo::GeoDomainConfig,
        landscape_common::config::geo::GeoIpConfig,
    ))
)]
pub struct ApiDoc;

/// Build the OpenApiRouter with all annotated config modules merged.
/// Used by main.rs for serving and by tests for spec export.
pub fn build_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(get_dns_rule_config_paths())
        .merge(get_flow_rule_config_paths())
        .merge(get_dns_redirect_config_paths())
        .merge(get_dns_upstream_config_paths())
        .merge(get_firewall_rule_config_paths())
        .merge(get_firewall_blacklist_config_paths())
        .merge(get_dst_ip_rule_config_paths())
        .merge(get_static_nat_mapping_config_paths())
        .merge(get_enrolled_device_config_paths())
        .merge(get_geo_site_config_paths())
        .merge(get_geo_ip_config_paths())
}

/// Prepend a prefix to all OpenAPI paths in the spec.
fn prefix_paths(openapi: &mut utoipa::openapi::OpenApi, prefix: &str) {
    let old_paths: std::collections::BTreeMap<String, PathItem> =
        std::mem::take(&mut openapi.paths.paths);
    for (path, item) in old_paths {
        openapi.paths.paths.insert(format!("{prefix}{path}"), item);
    }
}

/// Build the full OpenAPI spec, including modules with different state types (e.g. auth).
/// Adds the correct URL prefixes so the spec matches the actual served routes.
pub fn build_full_openapi_spec() -> utoipa::openapi::OpenApi {
    // Config modules (state = LandscapeApp) — paths are relative (e.g. /dns_rules)
    let (_, mut config_openapi) = build_openapi_router().split_for_parts();
    prefix_paths(&mut config_openapi, "/api/src/config");

    // Auth module (state = Arc<AuthRuntimeConfig>) — paths are relative (e.g. /login)
    let (_, mut auth_openapi) = get_auth_openapi_router().split_for_parts();
    prefix_paths(&mut auth_openapi, "/api/auth");

    config_openapi.merge(auth_openapi);
    config_openapi
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
