use utoipa::openapi::PathItem;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::auth::get_auth_openapi_router;
use crate::config_service::dns_rule::get_dns_rule_config_paths;
use crate::config_service::flow_rule::get_flow_rule_config_paths;
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
        (name = "Flow Rules", description = "Flow rule configuration")
    )
)]
pub struct ApiDoc;

/// Build the OpenApiRouter with all annotated config modules merged.
/// Used by main.rs for serving and by tests for spec export.
pub fn build_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(get_dns_rule_config_paths())
        .merge(get_flow_rule_config_paths())
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
