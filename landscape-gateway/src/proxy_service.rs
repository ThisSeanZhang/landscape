use bytes::Bytes;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use landscape_common::sys_service::gateway::{
    ClientIpHeaderPolicy, HttpPathGroup, HttpUpstreamConfig, HttpUpstreamMatchRule,
    HttpUpstreamRuleConfig, HttpUpstreamTarget, LoadBalanceMethod, PathRewriteMode,
    ProxyHeaderConflictMode, ProxyRequestHeader,
};
use pingora::http::{RequestHeader, ResponseHeader, StatusCode};
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::SharedRules;

const GATEWAY_ROUTE_NOT_MATCHED: pingora::ErrorType =
    pingora::ErrorType::new_code("GatewayRouteNotMatched", 404);
const GATEWAY_NO_UPSTREAM_TARGETS: pingora::ErrorType =
    pingora::ErrorType::new_code("GatewayNoUpstreamTargets", 503);
const GATEWAY_PATH_REWRITE_FAILED: pingora::ErrorType =
    pingora::ErrorType::new_code("GatewayPathRewriteFailed", 500);
const GATEWAY_TRAILING_SLASH_REDIRECT: pingora::ErrorType =
    pingora::ErrorType::new_code("GatewayTrailingSlashRedirect", 308);

pub struct LandscapeReverseProxy {
    rules: SharedRules,
    round_robin_counter: AtomicUsize,
}

impl LandscapeReverseProxy {
    pub fn new(rules: SharedRules) -> Self {
        Self { rules, round_robin_counter: AtomicUsize::new(0) }
    }
}

#[derive(Debug, Clone)]
struct MatchedHttpRoute {
    request_headers: Vec<ProxyRequestHeader>,
    header_conflict_mode: ProxyHeaderConflictMode,
    client_ip_headers: ClientIpHeaderPolicy,
    rewrite_mode: PathRewriteMode,
    matched_prefix: Option<String>,
}

impl MatchedHttpRoute {
    fn from_resolved(route: &ResolvedHttpRoute<'_>) -> Self {
        Self {
            request_headers: route.upstream.request_headers.clone(),
            header_conflict_mode: route.upstream.header_conflict_mode.clone(),
            client_ip_headers: route.upstream.client_ip_headers.clone(),
            rewrite_mode: route.rewrite_mode.clone(),
            matched_prefix: route.matched_prefix.map(str::to_string),
        }
    }
}

struct ResolvedHttpRoute<'a> {
    rule_name: &'a str,
    upstream: &'a HttpUpstreamConfig,
    rewrite_mode: PathRewriteMode,
    matched_prefix: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedTarget {
    address: String,
    port: u16,
    tls: bool,
    skip_cert_verify: bool,
}

impl SelectedTarget {
    fn from_target(target: &HttpUpstreamTarget) -> Self {
        Self {
            address: target.address.clone(),
            port: target.port,
            tls: target.tls,
            skip_cert_verify: target.skip_cert_verify,
        }
    }

    fn display(&self) -> String {
        format!(
            "{}:{} tls={} skip_cert_verify={}",
            self.address, self.port, self.tls, self.skip_cert_verify
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayErrorResponse {
    status_code: u16,
    reason_code: &'static str,
    user_message: &'static str,
}

pub struct ProxyCtx {
    pub matched_rule_name: Option<String>,
    request_host: Option<String>,
    request_path: Option<String>,
    rewritten_path: Option<String>,
    redirect_location: Option<String>,
    selected_target: Option<SelectedTarget>,
    matched_route: Option<MatchedHttpRoute>,
}

#[async_trait]
impl ProxyHttp for LandscapeReverseProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx {
            matched_rule_name: None,
            request_host: None,
            request_path: None,
            rewritten_path: None,
            redirect_location: None,
            selected_target: None,
            matched_route: None,
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let rules = self.rules.load();
        let req = session.req_header();
        let host = extract_host(req);
        let path = req.uri.path();
        let path_and_query =
            req.uri.path_and_query().map(|value| value.as_str()).unwrap_or(path).to_string();

        ctx.request_host = host.clone();
        ctx.request_path = Some(path_and_query);
        ctx.rewritten_path = None;
        ctx.redirect_location = None;
        ctx.selected_target = None;

        let matched_route =
            match_http_route(&rules, host.as_deref(), path).ok_or_else(route_not_matched_error)?;

        ctx.matched_rule_name = Some(matched_route.rule_name.to_string());
        ctx.matched_route = Some(MatchedHttpRoute::from_resolved(&matched_route));

        if let Some(location) = trailing_slash_redirect_location(
            req.uri.path_and_query().map(|value| value.as_str()).unwrap_or(path),
            matched_route.matched_prefix,
        ) {
            ctx.redirect_location = Some(location);
            return Err(trailing_slash_redirect_error());
        }

        let (peer, selected_target) = make_peer(
            matched_route.upstream,
            &self.round_robin_counter,
            host.as_deref().unwrap_or(""),
            path,
        )?;
        ctx.selected_target = Some(selected_target);

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        let Some(matched_route) = ctx.matched_route.as_ref() else {
            return Ok(());
        };

        ctx.rewritten_path = apply_path_rewrite(upstream_request, matched_route)?;

        if matches!(matched_route.client_ip_headers, ClientIpHeaderPolicy::Standard)
            && let Some(client_addr) = session.client_addr().and_then(|addr| addr.as_inet())
        {
            apply_client_ip_headers(upstream_request, client_addr.ip())?;
        }

        apply_configured_headers(
            upstream_request,
            &matched_route.request_headers,
            &matched_route.header_conflict_mode,
        )?;

        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        if is_trailing_slash_redirect_error(e) {
            if session.response_written().is_none()
                && let Some(location) = ctx.redirect_location.as_deref()
                && let Err(write_err) = write_redirect_response(session, location).await
            {
                tracing::error!(
                    location,
                    original_error = %e,
                    write_error = %write_err,
                    "Failed to write trailing slash redirect response"
                );
            }

            return FailToProxy { error_code: 308, can_reuse_downstream: false };
        }

        let classified = classify_proxy_error(e);
        log_proxy_error(ctx, e, &classified);

        if classified.status_code > 0
            && session.response_written().is_none()
            && let Err(write_err) = write_gateway_error_response(session, &classified).await
        {
            tracing::error!(
                reason_code = classified.reason_code,
                error_type = e.etype().as_str(),
                error_source = e.esource().as_str(),
                original_error = %e,
                write_error = %write_err,
                "Failed to write gateway error response"
            );
        }

        FailToProxy {
            error_code: classified.status_code,
            can_reuse_downstream: false,
        }
    }
}

fn route_not_matched_error() -> pingora::BError {
    pingora::Error::explain(GATEWAY_ROUTE_NOT_MATCHED, "No matching upstream rule found").into_in()
}

fn no_upstream_targets_error() -> pingora::BError {
    pingora::Error::explain(GATEWAY_NO_UPSTREAM_TARGETS, "No upstream targets configured").into_in()
}

fn path_rewrite_failed_error() -> pingora::BError {
    pingora::Error::explain(GATEWAY_PATH_REWRITE_FAILED, "Failed to rewrite upstream request path")
        .into_in()
}

fn trailing_slash_redirect_error() -> pingora::BError {
    pingora::Error::explain(
        GATEWAY_TRAILING_SLASH_REDIRECT,
        "Redirected request path to the trailing slash variant",
    )
    .into_in()
}

fn is_trailing_slash_redirect_error(error: &pingora::Error) -> bool {
    error.etype() == &GATEWAY_TRAILING_SLASH_REDIRECT
}

fn match_http_route<'a>(
    rules: &'a [HttpUpstreamRuleConfig],
    host: Option<&str>,
    path: &str,
) -> Option<ResolvedHttpRoute<'a>> {
    if let Some(host) = host {
        if let Some(rule) = match_host_rule(rules, host, false) {
            return Some(resolve_host_route(rule, path));
        }
        if let Some(rule) = match_host_rule(rules, host, true) {
            return Some(resolve_host_route(rule, path));
        }

        if let Some(rule) = match_legacy_path_rule(rules, host, path, false) {
            return Some(resolve_legacy_route(rule));
        }
        if let Some(rule) = match_legacy_path_rule(rules, host, path, true) {
            return Some(resolve_legacy_route(rule));
        }
    }

    match_legacy_fallback_rule(rules, path).map(resolve_legacy_route)
}

fn resolve_host_route<'a>(rule: &'a HttpUpstreamRuleConfig, path: &str) -> ResolvedHttpRoute<'a> {
    let path_groups = match &rule.match_rule {
        HttpUpstreamMatchRule::Host { path_groups } => path_groups,
        _ => unreachable!("resolve_host_route called with non-host rule"),
    };

    if let Some(group) = match_path_group(path_groups, path) {
        return ResolvedHttpRoute {
            rule_name: &rule.name,
            upstream: &group.upstream,
            rewrite_mode: group.rewrite_mode.clone(),
            matched_prefix: Some(group.prefix.as_str()),
        };
    }

    ResolvedHttpRoute {
        rule_name: &rule.name,
        upstream: &rule.upstream,
        rewrite_mode: PathRewriteMode::Preserve,
        matched_prefix: None,
    }
}

fn resolve_legacy_route(rule: &HttpUpstreamRuleConfig) -> ResolvedHttpRoute<'_> {
    ResolvedHttpRoute {
        rule_name: &rule.name,
        upstream: &rule.upstream,
        rewrite_mode: PathRewriteMode::Preserve,
        matched_prefix: None,
    }
}

fn match_host_rule<'a>(
    rules: &'a [HttpUpstreamRuleConfig],
    host: &str,
    wildcard_only: bool,
) -> Option<&'a HttpUpstreamRuleConfig> {
    rules.iter().find(|rule| {
        rule.enable
            && matches!(rule.match_rule, HttpUpstreamMatchRule::Host { .. })
            && domain_matches(&rule.domains, host, wildcard_only)
    })
}

fn match_legacy_path_rule<'a>(
    rules: &'a [HttpUpstreamRuleConfig],
    host: &str,
    path: &str,
    wildcard_domains: bool,
) -> Option<&'a HttpUpstreamRuleConfig> {
    rules.iter().find(|rule| {
        rule.enable
            && matches!(rule.match_rule, HttpUpstreamMatchRule::LegacyPathPrefix { .. })
            && !rule.domains.is_empty()
            && domain_matches(&rule.domains, host, wildcard_domains)
            && legacy_path_matches(rule, path)
    })
}

fn match_legacy_fallback_rule<'a>(
    rules: &'a [HttpUpstreamRuleConfig],
    path: &str,
) -> Option<&'a HttpUpstreamRuleConfig> {
    rules.iter().find(|rule| {
        rule.enable
            && matches!(rule.match_rule, HttpUpstreamMatchRule::LegacyPathPrefix { .. })
            && rule.domains.is_empty()
            && legacy_path_matches(rule, path)
    })
}

fn legacy_path_matches(rule: &HttpUpstreamRuleConfig, path: &str) -> bool {
    match &rule.match_rule {
        HttpUpstreamMatchRule::LegacyPathPrefix { prefix } => path_matches_prefix(path, prefix),
        _ => false,
    }
}

fn domain_matches(domains: &[String], host: &str, wildcard_only: bool) -> bool {
    domains.iter().any(|domain| {
        if wildcard_only {
            domain.starts_with("*.") && match_wildcard(domain, host)
        } else {
            !domain.starts_with("*.") && domain.eq_ignore_ascii_case(host)
        }
    })
}

fn match_path_group<'a>(path_groups: &'a [HttpPathGroup], path: &str) -> Option<&'a HttpPathGroup> {
    path_groups
        .iter()
        .filter(|group| path_matches_prefix(path, &group.prefix))
        .max_by_key(|group| normalized_prefix_len(&group.prefix))
}

fn normalized_prefix_len(prefix: &str) -> usize {
    normalize_prefix(prefix).len()
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    let normalized = normalize_prefix(prefix);
    if normalized == "/" {
        return path.starts_with('/');
    }

    if path == normalized {
        return true;
    }

    path.strip_prefix(&normalized)
        .map(|rest| rest.is_empty() || rest.starts_with('/'))
        .unwrap_or(false)
}

fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim();
    if trimmed == "/" { "/".to_string() } else { trimmed.trim_end_matches('/').to_string() }
}

fn extract_host(req: &RequestHeader) -> Option<String> {
    if let Some(host) = req.headers.get("host")
        && let Ok(h) = host.to_str()
    {
        let h = h.split(':').next().unwrap_or(h);
        return Some(h.to_ascii_lowercase());
    }

    if let Some(authority) = req.uri.authority() {
        return Some(authority.host().to_ascii_lowercase());
    }

    None
}

fn match_wildcard(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let suffix_lower = suffix.to_ascii_lowercase();
        let host_lower = host.to_ascii_lowercase();
        if host_lower.ends_with(&suffix_lower) {
            let prefix_len = host_lower.len() - suffix_lower.len();
            if prefix_len > 0 && host_lower.as_bytes()[prefix_len - 1] == b'.' {
                return true;
            }
        }
    }
    false
}

fn apply_path_rewrite(
    upstream_request: &mut RequestHeader,
    matched_route: &MatchedHttpRoute,
) -> pingora::Result<Option<String>> {
    if !matches!(matched_route.rewrite_mode, PathRewriteMode::StripPrefix) {
        return Ok(None);
    }

    let Some(prefix) = matched_route.matched_prefix.as_deref() else {
        return Ok(None);
    };

    let path_and_query = upstream_request
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| upstream_request.uri.path());

    let rewritten = rewrite_path_and_query(path_and_query, prefix);
    if rewritten == path_and_query {
        return Ok(None);
    }

    upstream_request.set_raw_path(rewritten.as_bytes()).map_err(|_| path_rewrite_failed_error())?;

    Ok(Some(rewritten))
}

fn rewrite_path_and_query(path_and_query: &str, prefix: &str) -> String {
    let (path, query) = split_path_and_query(path_and_query);
    if !path_matches_prefix(path, prefix) {
        return path_and_query.to_string();
    }

    let normalized_prefix = normalize_prefix(prefix);
    let stripped_path = if normalized_prefix == "/" {
        path.to_string()
    } else if path == normalized_prefix {
        "/".to_string()
    } else {
        let remainder = path.strip_prefix(&normalized_prefix).unwrap_or(path);
        if remainder.is_empty() {
            "/".to_string()
        } else if remainder.starts_with('/') {
            remainder.to_string()
        } else {
            format!("/{remainder}")
        }
    };

    if let Some(query) = query { format!("{stripped_path}?{query}") } else { stripped_path }
}

fn trailing_slash_redirect_location(
    path_and_query: &str,
    matched_prefix: Option<&str>,
) -> Option<String> {
    let prefix = matched_prefix?;
    let normalized_prefix = normalize_prefix(prefix);
    if normalized_prefix == "/" || path_and_query.starts_with(&(normalized_prefix.clone() + "/")) {
        return None;
    }

    let (path, query) = split_path_and_query(path_and_query);
    if path != normalized_prefix {
        return None;
    }

    let redirected_path = format!("{normalized_prefix}/");
    Some(match query {
        Some(query) => format!("{redirected_path}?{query}"),
        None => redirected_path,
    })
}

fn split_path_and_query(path_and_query: &str) -> (&str, Option<&str>) {
    match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    }
}

fn apply_client_ip_headers(
    upstream_request: &mut RequestHeader,
    client_ip: IpAddr,
) -> pingora::Result<()> {
    let client_ip = client_ip.to_string();
    let forwarded = format!("for={}", forwarded_for_value(client_ip.as_str()));

    upstream_request
        .append_header("X-Forwarded-For", client_ip.as_str())
        .map_err(|_| pingora::Error::new_str("Failed to append X-Forwarded-For"))?;
    upstream_request
        .insert_header("X-Real-IP", client_ip.as_str())
        .map_err(|_| pingora::Error::new_str("Failed to insert X-Real-IP"))?;
    upstream_request
        .append_header("Forwarded", forwarded.as_str())
        .map_err(|_| pingora::Error::new_str("Failed to append Forwarded"))?;

    Ok(())
}

fn forwarded_for_value(client_ip: &str) -> String {
    if client_ip.contains(':') { format!("\"[{client_ip}]\"") } else { client_ip.to_string() }
}

fn apply_configured_headers(
    upstream_request: &mut RequestHeader,
    headers: &[ProxyRequestHeader],
    mode: &ProxyHeaderConflictMode,
) -> pingora::Result<()> {
    for header in headers {
        match mode {
            ProxyHeaderConflictMode::Set => {
                upstream_request
                    .insert_header(header.name.clone(), header.value.clone())
                    .map_err(|_| pingora::Error::new_str("Failed to insert configured header"))?;
            }
            ProxyHeaderConflictMode::Append => {
                upstream_request
                    .append_header(header.name.clone(), header.value.clone())
                    .map_err(|_| pingora::Error::new_str("Failed to append configured header"))?;
            }
        }
    }

    Ok(())
}

fn make_peer(
    upstream: &HttpUpstreamConfig,
    counter: &AtomicUsize,
    host: &str,
    path: &str,
) -> pingora::Result<(Box<HttpPeer>, SelectedTarget)> {
    let targets = &upstream.targets;
    if targets.is_empty() {
        return Err(no_upstream_targets_error());
    }

    let target = select_target(targets, &upstream.load_balance, counter, host, path);
    let mut peer =
        HttpPeer::new((target.address.as_str(), target.port), target.tls, target.address.clone());
    if target.tls && target.skip_cert_verify {
        peer.options.verify_cert = false;
        peer.options.verify_hostname = false;
    }
    peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
    Ok((Box::new(peer), SelectedTarget::from_target(target)))
}

fn select_target<'a>(
    targets: &'a [HttpUpstreamTarget],
    method: &LoadBalanceMethod,
    counter: &AtomicUsize,
    host: &str,
    path: &str,
) -> &'a HttpUpstreamTarget {
    if targets.len() == 1 {
        return &targets[0];
    }

    match method {
        LoadBalanceMethod::RoundRobin => {
            let idx = counter.fetch_add(1, Ordering::Relaxed) % targets.len();
            &targets[idx]
        }
        LoadBalanceMethod::Random => {
            let idx = fnv1a_hash(host, path) % targets.len();
            &targets[idx]
        }
        LoadBalanceMethod::Consistent => weighted_select(targets, fnv1a_hash(host, "")),
    }
}

fn weighted_select(targets: &[HttpUpstreamTarget], seed: usize) -> &HttpUpstreamTarget {
    let total_weight: u32 = targets.iter().map(|t| t.weight).sum();
    if total_weight == 0 {
        return &targets[0];
    }
    let pick = (seed as u32) % total_weight;
    let mut acc = 0u32;
    for target in targets {
        acc += target.weight;
        if pick < acc {
            return target;
        }
    }
    targets.last().unwrap()
}

fn fnv1a_hash(host: &str, path: &str) -> usize {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for b in host.bytes().chain(path.bytes()) {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash as usize
}

fn classify_proxy_error(error: &pingora::Error) -> GatewayErrorResponse {
    if error.etype() == &GATEWAY_ROUTE_NOT_MATCHED {
        return GatewayErrorResponse {
            status_code: 404,
            reason_code: "route_not_matched",
            user_message: "No gateway route matches this host and path.",
        };
    }

    if error.etype() == &GATEWAY_NO_UPSTREAM_TARGETS {
        return GatewayErrorResponse {
            status_code: 503,
            reason_code: "no_upstream_targets",
            user_message: "The matched route has no upstream targets configured.",
        };
    }

    if error.etype() == &GATEWAY_PATH_REWRITE_FAILED {
        return GatewayErrorResponse {
            status_code: 500,
            reason_code: "path_rewrite_failed",
            user_message: "The gateway failed to rewrite the upstream request path.",
        };
    }

    if let pingora::ErrorType::HTTPStatus(code) = error.etype() {
        return GatewayErrorResponse {
            status_code: normalize_status_code(*code),
            reason_code: "http_status",
            user_message: "The gateway returned an HTTP error response.",
        };
    }

    match error.esource() {
        pingora::ErrorSource::Upstream => classify_upstream_error(error.etype()),
        pingora::ErrorSource::Downstream => classify_downstream_error(error.etype()),
        pingora::ErrorSource::Internal | pingora::ErrorSource::Unset => GatewayErrorResponse {
            status_code: 500,
            reason_code: "internal_error",
            user_message: "The gateway encountered an internal error.",
        },
    }
}

fn classify_upstream_error(error_type: &pingora::ErrorType) -> GatewayErrorResponse {
    match error_type {
        pingora::ErrorType::ConnectTimedout
        | pingora::ErrorType::TLSHandshakeTimedout
        | pingora::ErrorType::ReadTimedout
        | pingora::ErrorType::WriteTimedout => GatewayErrorResponse {
            status_code: 504,
            reason_code: "upstream_timeout",
            user_message: "The upstream service timed out.",
        },
        pingora::ErrorType::ConnectRefused => GatewayErrorResponse {
            status_code: 503,
            reason_code: "upstream_connect_refused",
            user_message: "The upstream service refused the connection.",
        },
        pingora::ErrorType::ConnectNoRoute => GatewayErrorResponse {
            status_code: 503,
            reason_code: "upstream_no_route",
            user_message: "The upstream service is unreachable on the network.",
        },
        pingora::ErrorType::ConnectError
        | pingora::ErrorType::SocketError
        | pingora::ErrorType::ConnectProxyFailure => GatewayErrorResponse {
            status_code: 503,
            reason_code: "upstream_connect_failed",
            user_message: "The gateway could not connect to the upstream service.",
        },
        pingora::ErrorType::TLSHandshakeFailure
        | pingora::ErrorType::InvalidCert
        | pingora::ErrorType::HandshakeError
        | pingora::ErrorType::TLSWantX509Lookup => GatewayErrorResponse {
            status_code: 502,
            reason_code: "upstream_tls_failed",
            user_message: "The upstream TLS handshake failed.",
        },
        pingora::ErrorType::InvalidHTTPHeader
        | pingora::ErrorType::H1Error
        | pingora::ErrorType::H2Error
        | pingora::ErrorType::InvalidH2
        | pingora::ErrorType::H2Downgrade => GatewayErrorResponse {
            status_code: 502,
            reason_code: "upstream_invalid_response",
            user_message: "The upstream service returned an invalid HTTP response.",
        },
        pingora::ErrorType::ReadError
        | pingora::ErrorType::WriteError
        | pingora::ErrorType::ConnectionClosed => GatewayErrorResponse {
            status_code: 502,
            reason_code: "upstream_io_failed",
            user_message: "The upstream connection closed unexpectedly.",
        },
        _ => GatewayErrorResponse {
            status_code: 502,
            reason_code: "upstream_error",
            user_message: "The gateway could not complete the upstream request.",
        },
    }
}

fn classify_downstream_error(error_type: &pingora::ErrorType) -> GatewayErrorResponse {
    match error_type {
        pingora::ErrorType::ReadError
        | pingora::ErrorType::WriteError
        | pingora::ErrorType::ConnectionClosed => GatewayErrorResponse {
            status_code: 0,
            reason_code: "downstream_closed",
            user_message: "The client connection closed before the response was sent.",
        },
        _ => GatewayErrorResponse {
            status_code: 400,
            reason_code: "downstream_error",
            user_message: "The client request could not be processed.",
        },
    }
}

fn normalize_status_code(code: u16) -> u16 {
    if StatusCode::from_u16(code).is_ok() { code } else { 500 }
}

fn status_line(code: u16) -> String {
    match StatusCode::from_u16(code) {
        Ok(status) => {
            let reason = status.canonical_reason().unwrap_or("Unknown Status");
            format!("{} {}", status.as_u16(), reason)
        }
        Err(_) => "500 Internal Server Error".to_string(),
    }
}

fn build_gateway_error_body(response: &GatewayErrorResponse) -> String {
    format!(
        "{}\nReason: {}\n{}\n",
        status_line(response.status_code),
        response.reason_code,
        response.user_message
    )
}

fn build_gateway_error_response_header(
    status_code: u16,
    body_len: usize,
) -> pingora::Result<ResponseHeader> {
    let mut response = ResponseHeader::build(normalize_status_code(status_code), None)
        .map_err(|e| e.more_context("Failed to build gateway error response header").into_in())?;
    response
        .set_content_length(body_len)
        .map_err(|e| e.more_context("Failed to set Content-Length header").into_in())?;
    response
        .insert_header("Content-Type", "text/plain; charset=utf-8")
        .map_err(|e| e.more_context("Failed to insert Content-Type header").into_in())?;
    response
        .insert_header("Cache-Control", "private, no-store")
        .map_err(|e| e.more_context("Failed to insert Cache-Control header").into_in())?;
    Ok(response)
}

fn build_redirect_response_header(location: &str) -> pingora::Result<ResponseHeader> {
    let mut response = ResponseHeader::build(StatusCode::PERMANENT_REDIRECT.as_u16(), None)
        .map_err(|e| e.more_context("Failed to build redirect response header").into_in())?;
    response
        .set_content_length(0)
        .map_err(|e| e.more_context("Failed to set redirect Content-Length header").into_in())?;
    response
        .insert_header("Location", location)
        .map_err(|e| e.more_context("Failed to insert redirect Location header").into_in())?;
    response
        .insert_header("Cache-Control", "private, no-store")
        .map_err(|e| e.more_context("Failed to insert redirect Cache-Control header").into_in())?;
    Ok(response)
}

async fn write_gateway_error_response(
    session: &mut Session,
    response: &GatewayErrorResponse,
) -> pingora::Result<()> {
    let body = Bytes::from(build_gateway_error_body(response));
    let header = build_gateway_error_response_header(response.status_code, body.len())?;

    session.set_keepalive(None);
    session.write_response_header(Box::new(header), false).await?;
    session.write_response_body(Some(body), true).await?;

    Ok(())
}

async fn write_redirect_response(session: &mut Session, location: &str) -> pingora::Result<()> {
    let header = build_redirect_response_header(location)?;

    session.set_keepalive(None);
    session.write_response_header(Box::new(header), true).await?;

    Ok(())
}

fn log_proxy_error(ctx: &ProxyCtx, error: &pingora::Error, response: &GatewayErrorResponse) {
    let matched_rule = ctx.matched_rule_name.as_deref().unwrap_or("-");
    let request_host = ctx.request_host.as_deref().unwrap_or("-");
    let request_path = ctx.request_path.as_deref().unwrap_or("-");
    let rewritten_path = ctx.rewritten_path.as_deref().unwrap_or("-");
    let selected_target =
        ctx.selected_target.as_ref().map_or_else(|| "-".to_string(), SelectedTarget::display);

    if matches!(error.esource(), pingora::ErrorSource::Internal | pingora::ErrorSource::Unset)
        && response.status_code >= 500
    {
        tracing::error!(
            reason_code = response.reason_code,
            status_code = response.status_code,
            error_type = error.etype().as_str(),
            error_source = error.esource().as_str(),
            matched_rule,
            request_host,
            request_path,
            rewritten_path,
            selected_target,
            error = %error,
            "Gateway proxy request failed"
        );
    } else {
        tracing::warn!(
            reason_code = response.reason_code,
            status_code = response.status_code,
            error_type = error.etype().as_str(),
            error_source = error.esource().as_str(),
            matched_rule,
            request_host,
            request_path,
            rewritten_path,
            selected_target,
            error = %error,
            "Gateway proxy request failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use landscape_common::sys_service::gateway::{
        ClientIpHeaderPolicy, HttpUpstreamConfig, ProxyHeaderConflictMode,
    };

    fn target(address: &str, port: u16, weight: u32) -> HttpUpstreamTarget {
        HttpUpstreamTarget {
            address: address.to_string(),
            port,
            weight,
            tls: false,
            skip_cert_verify: false,
        }
    }

    fn upstream_config() -> HttpUpstreamConfig {
        HttpUpstreamConfig {
            targets: vec![target("127.0.0.1", 8080, 1)],
            load_balance: LoadBalanceMethod::RoundRobin,
            health_check: None,
            request_headers: vec![],
            header_conflict_mode: ProxyHeaderConflictMode::Set,
            client_ip_headers: ClientIpHeaderPolicy::Standard,
        }
    }

    fn rule(
        name: &str,
        domains: &[&str],
        match_rule: HttpUpstreamMatchRule,
    ) -> HttpUpstreamRuleConfig {
        HttpUpstreamRuleConfig {
            id: uuid::Uuid::new_v4(),
            enable: true,
            name: name.to_string(),
            domains: domains.iter().map(|domain| domain.to_string()).collect(),
            match_rule,
            upstream: upstream_config(),
            update_at: 0.0,
        }
    }

    #[test]
    fn match_http_route_prefers_exact_host_before_wildcard() {
        let rules = vec![
            rule(
                "wildcard",
                &["*.example.com"],
                HttpUpstreamMatchRule::Host { path_groups: vec![] },
            ),
            rule(
                "exact",
                &["api.example.com"],
                HttpUpstreamMatchRule::Host { path_groups: vec![] },
            ),
        ];

        let matched = match_http_route(&rules, Some("api.example.com"), "/api/v1").unwrap();
        assert_eq!(matched.rule_name, "exact");
    }

    #[test]
    fn match_http_route_prefers_longest_path_group() {
        let rules = vec![rule(
            "host",
            &["api.example.com"],
            HttpUpstreamMatchRule::Host {
                path_groups: vec![
                    HttpPathGroup {
                        prefix: "/api".to_string(),
                        rewrite_mode: PathRewriteMode::Preserve,
                        upstream: upstream_config(),
                    },
                    HttpPathGroup {
                        prefix: "/api/v1".to_string(),
                        rewrite_mode: PathRewriteMode::StripPrefix,
                        upstream: upstream_config(),
                    },
                ],
            },
        )];

        let matched = match_http_route(&rules, Some("api.example.com"), "/api/v1/users").unwrap();
        assert_eq!(matched.matched_prefix, Some("/api/v1"));
        assert!(matches!(matched.rewrite_mode, PathRewriteMode::StripPrefix));
    }

    #[test]
    fn match_http_route_falls_back_to_default_upstream_when_no_group_matches() {
        let rules = vec![rule(
            "host",
            &["api.example.com"],
            HttpUpstreamMatchRule::Host {
                path_groups: vec![HttpPathGroup {
                    prefix: "/api".to_string(),
                    rewrite_mode: PathRewriteMode::Preserve,
                    upstream: upstream_config(),
                }],
            },
        )];

        let matched = match_http_route(&rules, Some("api.example.com"), "/about").unwrap();
        assert!(matched.matched_prefix.is_none());
        assert!(matches!(matched.rewrite_mode, PathRewriteMode::Preserve));
    }

    #[test]
    fn match_http_route_uses_legacy_fallback_without_host() {
        let rules = vec![rule(
            "legacy",
            &[],
            HttpUpstreamMatchRule::LegacyPathPrefix { prefix: "/api".to_string() },
        )];

        let matched = match_http_route(&rules, None, "/api/v1").unwrap();
        assert_eq!(matched.rule_name, "legacy");
    }

    #[test]
    fn path_matches_prefix_uses_segment_boundaries() {
        assert!(path_matches_prefix("/api", "/api"));
        assert!(path_matches_prefix("/api/users", "/api"));
        assert!(!path_matches_prefix("/apix", "/api"));
    }

    #[test]
    fn rewrite_path_and_query_strips_prefix_and_keeps_query() {
        assert_eq!(rewrite_path_and_query("/api/users?id=1", "/api"), "/users?id=1");
        assert_eq!(rewrite_path_and_query("/api", "/api"), "/");
        assert_eq!(rewrite_path_and_query("/foo", "/"), "/foo");
    }

    #[test]
    fn trailing_slash_redirect_location_adds_slash_and_keeps_query() {
        assert_eq!(
            trailing_slash_redirect_location("/ai?mode=demo", Some("/ai")),
            Some("/ai/?mode=demo".to_string())
        );
        assert_eq!(trailing_slash_redirect_location("/ai", Some("/ai/")), Some("/ai/".to_string()));
    }

    #[test]
    fn trailing_slash_redirect_location_ignores_root_and_already_suffixed_paths() {
        assert_eq!(trailing_slash_redirect_location("/", Some("/")), None);
        assert_eq!(trailing_slash_redirect_location("/ai/", Some("/ai")), None);
        assert_eq!(trailing_slash_redirect_location("/ai/assets/app.js", Some("/ai")), None);
        assert_eq!(trailing_slash_redirect_location("/about", None), None);
    }

    #[test]
    fn apply_client_ip_headers_sets_standard_proxy_headers() {
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();

        apply_client_ip_headers(&mut request, "203.0.113.5".parse().unwrap()).unwrap();

        let xff: Vec<_> = request.headers.get_all("x-forwarded-for").iter().collect();
        let forwarded: Vec<_> = request.headers.get_all("forwarded").iter().collect();

        assert_eq!(xff.len(), 1);
        assert_eq!(xff[0], "203.0.113.5");
        assert_eq!(request.headers.get("x-real-ip").unwrap(), "203.0.113.5");
        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded[0], "for=203.0.113.5");
    }

    #[test]
    fn apply_configured_headers_set_overrides_existing_value() {
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        request.insert_header("X-Test", "old").unwrap();

        apply_configured_headers(
            &mut request,
            &[ProxyRequestHeader {
                name: "X-Test".to_string(),
                value: "new".to_string(),
            }],
            &ProxyHeaderConflictMode::Set,
        )
        .unwrap();

        let values: Vec<_> = request.headers.get_all("x-test").iter().collect();
        assert_eq!(values, vec!["new"]);
    }

    #[test]
    fn apply_configured_headers_append_keeps_existing_value() {
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        request.insert_header("X-Test", "old").unwrap();

        apply_configured_headers(
            &mut request,
            &[ProxyRequestHeader {
                name: "X-Test".to_string(),
                value: "new".to_string(),
            }],
            &ProxyHeaderConflictMode::Append,
        )
        .unwrap();

        let values: Vec<_> = request.headers.get_all("x-test").iter().collect();
        assert_eq!(values, vec!["old", "new"]);
    }

    #[test]
    fn classify_proxy_error_maps_route_not_matched_to_404() {
        let error = route_not_matched_error();

        assert_eq!(
            classify_proxy_error(&error),
            GatewayErrorResponse {
                status_code: 404,
                reason_code: "route_not_matched",
                user_message: "No gateway route matches this host and path.",
            }
        );
    }

    #[test]
    fn classify_proxy_error_maps_no_upstream_targets_to_503() {
        let error = no_upstream_targets_error();

        assert_eq!(
            classify_proxy_error(&error),
            GatewayErrorResponse {
                status_code: 503,
                reason_code: "no_upstream_targets",
                user_message: "The matched route has no upstream targets configured.",
            }
        );
    }

    #[test]
    fn classify_proxy_error_maps_upstream_timeout_to_504() {
        let error = pingora::Error::new_up(pingora::ErrorType::ConnectTimedout);

        assert_eq!(
            classify_proxy_error(&error),
            GatewayErrorResponse {
                status_code: 504,
                reason_code: "upstream_timeout",
                user_message: "The upstream service timed out.",
            }
        );
    }

    #[test]
    fn classify_proxy_error_maps_tls_failure_to_502() {
        let error = pingora::Error::new_up(pingora::ErrorType::TLSHandshakeFailure);

        assert_eq!(
            classify_proxy_error(&error),
            GatewayErrorResponse {
                status_code: 502,
                reason_code: "upstream_tls_failed",
                user_message: "The upstream TLS handshake failed.",
            }
        );
    }

    #[test]
    fn classify_proxy_error_maps_downstream_closed_to_no_response() {
        let error = pingora::Error::new_down(pingora::ErrorType::ConnectionClosed);

        assert_eq!(
            classify_proxy_error(&error),
            GatewayErrorResponse {
                status_code: 0,
                reason_code: "downstream_closed",
                user_message: "The client connection closed before the response was sent.",
            }
        );
    }

    #[test]
    fn build_gateway_error_body_includes_reason_code() {
        let body = build_gateway_error_body(&GatewayErrorResponse {
            status_code: 503,
            reason_code: "upstream_connect_failed",
            user_message: "The gateway could not connect to the upstream service.",
        });

        assert!(body.contains("503 Service Unavailable"));
        assert!(body.contains("Reason: upstream_connect_failed"));
        assert!(body.contains("The gateway could not connect to the upstream service."));
    }

    #[test]
    fn build_gateway_error_response_header_sets_text_plain_and_no_store() {
        let response = build_gateway_error_response_header(502, 12).unwrap();

        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        assert_eq!(response.headers.get("content-type").unwrap(), "text/plain; charset=utf-8");
        assert_eq!(response.headers.get("cache-control").unwrap(), "private, no-store");
        assert_eq!(response.headers.get("content-length").unwrap(), "12");
    }

    #[test]
    fn build_redirect_response_header_sets_location_and_empty_body() {
        let response = build_redirect_response_header("/ai/?mode=demo").unwrap();

        assert_eq!(response.status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(response.headers.get("location").unwrap(), "/ai/?mode=demo");
        assert_eq!(response.headers.get("cache-control").unwrap(), "private, no-store");
        assert_eq!(response.headers.get("content-length").unwrap(), "0");
    }
}
