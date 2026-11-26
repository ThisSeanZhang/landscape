use crate::health::GatewayHealth;
use bytes::Bytes;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use landscape_common::sys_service::gateway::{
    ClientIpHeaderPolicy, HttpUpstreamTarget, LoadBalanceMethod, PathRewriteMode,
    ProxyHeaderConflictMode,
};
use pingora::http::{RequestHeader, ResponseHeader, StatusCode};
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::SharedGatewayRoutes;
use crate::routes::{
    CompiledHttpRoute, CompiledRequestHeader, CompiledUpstream, path_matches_prefix,
};

const GATEWAY_ROUTE_NOT_MATCHED: pingora::ErrorType =
    pingora::ErrorType::new_code("GatewayRouteNotMatched", 404);
const GATEWAY_NO_UPSTREAM_TARGETS: pingora::ErrorType =
    pingora::ErrorType::new_code("GatewayNoUpstreamTargets", 503);
const GATEWAY_NO_HEALTHY_UPSTREAMS: pingora::ErrorType =
    pingora::ErrorType::new_code("GatewayNoHealthyUpstreams", 503);
const GATEWAY_PATH_REWRITE_FAILED: pingora::ErrorType =
    pingora::ErrorType::new_code("GatewayPathRewriteFailed", 500);
const GATEWAY_TRAILING_SLASH_REDIRECT: pingora::ErrorType =
    pingora::ErrorType::new_code("GatewayTrailingSlashRedirect", 308);

pub struct LandscapeReverseProxy {
    routes: SharedGatewayRoutes,
    health: GatewayHealth,
    round_robin_counter: AtomicUsize,
}

impl LandscapeReverseProxy {
    pub fn new(routes: SharedGatewayRoutes) -> Self {
        Self::with_health(routes, GatewayHealth::default())
    }

    pub(crate) fn with_health(routes: SharedGatewayRoutes, health: GatewayHealth) -> Self {
        Self {
            routes,
            health,
            round_robin_counter: AtomicUsize::new(0),
        }
    }

    fn route_for_request(
        &self,
        ctx: &mut ProxyCtx,
        host: Option<&str>,
        path: &str,
    ) -> pingora::Result<Arc<CompiledHttpRoute>> {
        // Retries and later callbacks must use the same route generation as the
        // first upstream selection, even if rules are published in between.
        if let Some(route) = &ctx.matched_route {
            return Ok(route.clone());
        }
        let route =
            self.routes.load().match_http_route(host, path).ok_or_else(route_not_matched_error)?;
        ctx.matched_rule_name = Some(route.rule_name.clone());
        ctx.matched_route = Some(route.clone());
        Ok(route)
    }
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
    remaining_peers: VecDeque<HttpPeer>,
    pub matched_rule_name: Option<String>,
    request_host: Option<String>,
    request_path: Option<String>,
    rewritten_path: Option<String>,
    redirect_location: Option<String>,
    selected_target: Option<SelectedTarget>,
    matched_route: Option<Arc<CompiledHttpRoute>>,
}

#[async_trait]
impl ProxyHttp for LandscapeReverseProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx {
            remaining_peers: VecDeque::new(),
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
        if let Some(peer) = ctx.remaining_peers.pop_front() {
            return Ok(Box::new(peer));
        }
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

        let matched_route = self.route_for_request(ctx, host.as_deref(), path)?;

        if let Some(location) = trailing_slash_redirect_location(
            req.uri.path_and_query().map(|value| value.as_str()).unwrap_or(path),
            matched_route.matched_prefix.as_deref(),
        ) {
            ctx.redirect_location = Some(location);
            return Err(trailing_slash_redirect_error());
        }

        let (mut peers, selected_target) = resolve_peers(
            &matched_route.upstream,
            &self.health,
            &self.round_robin_counter,
            host.as_deref().unwrap_or(""),
            path,
        )
        .await?;
        ctx.selected_target = Some(selected_target);
        let peer = peers.pop_front().ok_or_else(no_upstream_targets_error)?;
        ctx.remaining_peers = peers;
        Ok(Box::new(peer))
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut error: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        if !ctx.remaining_peers.is_empty() {
            // Try the next address of this same upstream before a request has been sent.
            error.set_retry(true);
        }
        error
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        ctx.remaining_peers.clear();
        let Some(matched_route) = ctx.matched_route.as_ref() else {
            return Ok(());
        };

        ctx.rewritten_path = apply_path_rewrite(upstream_request, matched_route)?;

        if matches!(matched_route.upstream.client_ip_headers, ClientIpHeaderPolicy::Standard)
            && let Some(client_addr) = session.client_addr().and_then(|addr| addr.as_inet())
        {
            apply_client_ip_headers(upstream_request, client_addr.ip())?;
        }

        apply_configured_headers(
            upstream_request,
            &matched_route.upstream.request_headers,
            &matched_route.upstream.header_conflict_mode,
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

fn apply_path_rewrite(
    upstream_request: &mut RequestHeader,
    matched_route: &CompiledHttpRoute,
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

    let normalized_prefix = prefix;
    let stripped_path = if normalized_prefix == "/" {
        path.to_string()
    } else if path == normalized_prefix {
        "/".to_string()
    } else {
        let remainder = path.strip_prefix(normalized_prefix).unwrap_or(path);
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
    let normalized_prefix = prefix;
    if normalized_prefix == "/" {
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
    headers: &[CompiledRequestHeader],
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

async fn resolve_peers(
    upstream: &CompiledUpstream,
    health: &GatewayHealth,
    counter: &AtomicUsize,
    host: &str,
    path: &str,
) -> pingora::Result<(VecDeque<HttpPeer>, SelectedTarget)> {
    let seed = match upstream.load_balance {
        LoadBalanceMethod::RoundRobin if upstream.targets.len() > 1 => {
            counter.fetch_add(1, Ordering::Relaxed) as u64
        }
        LoadBalanceMethod::Random => fnv1a_hash(host, path),
        _ => fnv1a_hash(host, ""),
    };
    let target = health.select(upstream, seed).ok_or_else(|| {
        if upstream.targets.is_empty() {
            no_upstream_targets_error()
        } else {
            pingora::Error::new(GATEWAY_NO_HEALTHY_UPSTREAMS)
        }
    })?;
    let timeout = std::time::Duration::from_secs(10);
    let connection_host = target.connection_host();
    // An IPv6 zone selects the socket interface. Certificates identify the IP itself.
    let tls_name = match connection_host.split_once('%') {
        Some((ip, _)) if ip.contains(':') => ip,
        _ => connection_host,
    };
    let addresses =
        tokio::time::timeout(timeout, tokio::net::lookup_host((connection_host, target.port)))
            .await
            .map_err(|_| pingora::Error::new_up(pingora::ErrorType::ConnectTimedout))?
            .map_err(|error| {
                pingora::Error::because(
                    pingora::ErrorType::ConnectError,
                    "resolving gateway upstream",
                    error,
                )
                .into_up()
            })?;
    let peers: VecDeque<_> = addresses
        .map(|address| {
            // Construct the peer from a resolved socket address; DNS errors stay recoverable.
            let mut peer = HttpPeer::new(address, target.tls, tls_name.to_owned());
            if target.tls && target.skip_cert_verify {
                peer.options.verify_cert = false;
                peer.options.verify_hostname = false;
            }
            peer.options.connection_timeout = Some(timeout);
            peer
        })
        .collect();
    if peers.is_empty() {
        return Err(pingora::Error::explain(
            pingora::ErrorType::ConnectError,
            "upstream has no addresses",
        )
        .into_up());
    }
    Ok((peers, SelectedTarget::from_target(target)))
}

fn fnv1a_hash(host: &str, path: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for b in host.bytes().chain(path.bytes()) {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn classify_proxy_error(error: &pingora::Error) -> GatewayErrorResponse {
    if error.etype() == &GATEWAY_NO_HEALTHY_UPSTREAMS {
        return GatewayErrorResponse {
            status_code: 503,
            reason_code: "no_healthy_upstreams",
            user_message: "The matched route has no healthy upstream targets.",
        };
    }
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
        ClientIpHeaderPolicy, HttpPathGroup, HttpUpstreamConfig, HttpUpstreamMatchRule,
        HttpUpstreamRuleConfig, ProxyHeaderConflictMode, ProxyRequestHeader,
    };

    use crate::routes::CompiledGatewayRoutes;

    fn match_http_route(
        rules: &[HttpUpstreamRuleConfig],
        host: Option<&str>,
        path: &str,
    ) -> Option<Arc<CompiledHttpRoute>> {
        CompiledGatewayRoutes::compile(rules).unwrap().match_http_route(host, path)
    }

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

    #[tokio::test]
    async fn ipv6_upstreams_keep_the_scope_on_the_socket_and_use_the_ip_for_tls() {
        use pingora::upstreams::peer::Peer;

        for (host, tls_name, socket) in [
            ("[::1]", "::1", "[::1]:8443"),
            ("::1", "::1", "[::1]:8443"),
            ("[fe80::1%1]", "fe80::1", "[fe80::1%1]:8443"),
            ("fe80::1%1", "fe80::1", "[fe80::1%1]:8443"),
        ] {
            let mut rule = rule(
                "ipv6",
                &["test.example"],
                HttpUpstreamMatchRule::Host { path_groups: vec![] },
            );
            rule.upstream.targets = vec![target(host, 8443, 1)];
            rule.upstream.targets[0].tls = true;
            let route = match_http_route(&[rule], Some("test.example"), "/").unwrap();
            let (peers, _) = resolve_peers(
                &route.upstream,
                &GatewayHealth::default(),
                &AtomicUsize::new(0),
                "test.example",
                "/",
            )
            .await
            .unwrap();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].sni, tls_name);
            assert!(rustls::pki_types::ServerName::try_from(peers[0].sni.as_str()).is_ok());
            assert_eq!(peers[0].address().to_string(), socket);
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
        assert_eq!(matched.matched_prefix.as_deref(), Some("/api/v1"));
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
    fn legacy_domains_must_not_normalize_into_a_hostless_fallback() {
        let invalid = rule(
            "legacy",
            &[" ", "."],
            HttpUpstreamMatchRule::LegacyPathPrefix { prefix: "/api".to_string() },
        );
        assert!(matches!(
            CompiledGatewayRoutes::compile(&[invalid]),
            Err(landscape_common::sys_service::gateway::GatewayError::DomainsRequired { .. })
        ));
    }

    #[test]
    fn compiled_routes_normalize_domains_and_path_groups() {
        let rules = vec![rule(
            "normalized",
            &[" API.Example.Com. "],
            HttpUpstreamMatchRule::Host {
                path_groups: vec![HttpPathGroup {
                    prefix: " /api/ ".to_string(),
                    rewrite_mode: PathRewriteMode::StripPrefix,
                    upstream: upstream_config(),
                }],
            },
        )];
        let routes = CompiledGatewayRoutes::compile(&rules).unwrap();
        let route = routes.match_http_route(Some("Api.Example.Com."), "/api/items").unwrap();
        assert_eq!(route.matched_prefix.as_deref(), Some("/api"));
        let mut request = RequestHeader::build("GET", b"/api/items?q=1", None).unwrap();
        assert_eq!(
            apply_path_rewrite(&mut request, &route).unwrap().as_deref(),
            Some("/items?q=1")
        );
        assert_eq!(
            trailing_slash_redirect_location("/api?q=1", route.matched_prefix.as_deref())
                .as_deref(),
            Some("/api/?q=1")
        );
        assert!(
            routes
                .match_http_route(Some("api.example.com"), "/apix")
                .unwrap()
                .matched_prefix
                .is_none()
        );
    }

    #[test]
    fn compile_failure_keeps_the_published_http_and_sni_routes() {
        use landscape_common::sys_service::gateway::GatewayError;
        let http =
            rule("http", &["api.example.com"], HttpUpstreamMatchRule::Host { path_groups: vec![] });
        let sni = rule("sni", &["tls.example.com"], HttpUpstreamMatchRule::SniProxy);
        let initial = CompiledGatewayRoutes::compile(&[http.clone(), sni.clone()]).unwrap();
        let shared = Arc::new(crate::routes::GatewayRoutes::new(initial));
        let before = shared.load_full();
        let mut invalid = http;
        invalid.upstream.request_headers.push(ProxyRequestHeader {
            name: "X-Test".to_string(),
            value: "bad\r\nvalue".to_string(),
        });
        let result = CompiledGatewayRoutes::compile(&[invalid.clone(), sni]);
        assert!(matches!(result, Err(GatewayError::InvalidHeaderValue { .. })));
        assert!(Arc::ptr_eq(&before, &shared.load_full()));
        assert_eq!(
            before.match_http_route(Some("api.example.com"), "/").unwrap().rule_name,
            "http"
        );
        assert_eq!(before.match_sni_route("tls.example.com").unwrap().rule_name, "sni");

        invalid.upstream.request_headers[0].name = "bad name".to_string();
        invalid.upstream.request_headers[0].value = "valid".to_string();
        assert!(matches!(
            CompiledGatewayRoutes::compile(&[invalid]),
            Err(GatewayError::InvalidHeaderName { .. })
        ));
    }

    #[test]
    fn compilation_rejects_invalid_and_duplicate_path_groups() {
        use landscape_common::sys_service::gateway::GatewayError;
        let group = |prefix: &str| HttpPathGroup {
            prefix: prefix.to_string(),
            rewrite_mode: PathRewriteMode::Preserve,
            upstream: upstream_config(),
        };
        let invalid = rule(
            "bad",
            &["example.com"],
            HttpUpstreamMatchRule::Host { path_groups: vec![group("api")] },
        );
        assert!(matches!(
            CompiledGatewayRoutes::compile(&[invalid]),
            Err(GatewayError::InvalidPathPrefix { .. })
        ));
        let duplicate = rule(
            "duplicate",
            &["example.com"],
            HttpUpstreamMatchRule::Host { path_groups: vec![group("/api"), group(" /api/ ")] },
        );
        assert!(matches!(
            CompiledGatewayRoutes::compile(&[duplicate]),
            Err(GatewayError::DuplicatePathGroupPrefix { .. })
        ));
    }

    #[tokio::test]
    async fn request_pins_route_across_reload_and_retry() {
        let mut upstream = upstream_config();
        upstream.targets.push(target("127.0.0.2", 8080, 1));
        upstream.request_headers.push(ProxyRequestHeader {
            name: "X-Version".to_string(),
            value: "old".to_string(),
        });
        let mut old = rule(
            "old",
            &["api.example.com"],
            HttpUpstreamMatchRule::Host {
                path_groups: vec![HttpPathGroup {
                    prefix: "/api".to_string(),
                    rewrite_mode: PathRewriteMode::StripPrefix,
                    upstream,
                }],
            },
        );
        let shared = Arc::new(crate::routes::GatewayRoutes::new(
            CompiledGatewayRoutes::compile(&[old.clone()]).unwrap(),
        ));
        let proxy = LandscapeReverseProxy::new(shared.clone());
        let mut ctx = proxy.new_ctx();
        let selected =
            proxy.route_for_request(&mut ctx, Some("api.example.com"), "/api/items").unwrap();
        let (_, first_target) = resolve_peers(
            &selected.upstream,
            &proxy.health,
            &proxy.round_robin_counter,
            "api.example.com",
            "/api/items",
        )
        .await
        .unwrap();
        assert_eq!(first_target.address, "127.0.0.1");

        old.name = "new".to_string();
        old.match_rule = HttpUpstreamMatchRule::Host { path_groups: vec![] };
        old.upstream.targets = vec![target("127.0.0.3", 8080, 1), target("127.0.0.4", 8080, 1)];
        old.upstream.request_headers.push(ProxyRequestHeader {
            name: "X-Version".to_string(),
            value: "new".to_string(),
        });
        shared.store(Arc::new(CompiledGatewayRoutes::compile(&[old]).unwrap()));

        let retry =
            proxy.route_for_request(&mut ctx, Some("api.example.com"), "/api/items").unwrap();
        assert!(Arc::ptr_eq(&selected, &retry));
        let mut request = RequestHeader::build("GET", b"/api/items?q=1", None).unwrap();
        apply_path_rewrite(&mut request, ctx.matched_route.as_ref().unwrap()).unwrap();
        apply_configured_headers(
            &mut request,
            &retry.upstream.request_headers,
            &retry.upstream.header_conflict_mode,
        )
        .unwrap();
        assert_eq!(request.uri.path_and_query().unwrap().as_str(), "/items?q=1");
        assert_eq!(request.headers.get("x-version").unwrap(), "old");

        let next = proxy
            .route_for_request(&mut proxy.new_ctx(), Some("api.example.com"), "/api/items")
            .unwrap();
        assert_eq!(next.rule_name, "new");
        let (_, next_target) = resolve_peers(
            &next.upstream,
            &proxy.health,
            &proxy.round_robin_counter,
            "api.example.com",
            "/api/items",
        )
        .await
        .unwrap();
        // Updating configuration must not reset the long-lived proxy's counter.
        assert_eq!(next_target.address, "127.0.0.4");
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
        assert_eq!(trailing_slash_redirect_location("/ai", Some("/ai")), Some("/ai/".to_string()));
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
            &[CompiledRequestHeader {
                name: "X-Test".parse().unwrap(),
                value: "new".parse().unwrap(),
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
            &[CompiledRequestHeader {
                name: "X-Test".parse().unwrap(),
                value: "new".parse().unwrap(),
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
