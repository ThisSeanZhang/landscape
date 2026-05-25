use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use bollard::{query_parameters::ListContainersOptions, Docker};
use landscape_common::{
    dns::{check::CheckDnsReq, rule::LandscapeDnsRecordType},
    info::LAND_SYS_BASE_INFO,
    metric::connect::ConnectHistoryQueryParams,
    net::MacAddr,
    route::trace::{FlowMatchRequest, FlowVerdictRequest},
    service::{controller::ConfigController, ServiceStatus, WatchService},
};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router, ErrorData, ServerHandler,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::LandscapeApp;

#[derive(Clone)]
pub struct LandscapeMcpServer {
    app: LandscapeApp,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl LandscapeMcpServer {
    pub fn new(app: LandscapeApp) -> Self {
        Self { app, tool_router: Self::tool_router() }
    }
}

pub fn streamable_http_service(
    app: LandscapeApp,
) -> rmcp::transport::streamable_http_server::StreamableHttpService<
    LandscapeMcpServer,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    StreamableHttpService::new(
        move || Ok(LandscapeMcpServer::new(app.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_stateful_mode(false)
            .with_json_response(true)
            .disable_allowed_hosts(),
    )
}

// ── Request structs ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LimitRequest {
    #[schemars(description = "Maximum number of items returned. Default: 50.")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DnsCheckRequest {
    pub flow_id: u32,
    pub domain: String,
    #[schemars(description = "DNS record type: A, AAAA, or HTTPS.")]
    pub record_type: String,
    #[serde(default)]
    pub apply_filter: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FlowRuleLookupRequest {
    #[schemars(description = "Flow ID (u32). Takes precedence over id if both set.")]
    pub flow_id: Option<u32>,
    #[schemars(description = "Rule UUID.")]
    pub id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GeoCacheSearchRequest {
    #[schemars(description = "Cache type: ip or site.")]
    pub kind: String,
    pub name: Option<String>,
    pub key: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FlowMatchTraceRequest {
    pub src_ipv4: Option<String>,
    pub src_ipv6: Option<String>,
    pub src_mac: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FlowVerdictTraceRequest {
    pub flow_id: u32,
    pub src_ipv4: Option<String>,
    pub src_ipv6: Option<String>,
    pub dst_ips: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GlobalStatsRequest {
    #[serde(default)]
    pub force_refresh: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConnectionHistoryRequest {
    #[schemars(description = "Unix timestamp in seconds.")]
    pub start_time: Option<u64>,
    #[schemars(description = "Unix timestamp in seconds.")]
    pub end_time: Option<u64>,
    #[schemars(description = "Maximum number of items returned. Default: 50.")]
    pub limit: Option<usize>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub port_start: Option<u16>,
    pub port_end: Option<u16>,
    pub l3_proto: Option<u8>,
    pub l4_proto: Option<u8>,
    #[schemars(description = "Filter by flow ID.")]
    pub flow_id: Option<u8>,
    pub sort_key: Option<String>,
    pub sort_order: Option<String>,
    #[schemars(description = "0 = Active, 1 = Closed")]
    pub status: Option<u8>,
    pub gress: Option<u8>,
    pub ifindex: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DhcpLeasesRequest {
    #[schemars(description = "Interface name, e.g. lan0, wan0.")]
    pub iface_name: String,
}

// ── Helper functions ───────────────────────────────────────────────────────

fn truncate_vec<T>(mut values: Vec<T>, limit: Option<usize>) -> Vec<T> {
    values.truncate(limit.unwrap_or(50));
    values
}

fn structured<T: Serialize>(value: T) -> Result<CallToolResult, ErrorData> {
    serde_json::to_value(value).map(CallToolResult::structured).map_err(|err| {
        ErrorData::internal_error(
            "failed to serialize tool result",
            Some(json!({ "error": err.to_string() })),
        )
    })
}

fn structured_as(key: &str, value: impl Serialize) -> Result<CallToolResult, ErrorData> {
    // 截止到20260525，mcp协议要求structured_content必须是object，不能是array
    structured(json!({ key: value }))
}

fn invalid_params(message: impl Into<String>) -> ErrorData {
    ErrorData::invalid_params(message.into(), None)
}

fn parse_record_type(value: &str) -> Result<LandscapeDnsRecordType, ErrorData> {
    match value.trim().to_ascii_uppercase().as_str() {
        "A" => Ok(LandscapeDnsRecordType::A),
        "AAAA" => Ok(LandscapeDnsRecordType::AAAA),
        "HTTPS" => Ok(LandscapeDnsRecordType::HTTPS),
        other => Err(invalid_params(format!("unsupported DNS record type: {other}"))),
    }
}

fn parse_optional<T>(name: &str, value: Option<String>) -> Result<Option<T>, ErrorData>
where
    T: for<'de> Deserialize<'de>,
{
    value
        .map(|value| {
            serde_json::from_value(json!(value))
                .map_err(|err| invalid_params(format!("invalid {name}: {}", err)))
        })
        .transpose()
}

fn parse_optional_ip<T>(name: &str, value: Option<String>) -> Result<Option<T>, ErrorData>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .map(|value| value.parse().map_err(|err| invalid_params(format!("invalid {name}: {err}"))))
        .transpose()
}

fn parse_ip(value: &str) -> Result<IpAddr, ErrorData> {
    value.parse().map_err(|err| invalid_params(format!("invalid IP '{value}': {err}")))
}

fn watch_status(status: WatchService) -> ServiceStatus {
    status.0.borrow().clone()
}

async fn manager_statuses<T>(service: &T) -> BTreeMap<String, ServiceStatus>
where
    T: landscape_common::service::controller::ControllerService + Sync,
{
    service
        .get_all_status()
        .await
        .into_iter()
        .map(|(name, status)| (name, watch_status(status)))
        .collect()
}

// ── Tools ──────────────────────────────────────────────────────────────────

#[tool_router]
impl LandscapeMcpServer {
    // ========================================================================
    // System
    // ========================================================================

    #[tool(
        description = "Return basic system information: hostname, OS, kernel version, CPU architecture, uptime, and software version."
    )]
    async fn landscape_system_info(&self) -> Result<CallToolResult, ErrorData> {
        structured(&*LAND_SYS_BASE_INFO)
    }

    #[tool(
        description = "Return runtime statuses for all per-interface services (dhcp, ip, ipv6pd, lan_ipv6, mss_clamp, nat, pppoe, route_lan, route_wan, firewall, wifi) plus global services (dns, metric, docker)."
    )]
    async fn landscape_service_statuses(&self) -> Result<CallToolResult, ErrorData> {
        structured(json!({
            "global": {
                // Todo 这个状态现在无效
                // "dns": watch_status(self.app.dns_service.get_status().await),
                "metric": self.app.metric_service.status.0.borrow().clone(),
                "docker": self.app.docker_service.status.0.borrow().clone()
            },
            "per_interface": {
                "dhcp_v4": manager_statuses(&self.app.dhcp_v4_server_service).await,
                "ip": manager_statuses(&self.app.wan_ip_service).await,
                "ipv6pd": manager_statuses(&self.app.ipv6_pd_service).await,
                "lan_ipv6": manager_statuses(&self.app.lan_ipv6_service).await,
                "mss_clamp": manager_statuses(&self.app.mss_clamp_service).await,
                "nat": manager_statuses(&self.app.nat_service).await,
                "pppoe": manager_statuses(&self.app.pppd_service).await,
                "route_lan": manager_statuses(&self.app.route_lan_service).await,
                "route_wan": manager_statuses(&self.app.route_wan_service).await,
                "firewall": manager_statuses(&self.app.firewall_service).await,
                "wifi": manager_statuses(&self.app.wifi_service).await
            }
        }))
    }

    // ========================================================================
    // Interfaces
    // ========================================================================

    #[tool(description = "List configured network interfaces and their WAN configurations.")]
    async fn landscape_list_interfaces(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let interfaces = self.app.iface_config_service.read_ifaces().await;
        let wan_configs =
            truncate_vec(self.app.iface_config_service.get_all_wan_iface_config().await, req.limit);
        structured(json!({
            "interfaces": interfaces,
            "wan_configs": wan_configs
        }))
    }

    // ========================================================================
    // Flow Rules
    // ========================================================================

    #[tool(
        description = "List all flow rules sorted by flow_id. Each rule defines how traffic from a source device is matched and routed."
    )]
    async fn landscape_list_flow_rules(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut rules = self.app.flow_rule_service.list().await;
        rules.sort_by(|a, b| a.flow_id.cmp(&b.flow_id));
        structured_as("flow_rules", truncate_vec(rules, req.limit))
    }

    #[tool(
        description = "Look up a single flow rule by flow_id (u32) or by UUID. If both are provided, flow_id takes precedence."
    )]
    async fn landscape_get_flow_rule(
        &self,
        Parameters(req): Parameters<FlowRuleLookupRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Some(id_str) = &req.id {
            let id = Uuid::parse_str(id_str)
                .map_err(|e| invalid_params(format!("invalid UUID: {e}")))?;
            match self.app.flow_rule_service.find_by_id(id).await {
                Some(rule) => structured_as("flow_rule", rule),
                None => Err(invalid_params(format!("flow rule not found: {id_str}"))),
            }
        } else if let Some(flow_id) = req.flow_id {
            let rules: Vec<_> = self
                .app
                .flow_rule_service
                .list()
                .await
                .into_iter()
                .filter(|r| r.flow_id == flow_id)
                .collect();
            if rules.is_empty() {
                Err(invalid_params(format!("flow rule not found for flow_id: {flow_id}")))
            } else {
                structured_as("flow_rules", rules)
            }
        } else {
            Err(invalid_params("either flow_id or id must be provided"))
        }
    }

    #[tool(description = "Trace which flow would match a source IPv4, IPv6, or MAC address.")]
    async fn landscape_trace_flow_match(
        &self,
        Parameters(req): Parameters<FlowMatchTraceRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = landscape_ebpf::map_setting::route::trace_flow_match(FlowMatchRequest {
            src_ipv4: parse_optional_ip("src_ipv4", req.src_ipv4)?,
            src_ipv6: parse_optional_ip("src_ipv6", req.src_ipv6)?,
            src_mac: parse_optional::<MacAddr>("src_mac", req.src_mac)?,
        });
        structured_as("result", result)
    }

    #[tool(
        description = "Trace routing verdicts and cache consistency for a set of destination IPs within a flow."
    )]
    async fn landscape_trace_flow_verdict(
        &self,
        Parameters(req): Parameters<FlowVerdictTraceRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let dst_ips = req.dst_ips.iter().map(|ip| parse_ip(ip)).collect::<Result<Vec<_>, _>>()?;
        let result = landscape_ebpf::map_setting::route::trace_flow_verdict(FlowVerdictRequest {
            flow_id: req.flow_id,
            src_ipv4: parse_optional_ip("src_ipv4", req.src_ipv4)?,
            src_ipv6: parse_optional_ip("src_ipv6", req.src_ipv6)?,
            dst_ips,
        });
        structured_as("result", result)
    }

    // ========================================================================
    // DNS
    // ========================================================================

    #[tool(description = "List all DNS rules sorted by index.")]
    async fn landscape_list_dns_rules(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut rules = self.app.dns_rule_service.list().await;
        rules.sort_by(|a, b| a.index.cmp(&b.index));
        structured_as("dns_rules", truncate_vec(rules, req.limit))
    }

    #[tool(description = "List all configured DNS upstream servers.")]
    async fn landscape_list_dns_upstreams(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let upstreams = self.app.dns_upstream_service.list().await;
        structured_as("upstreams", truncate_vec(upstreams, req.limit))
    }

    #[tool(
        description = "Inspect DNS resolution and rule/cache behavior for a domain. Returns upstream records, cached records, matched rule info, and whether filtering was applied."
    )]
    async fn landscape_check_dns(
        &self,
        Parameters(req): Parameters<DnsCheckRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = self
            .app
            .dns_service
            .check_domain(CheckDnsReq {
                flow_id: req.flow_id,
                domain: req.domain,
                record_type: parse_record_type(&req.record_type)?,
                apply_filter: req.apply_filter,
            })
            .await;
        structured(result)
    }

    #[tool(
        description = "Return DDNS job runtime statuses. Shows sync state, last update time, error messages, and retry info for each DDNS job."
    )]
    async fn landscape_get_ddns_statuses(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let statuses: Vec<_> =
            self.app.ddns_service.get_runtime_statuses().await.into_values().collect();
        structured_as("ddns_statuses", truncate_vec(statuses, req.limit))
    }

    // ========================================================================
    // Firewall & NAT
    // ========================================================================

    #[tool(description = "List all firewall blacklist configurations.")]
    async fn landscape_list_firewall_blacklists(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let blacklists = self.app.firewall_blacklist_service.list().await;
        structured_as("blacklists", truncate_vec(blacklists, req.limit))
    }

    #[tool(description = "List all static NAT (port forwarding) mappings.")]
    async fn landscape_list_static_nat_mappings(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let mappings = self.app.static_nat_mapping_config_service.list().await;
        structured_as("mappings", truncate_vec(mappings, req.limit))
    }

    // ========================================================================
    // Traffic Monitoring
    // ========================================================================

    #[tool(description = "Return realtime active connections with traffic rates.")]
    async fn landscape_get_connections(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let connections = self.app.metric_service.connect_infos().await;
        structured_as("connections", truncate_vec(connections, req.limit))
    }

    #[tool(
        description = "Query connection history with optional filters: time range, source/destination IP, port range, L3/L4 protocol, flow ID, sort key, and status. Returns per-connection traffic totals."
    )]
    async fn landscape_get_connection_history(
        &self,
        Parameters(req): Parameters<ConnectionHistoryRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let sort_key =
            req.sort_key.as_deref().and_then(|s| match s.to_ascii_lowercase().as_str() {
                "time" => Some(landscape_common::metric::connect::ConnectSortKey::Time),
                "port" => Some(landscape_common::metric::connect::ConnectSortKey::Port),
                "ingress" => Some(landscape_common::metric::connect::ConnectSortKey::Ingress),
                "egress" => Some(landscape_common::metric::connect::ConnectSortKey::Egress),
                "duration" => Some(landscape_common::metric::connect::ConnectSortKey::Duration),
                _ => None,
            });
        let sort_order =
            req.sort_order.as_deref().and_then(|s| match s.to_ascii_lowercase().as_str() {
                "asc" => Some(landscape_common::metric::connect::SortOrder::Asc),
                "desc" => Some(landscape_common::metric::connect::SortOrder::Desc),
                _ => None,
            });

        let params = ConnectHistoryQueryParams {
            start_time: req.start_time,
            end_time: req.end_time,
            limit: req.limit,
            src_ip: req.src_ip,
            dst_ip: req.dst_ip,
            port_start: req.port_start,
            port_end: req.port_end,
            l3_proto: req.l3_proto,
            l4_proto: req.l4_proto,
            flow_id: req.flow_id,
            sort_key,
            sort_order,
            status: req.status,
            gress: req.gress,
            ifindex: req.ifindex,
        };

        let history = self.app.metric_service.history_summaries_complex(params).await;
        structured_as("connections", history)
    }

    #[tool(
        description = "Return aggregate global traffic statistics: total ingress/egress bytes, packets, and connection count."
    )]
    async fn landscape_get_global_traffic_stats(
        &self,
        Parameters(req): Parameters<GlobalStatsRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let stats =
            self.app.metric_service.get_global_stats(req.force_refresh).await.map_err(|err| {
                ErrorData::internal_error(
                    "failed to query global traffic stats",
                    Some(json!({ "error": err.to_string() })),
                )
            })?;
        structured_as("stats", stats)
    }

    #[tool(
        description = "Return per-interface realtime traffic statistics (ingress/egress bytes per second, packets per second, active connections)."
    )]
    async fn landscape_get_interface_stats(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let stats = self.app.metric_service.get_realtime_iface_stats().await;
        structured_as("interface_stats", truncate_vec(stats, req.limit))
    }

    // ========================================================================
    // Geo
    // ========================================================================

    #[tool(description = "Search Geo IP or Geo Site cache keys by source name and key substring.")]
    async fn landscape_search_geo_cache(
        &self,
        Parameters(req): Parameters<GeoCacheSearchRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let needle = req.key.map(|key| key.to_ascii_uppercase());
        let limit = req.limit;

        let mut keys = match req.kind.as_str() {
            "ip" => self.app.geo_ip_service.list_all_keys().await,
            "site" => self.app.geo_site_service.list_all_keys().await,
            other => return Err(invalid_params(format!("unsupported geo cache kind: {other}"))),
        };

        keys.retain(|entry| {
            req.name.as_ref().map_or(true, |name| &entry.name == name)
                && needle.as_ref().map_or(true, |key| entry.key.contains(key))
        });

        structured_as("cache_keys", truncate_vec(keys, limit))
    }

    // ========================================================================
    // Docker
    // ========================================================================

    #[tool(description = "List all Docker containers with their names, images, status, and ports.")]
    async fn landscape_list_docker_containers(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut containers = Vec::new();
        if let Ok(docker) = Docker::connect_with_socket_defaults() {
            if let Ok(list) = docker
                .list_containers(Some(ListContainersOptions { all: true, ..Default::default() }))
                .await
            {
                containers = list;
            }
        }
        structured(json!({
            "status": self.app.docker_service.status.0.borrow().clone(),
            "containers": truncate_vec(containers, req.limit)
        }))
    }

    // ========================================================================
    // DHCP
    // ========================================================================

    #[tool(
        description = "Return DHCPv4 assigned IPs (leases) for a given interface. Shows IP, MAC, hostname, lease expiration, and whether the assignment is static."
    )]
    async fn landscape_get_dhcp_leases(
        &self,
        Parameters(req): Parameters<DhcpLeasesRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        match self
            .app
            .dhcp_v4_server_service
            .get_assigned_ips_by_iface_name(req.iface_name.clone())
            .await
        {
            Some(info) => structured_as("dhcp_info", info),
            None => Err(invalid_params(format!("no DHCP info for interface: {}", req.iface_name))),
        }
    }

    // ========================================================================
    // Certificates
    // ========================================================================

    #[tool(
        description = "List all TLS certificates with their names, domains, status (valid/expired/revoked/etc.), expiration timestamps, and whether they serve the gateway or API."
    )]
    async fn landscape_list_certificates(
        &self,
        Parameters(req): Parameters<LimitRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let certs = self.app.cert_service.list().await;
        structured_as("certificates", truncate_vec(certs, req.limit))
    }
}

// ── ServerHandler ──────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for LandscapeMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Landscape Router MCP server. Tools are read-only or diagnostic and require the same bearer token as the HTTP API.")
    }
}
