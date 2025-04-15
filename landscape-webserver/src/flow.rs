use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get},
    Json, Router,
};
use landscape_common::{dns::DNSRuleConfig, flow::FlowConfig, store::storev2::StoreFileManager};
use landscape_dns::diff_server::LandscapeFiffFlowDnsService;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::SimpleResult;

#[derive(Clone)]
struct LandscapeFlowServices {
    dns_service: LandscapeFiffFlowDnsService,
    store: Arc<Mutex<StoreFileManager<FlowConfig>>>,
    dns_store: Arc<Mutex<StoreFileManager<DNSRuleConfig>>>,
}

pub async fn get_flow_paths(
    mut store: StoreFileManager<FlowConfig>,
    mut dns_store: StoreFileManager<DNSRuleConfig>,
) -> Router {
    let mut dns_rules = dns_store.list();
    if dns_rules.is_empty() {
        dns_store.set(DNSRuleConfig::default());
        dns_rules = dns_store.list();
    }

    let rules = store.list();
    let share_state = LandscapeFlowServices {
        dns_service: LandscapeFiffFlowDnsService::new().await,
        store: Arc::new(Mutex::new(store)),
        dns_store: Arc::new(Mutex::new(dns_store)),
    };

    share_state.dns_service.restart(53).await;
    share_state.dns_service.update_flow_map(&rules).await;
    share_state.dns_service.init_handle(dns_rules).await;

    tracing::debug!("init flow configs: {:?}", rules);
    landscape::flow::update_flow_matchs(rules, vec![]).await;

    Router::new()
        .route("/", get(get_flow_configs).post(new_flow_config))
        .route("/:index", delete(del_flow_config))
        .route("/dns", get(get_dns_service_status).post(start_dns_service).delete(stop_dns_service))
        .route("/dns/rules", get(get_dns_rules).post(add_dns_rules))
        .route("/dns/rules/:index", delete(del_dns_rules))
        .with_state(share_state)
}

async fn get_dns_service_status(State(state): State<LandscapeFlowServices>) -> Json<Value> {
    let result = serde_json::to_value(state.dns_service);
    Json(result.unwrap())
}

async fn start_dns_service(
    State(state): State<LandscapeFlowServices>,
    Json(DNSStartRequest { udp_port, .. }): Json<DNSStartRequest>,
) -> Json<Value> {
    let mut get_dns_store = state.dns_store.lock().await;
    let dns_rules = get_dns_store.list();
    drop(get_dns_store);
    // TODO 重置 Flow 相关 map 信息

    state.dns_service.init_handle(dns_rules).await;
    state.dns_service.restart(udp_port).await;

    let result = serde_json::to_value(state.dns_service);
    Json(result.unwrap())
}

async fn stop_dns_service(State(state): State<LandscapeFlowServices>) -> Json<Value> {
    state.dns_service.stop();
    let result = serde_json::to_value(state.dns_service);
    Json(result.unwrap())
}

async fn get_flow_configs(State(state): State<LandscapeFlowServices>) -> Json<Value> {
    let mut get_store = state.store.lock().await;
    let mut flow_configs = get_store.list();
    flow_configs.sort_by(|a, b| a.flow_id.cmp(&b.flow_id));
    let result = serde_json::to_value(flow_configs);
    Json(result.unwrap())
}

async fn new_flow_config(
    State(state): State<LandscapeFlowServices>,
    Json(flow_config): Json<FlowConfig>,
) -> Json<Value> {
    let mut get_store = state.store.lock().await;
    let old_records = get_store.list();
    get_store.set(flow_config);
    let new_records = get_store.list();
    drop(get_store);

    state.dns_service.update_flow_map(&new_records).await;
    landscape::flow::update_flow_matchs(new_records, old_records).await;

    let result = serde_json::to_value(SimpleResult { success: true });
    Json(result.unwrap())
}

async fn del_flow_config(
    State(state): State<LandscapeFlowServices>,
    Path(index): Path<String>,
) -> Json<Value> {
    let mut get_store = state.store.lock().await;
    let old_records = get_store.list();
    get_store.del(&index);
    let new_records = get_store.list();
    drop(get_store);

    state.dns_service.update_flow_map(&new_records).await;
    landscape::flow::update_flow_matchs(new_records, old_records).await;

    let result = serde_json::to_value(SimpleResult { success: true });
    Json(result.unwrap())
}

async fn get_dns_rules(
    State(state): State<LandscapeFlowServices>,
    Query(DnsRuleQuery { flow_id }): Query<DnsRuleQuery>,
) -> Json<Value> {
    let mut get_store = state.dns_store.lock().await;
    let mut dns_rules = get_store.list();
    dns_rules.sort_by(|a, b| a.index.cmp(&b.index));
    if let Some(flow_id) = flow_id {
        dns_rules.retain(|rule| rule.flow_id == flow_id);
    }
    let result = serde_json::to_value(dns_rules);
    Json(result.unwrap())
}

async fn add_dns_rules(
    State(state): State<LandscapeFlowServices>,
    Json(dns_rule): Json<DNSRuleConfig>,
) -> Json<Value> {
    let flow_id = dns_rule.flow_id;
    let mut get_store = state.dns_store.lock().await;
    get_store.set(dns_rule);
    let dns_rules = get_store.list();
    drop(get_store);
    state.dns_service.flush_specific_flow_dns_rule(flow_id, dns_rules).await;

    let result = serde_json::to_value(SimpleResult { success: true });
    Json(result.unwrap())
}

async fn del_dns_rules(
    State(state): State<LandscapeFlowServices>,
    Path(index): Path<String>,
) -> Json<Value> {
    let mut get_store = state.dns_store.lock().await;
    if let Some(flow_config) = get_store.get(&index) {
        get_store.del(&index);
        let dns_rules = get_store.list();
        drop(get_store);
        state.dns_service.flush_specific_flow_dns_rule(flow_config.flow_id, dns_rules).await;
    }

    let result = serde_json::to_value(SimpleResult { success: true });
    Json(result.unwrap())
}

#[derive(Clone, Serialize, Deserialize)]
struct DNSStartRequest {
    udp_port: u16,
}

#[derive(Deserialize)]
struct DnsRuleQuery {
    flow_id: Option<u32>,
}
