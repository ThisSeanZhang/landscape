use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get},
    Json, Router,
};
use landscape_common::{
    args::LAND_HOME_PATH, dns::DNSRuleConfig, flow::FlowConfig, ip_mark::WanIPRuleConfig,
    store::storev2::StoreFileManager, GEO_IP_FILE_NAME,
};
use landscape_dns::{diff_server::LandscapeFiffFlowDnsService, ip_rule::update_wan_rules};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::{
    error::{LandscapeApiError, LandscapeResult},
    SimpleResult,
};

#[derive(Clone)]
struct LandscapeFlowServices {
    dns_service: LandscapeFiffFlowDnsService,
    store: Arc<Mutex<StoreFileManager<FlowConfig>>>,
    dns_store: Arc<Mutex<StoreFileManager<DNSRuleConfig>>>,
    wanip_store: Arc<Mutex<StoreFileManager<WanIPRuleConfig>>>,
}

pub async fn get_flow_paths(
    mut store: StoreFileManager<FlowConfig>,
    mut dns_store: StoreFileManager<DNSRuleConfig>,
    mut wanip_store: StoreFileManager<WanIPRuleConfig>,
) -> Router {
    let mut dns_rules = dns_store.list();
    if dns_rules.is_empty() {
        dns_store.set(DNSRuleConfig::default());
        dns_rules = dns_store.list();
    }

    let rules = store.list();
    let wanip_rules = wanip_store.list();
    let share_state = LandscapeFlowServices {
        dns_service: LandscapeFiffFlowDnsService::new().await,
        store: Arc::new(Mutex::new(store)),
        dns_store: Arc::new(Mutex::new(dns_store)),
        wanip_store: Arc::new(Mutex::new(wanip_store)),
    };

    share_state.dns_service.restart(53).await;
    share_state.dns_service.update_flow_map(&rules).await;
    share_state.dns_service.init_handle(dns_rules).await;

    tracing::debug!("init flow configs: {:?}", rules);
    landscape::flow::update_flow_matchs(rules, vec![]).await;

    update_wan_rules(wanip_rules, vec![], LAND_HOME_PATH.join(GEO_IP_FILE_NAME), None).await;

    Router::new()
        .route("/", get(get_flow_configs).post(new_flow_config))
        .route("/:index", delete(del_flow_config))
        .route("/dns", get(get_dns_service_status).post(start_dns_service).delete(stop_dns_service))
        .route("/dns/rules", get(get_dns_rules).post(add_dns_rules))
        .route("/dns/rules/:index", delete(del_dns_rules))
        .route("/:flow_id/wans", get(list_wan_ip_rules).post(add_wan_ip_rule))
        .route("/:flow_id/wans/:rule_id", get(get_wan_ip_rule).put(update_wan_ip_rule))
        // .route("/:flow_id/wans/:wans_id",delete() )
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

async fn get_wan_ip_rule(
    State(state): State<LandscapeFlowServices>,
    Path((_flow_id, rule_id)): Path<(u32, String)>,
) -> LandscapeResult<Json<WanIPRuleConfig>> {
    let result = {
        let mut store_lock = state.wanip_store.lock().await;
        let result = store_lock.get(&rule_id);
        drop(store_lock);
        result
    };

    if let Some(result) = result {
        Ok(Json(result))
    } else {
        Err(LandscapeApiError::NotFound(format!("id: {rule_id}")))
    }
}

async fn list_wan_ip_rules(
    State(state): State<LandscapeFlowServices>,
    Path(flow_id): Path<u32>,
) -> Json<Value> {
    let mut store_lock = state.wanip_store.lock().await;
    let mut results = store_lock.list();
    drop(store_lock);

    results.sort_by(|a, b| a.index.cmp(&b.index));
    results.retain(|rule| rule.flow_id == flow_id);

    let result = serde_json::to_value(results);
    Json(result.unwrap())
}

async fn add_wan_ip_rule(
    State(state): State<LandscapeFlowServices>,
    Path(flow_id): Path<u32>,
    Json(mut wan_config): Json<WanIPRuleConfig>,
) -> Json<Value> {
    let result = SimpleResult { success: true };
    wan_config.id = landscape_common::utils::id::gen_uuid();
    let mut store_lock = state.wanip_store.lock().await;
    let mut old_rules = store_lock.list();
    store_lock.set(wan_config.clone());
    let mut new_rules = store_lock.list();
    drop(store_lock);

    old_rules.retain(|e| e.flow_id == flow_id);
    new_rules.retain(|e| e.flow_id == flow_id);

    update_wan_rules(new_rules, old_rules, LAND_HOME_PATH.join(GEO_IP_FILE_NAME), None).await;

    let result = serde_json::to_value(result);
    Json(result.unwrap())
}

/// TODO: reduce code copy
async fn update_wan_ip_rule(
    State(state): State<LandscapeFlowServices>,
    Path((flow_id, rule_id)): Path<(u32, String)>,
    Json(mut wan_config): Json<WanIPRuleConfig>,
) -> Json<Value> {
    let result = SimpleResult { success: true };
    wan_config.id = rule_id;
    wan_config.flow_id = flow_id;
    let mut store_lock = state.wanip_store.lock().await;
    let mut old_rules = store_lock.list();
    store_lock.set(wan_config.clone());
    let mut new_rules = store_lock.list();
    drop(store_lock);

    old_rules.retain(|e| e.flow_id == flow_id);
    new_rules.retain(|e| e.flow_id == flow_id);

    update_wan_rules(new_rules, old_rules, LAND_HOME_PATH.join(GEO_IP_FILE_NAME), None).await;

    let result = serde_json::to_value(result);
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
