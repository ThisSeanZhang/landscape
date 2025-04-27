use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Json, Router,
};
use landscape::firewall::rules::update_firewall_rules;
use landscape_common::{
    firewall::{insert_default_firewall_rule, FirewallRuleConfig},
    store::storev2::StoreFileManager,
};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::SimpleResult;

#[derive(Clone)]
struct LandscapeIPMarkServices {
    // lan_store: Arc<Mutex<StoreFileManager<LanIPRuleConfig>>>,
    // wan_store: Arc<Mutex<StoreFileManager<WanIPRuleConfig>>>,
    firewall_rules_store: Arc<Mutex<StoreFileManager<FirewallRuleConfig>>>,
}

pub async fn get_global_mark_paths(
    // mut lan_store: StoreFileManager<LanIPRuleConfig>,
    // mut wan_store: StoreFileManager<WanIPRuleConfig>,
    mut firewall_rules_store: StoreFileManager<FirewallRuleConfig>,
) -> Router {
    if firewall_rules_store.list().is_empty() {
        if let Some(rule) = insert_default_firewall_rule() {
            firewall_rules_store.set(rule);
        }
    }

    // let lan_rules = lan_store.list();
    // let wan_rules = wan_store.list();
    let firewall_rules = firewall_rules_store.list();

    // update_lan_rules(lan_rules, vec![]);
    // update_wan_rules(wan_rules, vec![], LAND_HOME_PATH.join(GEO_IP_FILE_NAME), None).await;
    update_firewall_rules(firewall_rules, vec![]);

    let share_state = LandscapeIPMarkServices {
        // lan_store: Arc::new(Mutex::new(lan_store)),
        // wan_store: Arc::new(Mutex::new(wan_store)),
        firewall_rules_store: Arc::new(Mutex::new(firewall_rules_store)),
    };

    Router::new()
        // .route("/lans", get(list_lan_ip_rules).post(add_lan_ip_rule))
        // .route("/wans", get(list_wan_ip_rules).post(add_wan_ip_rule))
        .route("/firewall", get(list_firewall_rules).post(add_firewall_rule))
        .route("/firewall/:index", delete(del_firewall_rule))
        .with_state(share_state)
}

// async fn list_lan_ip_rules(State(state): State<LandscapeIPMarkServices>) -> Json<Value> {
//     let mut store_lock = state.lan_store.lock().await;
//     let mut results = store_lock.list();
//     drop(store_lock);
//     results.sort_by(|a, b| a.index.cmp(&b.index));
//     let result = serde_json::to_value(results);
//     Json(result.unwrap())
// }

// async fn add_lan_ip_rule(
//     State(state): State<LandscapeIPMarkServices>,
//     Json(lan_config): Json<LanIPRuleConfig>,
// ) -> Json<Value> {
//     let result = SimpleResult { success: true };
//     let mut store_lock = state.lan_store.lock().await;
//     let old_rules = store_lock.list();
//     store_lock.set(lan_config.clone());
//     let new_rules = store_lock.list();
//     drop(store_lock);

//     update_lan_rules(new_rules, old_rules);

//     let result = serde_json::to_value(result);
//     Json(result.unwrap())
// }

// async fn list_wan_ip_rules(State(state): State<LandscapeIPMarkServices>) -> Json<Value> {
//     let mut store_lock = state.wan_store.lock().await;
//     let mut results = store_lock.list();
//     drop(store_lock);

//     results.sort_by(|a, b| a.index.cmp(&b.index));
//     let result = serde_json::to_value(results);
//     Json(result.unwrap())
// }

// async fn add_wan_ip_rule(
//     State(state): State<LandscapeIPMarkServices>,
//     Json(wan_config): Json<WanIPRuleConfig>,
// ) -> Json<Value> {
//     let result = SimpleResult { success: true };
//     let mut store_lock = state.wan_store.lock().await;
//     let old_rules = store_lock.list();
//     store_lock.set(wan_config.clone());
//     let new_rules = store_lock.list();
//     drop(store_lock);

//     update_wan_rules(new_rules, old_rules, LAND_HOME_PATH.join(GEO_IP_FILE_NAME), None).await;

//     let result = serde_json::to_value(result);
//     Json(result.unwrap())
// }

async fn list_firewall_rules(State(state): State<LandscapeIPMarkServices>) -> Json<Value> {
    let mut store_lock = state.firewall_rules_store.lock().await;
    let mut results = store_lock.list();
    drop(store_lock);

    results.sort_by(|a, b| a.index.cmp(&b.index));
    let result = serde_json::to_value(results);
    Json(result.unwrap())
}

async fn add_firewall_rule(
    State(state): State<LandscapeIPMarkServices>,
    Json(firewall_rule): Json<FirewallRuleConfig>,
) -> Json<Value> {
    let result = SimpleResult { success: true };
    let mut store_lock = state.firewall_rules_store.lock().await;
    let old_rules = store_lock.list();
    store_lock.set(firewall_rule.clone());
    let new_rules = store_lock.list();
    drop(store_lock);

    update_firewall_rules(new_rules, old_rules);

    let result = serde_json::to_value(result);
    Json(result.unwrap())
}

async fn del_firewall_rule(
    State(state): State<LandscapeIPMarkServices>,
    Path(index): Path<String>,
) -> Json<Value> {
    let result = SimpleResult { success: true };
    let mut store_lock = state.firewall_rules_store.lock().await;
    let old_rules = store_lock.list();
    store_lock.del(&index);
    let new_rules = store_lock.list();
    drop(store_lock);

    update_firewall_rules(new_rules, old_rules);

    let result = serde_json::to_value(result);
    Json(result.unwrap())
}
