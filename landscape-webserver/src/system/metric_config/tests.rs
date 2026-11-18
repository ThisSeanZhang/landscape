use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::{LAND_CONFIG, args::WebCommArgs, sys_config::RuntimeConfig};
use landscape_database::provider::LandscapeDBServiceProvider;
use serde_json::{Value, json};
use tokio::sync::Barrier;
use tower::ServiceExt;

const DNS_PATH: &str = "/config/edit/metric/dns";
const CONNECT_PATH: &str = "/config/edit/metric/connect";
const SELF_MONITOR_PATH: &str = "/config/edit/self_monitor";

async fn app() -> (tempfile::TempDir, LandscapeConfigService, Router) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(LAND_CONFIG), "[metric]\nmode = 'memory'\n").unwrap();
    let runtime = RuntimeConfig::new(WebCommArgs {
        config_dir: Some(dir.path().into()),
        ..Default::default()
    });
    let configs =
        LandscapeConfigService::new(runtime, LandscapeDBServiceProvider::mem_test_db().await).await;
    let (router, _) = super::paths().with_state(configs.clone()).split_for_parts();
    (dir, configs, router)
}

async fn request(router: &Router, path: &str, payload: Option<Value>) -> (StatusCode, Value) {
    let request = match payload {
        Some(payload) => Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string())),
        None => Request::get(path).body(Body::empty()),
    }
    .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn read(router: &Router, path: &str) -> Value {
    let (status, body) = request(router, path, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["data"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn concurrent_metric_edits_reject_one_stale_hash_and_preserve_the_other_section() {
    let (dir, configs, router) = app().await;
    let dns = read(&router, DNS_PATH).await;
    let connect = read(&router, CONNECT_PATH).await;
    let saved_monitor = read(&router, SELF_MONITOR_PATH).await;
    let monitor = configs.subscribe_self_monitor();
    let barrier = Arc::new(Barrier::new(3));
    let save = |path: &'static str, config: Value, hash: &Value| {
        let router = router.clone();
        let barrier = barrier.clone();
        let payload = json!({ "config": config, "expected_hash": hash });
        tokio::spawn(async move {
            barrier.wait().await;
            request(&router, path, Some(payload)).await
        })
    };
    let dns_edit = |days| {
        let mut config = dns["config"].clone();
        config["retention_days"] = json!(days);
        save(DNS_PATH, config, &dns["hash"])
    };
    let mut connection = connect["config"].clone();
    connection["write_batch_size"] = json!(321);
    let (first, second, sibling) =
        tokio::join!(dns_edit(7), dns_edit(14), save(CONNECT_PATH, connection, &connect["hash"]));
    let (first, second) = (first.unwrap(), second.unwrap());
    assert_eq!(sibling.unwrap().0, StatusCode::OK);
    let (days, conflict) = match (first.0, second.0) {
        (StatusCode::OK, StatusCode::CONFLICT) => (7, second.1),
        (StatusCode::CONFLICT, StatusCode::OK) => (14, first.1),
        statuses => panic!("unexpected save responses: {statuses:?}"),
    };
    assert_eq!(conflict["error_id"], "config.conflict");
    let saved = read(&router, DNS_PATH).await;
    assert_ne!(saved["hash"], dns["hash"]);
    assert_eq!(saved["config"]["retention_days"], days);
    assert_eq!(read(&router, CONNECT_PATH).await["config"]["write_batch_size"], 321);
    assert_eq!(read(&router, SELF_MONITOR_PATH).await, saved_monitor);
    let restart = RuntimeConfig::new(WebCommArgs {
        config_dir: Some(dir.path().into()),
        ..Default::default()
    });
    assert_eq!(restart.metric_dns.retention_days, days);
    assert_eq!(restart.metric_connect.write_batch_size, 321);
    assert_eq!(restart.metric_dns, *configs.subscribe_dns_metric().borrow());
    assert_eq!(restart.metric_connect, *configs.subscribe_connect_metric().borrow());
    assert_eq!(restart.self_monitor, *monitor.borrow());
    assert!(!monitor.has_changed().unwrap());
}

#[tokio::test]
async fn rejected_metric_edits_leave_the_file_hash_and_subscriptions_unchanged() {
    let (_dir, configs, router) = app().await;
    let before = read(&router, DNS_PATH).await;
    let file = std::fs::read(configs.get_config_path()).unwrap();
    let dns = configs.subscribe_dns_metric();
    let connect = configs.subscribe_connect_metric();
    let monitor = configs.subscribe_self_monitor();
    let mut invalid =
        vec![(json!({"cleanup_time_budget_secs": 61}), "metric.invalid_cleanup_time_budget")];
    if !cfg!(feature = "metric-persistent") {
        invalid.push((json!({"backend": "sqlite"}), "metric.sqlite_unavailable"));
    }
    for (store, error_id) in invalid {
        let payload = json!({ "config": {"store": store}, "expected_hash": before["hash"] });
        let (status, body) = request(&router, DNS_PATH, Some(payload)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error_id"], error_id);
        assert_eq!(read(&router, DNS_PATH).await, before);
        assert_eq!(std::fs::read(configs.get_config_path()).unwrap(), file);
        assert!(!dns.has_changed().unwrap());
        assert!(!connect.has_changed().unwrap());
        assert!(!monitor.has_changed().unwrap());
    }
}
