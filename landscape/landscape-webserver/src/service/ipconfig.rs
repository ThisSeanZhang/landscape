use std::{collections::HashMap, path::PathBuf, sync::Arc};

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use landscape::{
    service::{
        ipconfig::{IfaceIpServiceConfig, IpConfigManager},
        WatchServiceStatus,
    },
    store::StoreFileManager,
};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::{error::LandscapeApiError, SimpleResult};

#[derive(Clone)]
struct LandscapeIfaceIpServices {
    service: IpConfigManager,
    store: Arc<Mutex<StoreFileManager>>,
}

pub async fn get_iface_service_paths(home_path: PathBuf) -> Router {
    let store = StoreFileManager::new(home_path.clone(), "iface_ipconfig_service".to_string());

    let share_state = LandscapeIfaceIpServices {
        service: IpConfigManager::init(vec![]).await,
        store: Arc::new(Mutex::new(store)),
    };
    Router::new()
        .route("/ipconfigs/status", get(get_all_ipconfig_status))
        .route(
            "/ipconfigs/:iface_name",
            get(get_iface_service_conifg)
                .post(handle_iface_service_status)
                .delete(delete_and_stop_iface_service),
        )
        .route("/ipconfigs/:iface_name/status", get(get_iface_service_status))
        .with_state(share_state)
}

async fn get_all_ipconfig_status(State(state): State<LandscapeIfaceIpServices>) -> Json<Value> {
    let read_lock = state.service.services.read().await;
    let mut result = HashMap::new();
    for (key, (iface_status, _)) in read_lock.iter() {
        result.insert(key.clone(), iface_status.clone());
    }
    drop(read_lock);
    let result = serde_json::to_value(result);
    Json(result.unwrap())
}

async fn get_iface_service_conifg(
    State(state): State<LandscapeIfaceIpServices>,
    Path(iface_name): Path<String>,
) -> Result<Json<Value>, LandscapeApiError> {
    let mut read_lock = state.store.lock().await;
    if let Some(iface_config) = read_lock.get(iface_name) {
        let data: Value = serde_json::from_str(&iface_config)?;
        Ok(Json(data))
    } else {
        Err(LandscapeApiError::NotFound("can not find".into()))
    }
}

async fn get_iface_service_status(
    State(state): State<LandscapeIfaceIpServices>,
    Path(iface_name): Path<String>,
) -> Json<Value> {
    let read_lock = state.service.services.read().await;
    let data = if let Some((iface_status, _)) = read_lock.get(&iface_name) {
        iface_status.clone()
    } else {
        WatchServiceStatus::default()
    };
    let result = serde_json::to_value(data);
    Json(result.unwrap())
}

async fn handle_iface_service_status(
    State(state): State<LandscapeIfaceIpServices>,
    Path(iface_name): Path<String>,
    Json(service_config): Json<IfaceIpServiceConfig>,
) -> Json<Value> {
    let result = SimpleResult { success: true };
    let write_data = serde_json::to_string(&service_config);

    // TODO 调用 IfaceIpModelConfig 的 check_iface_status 检查当前的 iface 是否能切换这个状态
    if let Ok(()) = state.service.start_new_service(service_config).await {
        let mut write_lock = state.store.lock().await;
        write_lock.set(iface_name, write_data.unwrap());
        drop(write_lock);
    }
    let result = serde_json::to_value(result);
    Json(result.unwrap())
}

async fn delete_and_stop_iface_service(
    State(state): State<LandscapeIfaceIpServices>,
    Path(iface_name): Path<String>,
) -> Json<Value> {
    let mut write_lock = state.store.lock().await;
    write_lock.del(iface_name.clone());
    drop(write_lock);

    let mut write_lock = state.service.services.write().await;
    let data = if let Some((iface_status, _)) = write_lock.remove(&iface_name) {
        iface_status
    } else {
        WatchServiceStatus::default()
    };
    drop(write_lock);
    // 停止服务
    data.stop().await;
    let result = serde_json::to_value(data);
    Json(result.unwrap())
}
