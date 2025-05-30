use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde_json::Value;
use tokio::sync::{broadcast, Mutex};

use landscape::service::ipconfig::IPConfigService;
use landscape_common::{
    config::wanip::IfaceIpServiceConfig,
    observer::IfaceObserverAction,
    service::{service_manager::ServiceManager, DefaultWatchServiceStatus},
    store::storev2::StoreFileManager,
};

use crate::{error::LandscapeApiError, SimpleResult};

#[derive(Clone)]
struct LandscapeIfaceIpServices {
    service: ServiceManager<IPConfigService>,
    store: Arc<Mutex<StoreFileManager<IfaceIpServiceConfig>>>,
}

pub async fn get_iface_ipconfig_paths(
    mut store: StoreFileManager<IfaceIpServiceConfig>,
    mut dev_observer: broadcast::Receiver<IfaceObserverAction>,
) -> Router {
    let share_state = LandscapeIfaceIpServices {
        service: ServiceManager::init(store.list()).await,
        store: Arc::new(Mutex::new(store)),
    };

    let share_state_copy = share_state.clone();
    tokio::spawn(async move {
        while let Ok(msg) = dev_observer.recv().await {
            match msg {
                IfaceObserverAction::Up(iface_name) => {
                    tracing::info!("restart {iface_name} IP config service");
                    let mut read_lock = share_state_copy.store.lock().await;
                    let service_config = if let Some(service_config) = read_lock.get(&iface_name) {
                        service_config
                    } else {
                        continue;
                    };
                    drop(read_lock);
                    let _ = share_state_copy.service.update_service(service_config).await;
                }
                IfaceObserverAction::Down(_) => {}
            }
        }
    });

    Router::new()
        .route("/ipconfigs/status", get(get_all_ipconfig_status))
        .route("/ipconfigs", post(handle_iface_service_status))
        .route(
            "/ipconfigs/:iface_name",
            get(get_iface_service_conifg).delete(delete_and_stop_iface_service),
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
) -> Result<Json<IfaceIpServiceConfig>, LandscapeApiError> {
    let mut read_lock = state.store.lock().await;
    if let Some(iface_config) = read_lock.get(&iface_name) {
        Ok(Json(iface_config))
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
        DefaultWatchServiceStatus::new()
    };
    let result = serde_json::to_value(data);
    Json(result.unwrap())
}

async fn handle_iface_service_status(
    State(state): State<LandscapeIfaceIpServices>,
    Json(service_config): Json<IfaceIpServiceConfig>,
) -> Json<Value> {
    let result = SimpleResult { success: true };
    // let write_data = serde_json::to_string(&service_config);

    // TODO 调用 IfaceIpModelConfig 的 check_iface_status 检查当前的 iface 是否能切换这个状态
    if let Ok(()) = state.service.update_service(service_config.clone()).await {
        let mut write_lock = state.store.lock().await;
        write_lock.set(service_config);
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
    write_lock.del(&iface_name);
    drop(write_lock);

    let mut write_lock = state.service.services.write().await;
    let data = if let Some((iface_status, _)) = write_lock.remove(&iface_name) {
        iface_status
    } else {
        DefaultWatchServiceStatus::new()
    };
    drop(write_lock);
    // 停止服务
    data.wait_stop().await;
    let result = serde_json::to_value(data);
    Json(result.unwrap())
}
