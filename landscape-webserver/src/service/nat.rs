use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape::service::nat_service::NatService;
use landscape_common::{
    config::nat::NatServiceConfig,
    observer::IfaceObserverAction,
    service::{service_manager::ServiceManager, DefaultWatchServiceStatus},
    store::storev2::StoreFileManager,
};
use serde_json::Value;
use tokio::sync::{broadcast, Mutex};

use crate::{error::LandscapeApiError, SimpleResult};

#[derive(Clone)]
struct LandscapeIfaceNatServices {
    service: ServiceManager<NatService>,
    store: Arc<Mutex<StoreFileManager<NatServiceConfig>>>,
}

pub async fn get_iface_nat_paths(
    mut store: StoreFileManager<NatServiceConfig>,
    mut dev_observer: broadcast::Receiver<IfaceObserverAction>,
) -> Router {
    let share_state = LandscapeIfaceNatServices {
        service: ServiceManager::init(store.list()).await,
        store: Arc::new(Mutex::new(store)),
    };

    let share_state_copy = share_state.clone();
    tokio::spawn(async move {
        while let Ok(msg) = dev_observer.recv().await {
            match msg {
                IfaceObserverAction::Up(iface_name) => {
                    tracing::info!("restart {iface_name} NAT service");
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
        .route("/nats/status", get(get_all_nat_status))
        .route("/nats", post(handle_iface_nat_status))
        .route("/nats/:iface_name", get(get_iface_nat_conifg).delete(delete_and_stop_iface_nat))
        // .route("/nats/:iface_name/restart", post(restart_nat_service_status))
        .with_state(share_state)
}

async fn get_all_nat_status(State(state): State<LandscapeIfaceNatServices>) -> Json<Value> {
    let read_lock = state.service.services.read().await;
    let mut result = HashMap::new();
    for (key, (iface_status, _)) in read_lock.iter() {
        result.insert(key.clone(), iface_status.clone());
    }
    drop(read_lock);
    let result = serde_json::to_value(result);
    Json(result.unwrap())
}

async fn get_iface_nat_conifg(
    State(state): State<LandscapeIfaceNatServices>,
    Path(iface_name): Path<String>,
) -> Result<Json<NatServiceConfig>, LandscapeApiError> {
    let mut read_lock = state.store.lock().await;
    if let Some(iface_config) = read_lock.get(&iface_name) {
        Ok(Json(iface_config))
    } else {
        Err(LandscapeApiError::NotFound("can not find".into()))
    }
}

async fn handle_iface_nat_status(
    State(state): State<LandscapeIfaceNatServices>,
    Json(service_config): Json<NatServiceConfig>,
) -> Json<Value> {
    let result = SimpleResult { success: true };

    // TODO 调用 IfaceIpModelConfig 的 check_iface_status 检查当前的 iface 是否能切换这个状态
    if let Ok(()) = state.service.update_service(service_config.clone()).await {
        let mut write_lock = state.store.lock().await;
        write_lock.set(service_config);
        drop(write_lock);
    }
    let result = serde_json::to_value(result);
    Json(result.unwrap())
}

async fn delete_and_stop_iface_nat(
    State(state): State<LandscapeIfaceNatServices>,
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

// async fn restart_nat_service_status(
//     State(state): State<LandscapeIfaceNatServices>,
//     Path(iface_name): Path<String>,
// ) -> Result<Json<Value>, LandscapeApiError> {
//     let mut result = SimpleResult { success: false };

//     let mut read_lock = state.store.lock().await;
//     if let Some(service_config) = read_lock.get(&iface_name) {
//         if let Ok(()) = state.service.start_new_service(service_config).await {
//             result.success = true;
//         }
//     } else {
//         return Err(LandscapeApiError::NotFound("can not find".into()));
//     }

//     let result = serde_json::to_value(result);
//     Ok(Json(result.unwrap()))
// }
