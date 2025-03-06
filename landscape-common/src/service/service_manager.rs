use std::{collections::HashMap, sync::Arc};

use tokio::sync::{mpsc, RwLock};

use crate::store::storev2::LandScapeStore;

use super::service_code::{WatchService, WatchServiceTrait};

type WatchServiceConfigPair<T, S> = (WatchService<T>, mpsc::Sender<S>);

/// T: 定义被观察的状态
/// S：存储的配置
pub struct ServiceManager<T: WatchServiceTrait, S: LandScapeStore> {
    pub services: Arc<RwLock<HashMap<String, WatchServiceConfigPair<T, S>>>>,
}

impl<T: WatchServiceTrait, S: LandScapeStore> ServiceManager<T, S> {
    pub async fn init(init_config: Vec<S>) -> Self {
        //
        let services = HashMap::new();
        let services = Arc::new(RwLock::new(services));

        for config in init_config.into_iter() {
            // new_iface_service_thread(config, services.clone()).await;
        }

        Self { services }
    }
}
