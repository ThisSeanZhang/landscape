use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;

use bollard::models::CreateImageInfo;
use bollard::query_parameters::CreateImageOptions;
use bollard::Docker;
use tokio::sync::broadcast;
use tokio::sync::RwLock;

use landscape_common::docker::image::{ImgPullEvent, PullImgTask, PullImgTaskItem};
use tokio_stream::StreamExt;
use uuid::Uuid;

pub type ARwLock<T> = Arc<RwLock<T>>;

#[cfg(debug_assertions)]
const TASK_MAX_SIZE: usize = 4;

#[cfg(not(debug_assertions))]
const TASK_MAX_SIZE: usize = 64;

#[derive(Clone)]
pub struct PullManager {
    sock_tx: broadcast::Sender<ImgPullEvent>,
    tasks: ARwLock<VecDeque<ARwLock<PullImgTask>>>,
}

impl PullManager {
    pub fn new() -> Self {
        let (sock_tx, _) = broadcast::channel(2048);

        Self {
            sock_tx,
            tasks: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    pub async fn get_info(&self) -> Vec<PullImgTask> {
        let inners: Vec<_> = { self.tasks.read().await.iter().cloned().collect() };

        let mut result = Vec::with_capacity(inners.len());
        for item in inners.into_iter().rev() {
            let item_read = item.read().await;
            result.push(item_read.clone());
            drop(item_read);
        }

        result
    }

    pub fn get_event_sock(&self) -> broadcast::Receiver<ImgPullEvent> {
        self.sock_tx.subscribe()
    }

    async fn push_task(&self) -> bool {
        let task_read = self.tasks.read().await;
        if task_read.len() >= TASK_MAX_SIZE {
            let task = task_read.front().cloned();
            drop(task_read);
            if let Some(task) = task {
                let is_complete = {
                    let task = task.read().await;
                    task.complete
                };

                if is_complete {
                    let mut task_write = self.tasks.write().await;
                    task_write.pop_front();
                    return true;
                } else {
                    return false;
                }
            }
        }
        return true;
    }

    pub async fn pull_img(&self, image_name: String, docker_client: Option<Docker>) {
        let docker = match docker_client {
            Some(d) => d,
            None => {
                tracing::warn!("Docker client not available for image pull");
                return;
            }
        };
        if !self.push_task().await {
            return;
        }
        let (split_image_name, image_tag) = if let Some((name, tag)) = image_name.split_once(':') {
            (name.to_string(), tag.to_string())
        } else {
            (image_name.to_string(), "latest".to_string())
        };

        let options = CreateImageOptions {
            from_image: Some(split_image_name),
            tag: Some(image_tag),
            ..Default::default()
        };

        let task_id = Uuid::new_v4();
        let task_info = PullImgTask {
            id: task_id.clone(),
            img_name: image_name.clone(),
            layer_current_info: HashMap::new(),
            complete: false,
        };

        let task_info = Arc::new(RwLock::new(task_info));
        {
            let mut write = self.tasks.write().await;
            write.push_back(task_info.clone());
            drop(write);
        }
        let sock_tx = self.sock_tx.clone();
        tokio::spawn(async move {
            let mut stream = docker.create_image(Some(options), None, None);

            'download: while let Some(res) = stream.next().await {
                match res {
                    Ok(CreateImageInfo {
                        id: Some(layer_id),
                        status: Some(_),
                        progress_detail: Some(progress_detail),
                        ..
                    }) => {
                        let mut info_write = task_info.write().await;

                        let info = info_write
                            .layer_current_info
                            .entry(layer_id.clone())
                            .or_insert(Default::default());

                        *info = PullImgTaskItem {
                            id: layer_id.clone(),
                            current: progress_detail.current,
                            total: progress_detail.total,
                        };

                        drop(info_write);
                        let _ = sock_tx.send(ImgPullEvent {
                            task_id,
                            img_name: image_name.clone(),
                            id: layer_id.clone(),
                            current: progress_detail.current,
                            total: progress_detail.total,
                        });
                        // println!("[拉取中: {id:?}] {}: {}{:?}", status, progress, progress_detail);
                    }
                    Ok(CreateImageInfo { id: None, status: Some(status), .. }) => {
                        let mut info_write = task_info.write().await;
                        if info_write.complete {
                            break 'download;
                        }
                        for (_, item) in &info_write.layer_current_info {
                            if item.current != item.total {
                                continue;
                            }
                        }
                        info_write.complete = true;
                        println!("[status] {}", status)
                    }

                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("fail: {}", e);
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {

    use tokio::sync::broadcast;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test1() {
        // Create a broadcast channel with a capacity of 5 messages
        let (tx, _) = broadcast::channel::<String>(5);

        // Start 3 consumers
        for id in 0..3 {
            let mut rx = tx.subscribe();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(msg) => {
                            println!("Consumer {} received: {}", id, msg);
                            sleep(Duration::from_millis(300)).await; // Simulate slow consumption
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            println!("Consumer {} lagged behind by {} messages!", id, n);
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        // Simulate producer
        for i in 1..=20 {
            let msg = format!("Message {}", i);
            println!("Producer sends: {}", msg);
            tx.send(msg).unwrap();
            sleep(Duration::from_millis(100)).await;
        }
    }
}
