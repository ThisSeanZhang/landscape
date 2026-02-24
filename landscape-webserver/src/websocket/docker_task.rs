use axum::{
    extract::{
        ws::{CloseFrame, Message, Utf8Bytes, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use landscape_common::docker::image::ImgPullEvent;
use tokio::sync::broadcast;

use crate::LandscapeApp;

pub async fn get_docker_images_socks_paths() -> Router<LandscapeApp> {
    Router::new().route("/tasks", get(listen_task_event))
}

async fn listen_task_event(
    State(state): State<LandscapeApp>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| {
        handle_socket(socket, state.docker_service.pull_manager.get_event_sock())
    })
}

async fn handle_socket(
    mut socket: WebSocket,
    mut img_task_sock: broadcast::Receiver<ImgPullEvent>,
) {
    if socket.send(Message::Ping(vec![1, 2, 3].into())).await.is_err() {
        tracing::info!("Could not send ping!");
        return;
    }

    tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                msg = socket.recv() => {
                    if let Some(msg) = msg {
                        if let Ok(msg) = msg {
                            if handle_websocket_msg(msg).await {
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                    continue;
                }
                data = img_task_sock.recv() => {
                    data
                }
            };
            match msg {
                Ok(msg) => {
                    let data = serde_json::to_string(&msg).unwrap();
                    if let Err(e) = socket.send(Message::Text(Utf8Bytes::from(&data))).await {
                        tracing::info!("send data error: {e:?}");
                    }
                    // tracing::info!("send data: {msg:?}");
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // ignore
                }
                Err(_) => {
                    if let Err(e) = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: axum::extract::ws::close_code::NORMAL,
                            reason: Utf8Bytes::from("Goodbye"),
                        })))
                        .await
                    {
                        tracing::info!("Could not send Close due to {e}, probably it is ok?");
                    }
                    break;
                }
            }
        }
        tracing::info!("Websocket context destroyed");
    });
}

async fn handle_websocket_msg(msg: Message) -> bool {
    match msg {
        Message::Text(_) => {
            // tracing::debug!(">>> sent str: {t:?}");
        }
        Message::Binary(_) => {
            // tracing::debug!(">>> sent {} bytes: {:?}", d.len(), d);
        }
        Message::Close(c) => {
            if let Some(cf) = c {
                tracing::debug!(">>>  sent close with code {} and reason `{}`", cf.code, cf.reason);
            } else {
                tracing::debug!(">>> somehow sent close message without CloseFrame");
            }
            return true;
        }
        Message::Pong(_) | Message::Ping(_) => {}
    }
    false
}
