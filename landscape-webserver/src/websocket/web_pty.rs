use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, WebSocketUpgrade,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::SinkExt;
use landscape::sys_service::web_pty::LandscapePtySession;
use landscape_common::pty::{LandscapePtyConfig, LandscapePtySize, PtyInMessage, PtyOutMessage};
use tokio::sync::{broadcast, mpsc};

use crate::LandscapeApp;

pub async fn get_web_pty_socks_paths() -> Router<LandscapeApp> {
    Router::new().route("/sessions", get(create_pty))
}

async fn create_pty(
    Query(param): Query<serde_json::Value>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    fn parse_u16(v: &serde_json::Value) -> u16 {
        v.as_str().and_then(|s| s.parse::<u16>().ok()).unwrap_or(0)
    }

    let rows = parse_u16(&param["rows"]);
    let cols = parse_u16(&param["cols"]);
    let pixel_width = parse_u16(&param["pixel_width"]);
    let pixel_height = parse_u16(&param["pixel_height"]);
    let shell = param["shell"].as_str().unwrap_or("bash").to_string();

    let config = LandscapePtyConfig {
        shell,
        size: LandscapePtySize { rows, cols, pixel_width, pixel_height },
    };

    println!("query: {config:?}");

    let session = LandscapePtySession::new(config).await.unwrap();
    ws.on_upgrade(move |socket| handle_socket(socket, session))
}

async fn handle_socket(mut socket: WebSocket, session: LandscapePtySession) {
    if socket.send(Message::Ping(vec![1, 2, 3].into())).await.is_err() {
        tracing::info!("Could not send ping!");
        return;
    }

    tokio::spawn(async move {
        let mut out = session.out_events.subscribe();
        let input = session.input_events.clone();

        loop {
            tokio::select! {
                msg = socket.recv() => {
                    if let Some(msg) = msg {
                        if let Ok(msg) = msg {
                            if handle_websocket_msg(msg, &input).await {
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                    continue;
                }
                data = out.recv() => {
                    if handle_pty_msg(data, &mut socket).await {
                        break;
                    }
                }
            };
        }
        tracing::info!("Websocket pty destroyed");
        let _ = socket.close();
        drop(session);
    });
}

async fn handle_websocket_msg(msg: Message, input: &mpsc::Sender<PtyInMessage>) -> bool {
    match msg {
        Message::Text(text) => {
            // 解析为 PtyInMessage
            if let Ok(input_msg) = serde_json::from_str::<PtyInMessage>(&text) {
                // tracing::debug!("pty from frontend: {input_msg:?}");
                // 发送到 PTY
                let _ = input.send(input_msg).await;
            }
        }
        Message::Close(c) => {
            if let Some(cf) = c {
                tracing::debug!(">>>  sent close with code {} and reason `{}`", cf.code, cf.reason);
            } else {
                tracing::debug!(">>> somehow sent close message without CloseFrame");
            }
            return true;
        }
        Message::Binary(_) | Message::Pong(_) | Message::Ping(_) => {}
    }
    false
}

async fn handle_pty_msg(
    msg: Result<PtyOutMessage, broadcast::error::RecvError>,
    socket: &mut WebSocket,
) -> bool {
    match msg {
        Ok(pty_msg) => {
            // tracing::debug!("pty from backend: {pty_msg:?}");
            // 将 PtyOutMessage 序列化成 JSON 发送给前端
            if let Ok(data) = serde_json::to_string(&pty_msg) {
                if let Err(e) = socket.send(Message::Text(data.into())).await {
                    tracing::error!("send data to front error: {e:?}");
                    // 发送失败，说明连接可能已经关闭
                    return true;
                }
            }
        }
        Err(broadcast::error::RecvError::Lagged(_)) => {}
        Err(broadcast::error::RecvError::Closed) => {
            tracing::error!("pty out channle close");
            return true;
        }
    }
    false
}
