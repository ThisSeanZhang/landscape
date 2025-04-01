use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path,
    },
    response::IntoResponse,
};
use axum::{routing::get, Router};
use landscape::dump::eth::EthFram;
use std::borrow::Cow;
use std::ops::ControlFlow;
use tokio::sync::mpsc::Sender;

use axum::extract::ws::CloseFrame;

pub fn get_tump_router() -> Router {
    Router::new().route("/dump/:iface_name", get(ws_handler))
}

async fn ws_handler(ws: WebSocketUpgrade, Path(iface_name): Path<String>) -> impl IntoResponse {
    println!("`{iface_name}` connected.");
    ws.on_upgrade(move |socket| handle_socket(socket, iface_name))
}

/// Actual websocket statemachine (one will be spawned per connection)
async fn handle_socket(mut socket: WebSocket, who_in: String) {
    // send a ping (unsupported by some browsers) just to kick things off and get a response
    if socket.send(Message::Ping(vec![1, 2, 3])).await.is_ok() {
        println!("Pinged {who_in}...");
    } else {
        println!("Could not send ping {who_in}!");
        // no Error here since the only thing we can do is to close the connection.
        // If we can not send messages, there is no way to salvage the statemachine anyway.
        return;
    }

    let (mut dump_tx, mut dump_rx) = landscape::dump::create_dump(who_in.clone()).await;
    println!("create dump thread");
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = socket.recv() => {
                    if let Some(msg) = msg {
                        if let Ok(msg) = msg {
                            if handle_websocket_msg(msg, &mut dump_tx).await.is_break() {
                                break;
                            }
                        }
                    }
                },
                packet = dump_rx.recv() => {
                    if let Some(packet) = packet {
                        handle_dump_msg(packet, &mut socket).await;
                    } else {

                        //TDOO close
                        if let Err(e) = socket
                            .send(Message::Close(Some(CloseFrame {
                                code: axum::extract::ws::close_code::NORMAL,
                                reason: Cow::from("Goodbye"),
                            })))
                            .await
                        {
                            println!("Could not send Close due to {e}, probably it is ok?");
                        }
                        break;
                    }
                }
            }
        }
        println!("Websocket context {who_in} destroyed");
    });
}

async fn handle_dump_msg(packet: Box<EthFram>, socket: &mut WebSocket) {
    // let data = serde_json::json!(packet).to_string();
    let data = serde_json::to_string_pretty(&packet).unwrap();
    if let Err(e) = socket.send(Message::Text(data)).await {
        println!("send data error: {e:?}");
    }
    // if let Err(e) = socket.send(Message::Text(serde_json::json!(packet).to_string())).await {
    //     println!("send data error: {e:?}");
    // }
}

async fn handle_websocket_msg(msg: Message, _dump_tx: &mut Sender<Vec<u8>>) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t) => {
            println!(">>> sent str: {t:?}");
        }
        Message::Binary(d) => {
            println!(">>> sent {} bytes: {:?}", d.len(), d);
        }
        Message::Close(c) => {
            if let Some(cf) = c {
                println!(">>>  sent close with code {} and reason `{}`", cf.code, cf.reason);
            } else {
                println!(">>> somehow sent close message without CloseFrame");
            }
            return ControlFlow::Break(());
        }

        Message::Pong(v) => {
            println!(">>> sent pong with {v:?}");
        }
        // You should never need to manually handle Message::Ping, as axum's websocket library
        // will do so for you automagically by replying with Pong and copying the v according to
        // spec. But if you need the contents of the pings you can see them here.
        Message::Ping(v) => {
            println!(">>> sent ping with {v:?}");
        }
    }
    ControlFlow::Continue(())
}
