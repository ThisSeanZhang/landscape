use landscape_common::{
    concurrency::{short_thread_name, spawn_named_thread, thread_name},
    error::pty::PtyError,
    pty::{LandscapePtyConfig, PtyInMessage, PtyOutMessage, SessionChannel, SessionStatus},
};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::Arc,
};
use tokio::sync::{broadcast, mpsc, watch, RwLock};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone)]
pub struct LandscapePtyService {
    session: Arc<RwLock<HashMap<String, LandscapePtySession>>>,
}

impl Default for LandscapePtyService {
    fn default() -> Self {
        Self::new()
    }
}

impl LandscapePtyService {
    pub fn new() -> Self {
        Self { session: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub async fn new_session(
        &self,
        session_name: String,
        config: LandscapePtyConfig,
    ) -> Result<SessionChannel, PtyError> {
        let session = LandscapePtySession::new(config).await?;
        let result = SessionChannel {
            out_events: session.out_events.subscribe(),
            input_events: session.input_events.clone(),
        };
        let mut write = self.session.write().await;
        write.insert(session_name, session);
        Ok(result)
    }
}

pub struct LandscapePtySession {
    session_key: String,
    pub out_events: broadcast::Sender<PtyOutMessage>,
    pub input_events: mpsc::Sender<PtyInMessage>,
    pub status: watch::Sender<SessionStatus>,
    pub cancel: CancellationToken,
}

impl Drop for LandscapePtySession {
    fn drop(&mut self) {
        tracing::debug!(session = %self.session_key, "dropping PTY session");
        self.cancel.cancel();
    }
}

impl LandscapePtySession {
    // pub async fn new2(config: LandscapePtyConfig) -> Result<Self, PtyError> {
    //     let mut cmd = Command::new(config.shell);

    //     let (out_tx, _out_rx) = broadcast::channel(1024);

    //     let (input_tx, mut input_rx) = mpsc::channel::<Box<Vec<u8>>>(100);

    //     let (status_tx, _status_rx) = watch::channel(SessionStatus::On);

    //     let cancel = CancellationToken::new();

    //     let mut terminal = cmd.spawn_terminal().expect("Failed to spawn terminal");

    //     let (mut terminal_in, mut terminal_out) = terminal.split().unwrap();

    //     tokio::spawn(async move {
    //         while let Some(message) = input_rx.next().await {
    //             if let Err(e) = terminal_in.write_all(&message).await {
    //                 eprintln!("Error writing to terminal: {e}");
    //                 break;
    //             }
    //             if let Err(e) = terminal_in.flush().await {
    //                 eprintln!("Error flushing terminal: {e}");
    //                 break;
    //             }
    //         }
    //     });

    //     let out_tx_clone = out_tx.clone();
    //     tokio::spawn(async move {
    //         // Buffer for reading from terminal
    //         let mut buf = [0u8; 1024];

    //         loop {
    //             match terminal_out.read(&mut buf).await {
    //                 Ok(0) => break, // EOF
    //                 Ok(n) => {
    //                     if let Err(e) = out_tx_clone.send(Box::new(buf[..n].to_vec())).await {
    //                         eprintln!("Error sending to WebSocket: {e}");
    //                         break;
    //                     }
    //                 }
    //                 Err(e) => {
    //                     eprintln!("Error reading from terminal: {e}");
    //                     break;
    //                 }
    //             }
    //         }
    //     });

    //     Ok(Self {
    //         out_events: out_tx,
    //         input_events: input_tx,
    //         status: status_tx,
    //         cancel,
    //     })
    // }

    pub async fn new(config: LandscapePtyConfig) -> Result<Self, PtyError> {
        let session_key = Uuid::new_v4().simple().to_string();
        // 创建广播通道用于输出事件
        let (out_tx, _out_rx) = broadcast::channel::<PtyOutMessage>(1024);

        // 创建 mpsc 通道用于输入事件
        let (input_tx, mut input_rx) = mpsc::channel::<PtyInMessage>(100);

        // 创建 watch 通道用于状态更新
        let (status_tx, _status_rx) = watch::channel(SessionStatus::On);

        // 创建取消令牌
        let cancel = CancellationToken::new();

        // 创建 PTY 系统
        let pty_system = NativePtySystem::default();
        let pair = pty_system.openpty(PtySize {
            rows: config.size.rows,
            cols: config.size.cols,
            pixel_width: config.size.pixel_width,
            pixel_height: config.size.pixel_height,
        })?;

        // 设置命令
        let shell = config.shell.clone();
        let candidates = if shell == "bash" {
            vec![
                "bash",
                "/usr/bin/bash",
                "/bin/bash",
                "/usr/local/bin/bash",
                "sh",
                "/usr/bin/sh",
                "/bin/sh",
            ]
        } else if shell == "sh" {
            vec!["sh", "/usr/bin/sh", "/bin/sh", "bash", "/usr/bin/bash", "/bin/bash"]
        } else {
            vec![shell.as_str()]
        };

        let mut spawn_err = None;
        let mut child_and_writer = None;

        for &candidate in &candidates {
            let mut cmd = CommandBuilder::new(candidate);
            cmd.env("TERM", "xterm-256color");
            cmd.env("LANG", "en_US.UTF-8");
            cmd.env("LC_ALL", "en_US.UTF-8");

            if let Ok(path) = std::env::var("PATH") {
                cmd.env("PATH", path);
            }

            match pair.slave.spawn_command(cmd) {
                Ok(child) => {
                    // 获取读写器
                    match pair.master.try_clone_reader() {
                        Ok(reader) => match pair.master.take_writer() {
                            Ok(writer) => {
                                child_and_writer = Some((child, reader, writer));
                                break;
                            }
                            Err(e) => spawn_err = Some(PtyError::AnyErr(e)),
                        },
                        Err(e) => spawn_err = Some(PtyError::AnyErr(e)),
                    }
                }
                Err(e) => {
                    spawn_err = Some(PtyError::SpawnCommand(format!(
                        "Unable to spawn {} because: {}",
                        candidate, e
                    )));
                }
            }
        }

        let (mut child, mut reader, mut writer) = match child_and_writer {
            Some(res) => res,
            None => {
                return Err(spawn_err.unwrap_or_else(|| {
                    PtyError::SpawnCommand("No viable shell found".to_string())
                }))
            }
        };

        drop(pair.slave);

        // 克隆必要的通道和令牌用于任务
        let out_tx_clone = out_tx.clone();
        let status_tx_clone = status_tx.clone();
        let cancel_clone = cancel.clone();
        let read_input_tx = input_tx.clone();
        let read_session_key = session_key.clone();

        // 启动读取任务
        spawn_named_thread(
            short_thread_name(thread_name::prefix::PTY_READ, &session_key),
            move || {
                let mut buffer = [0u8; 1024];
                loop {
                    // 检查是否被取消
                    if cancel_clone.is_cancelled() {
                        break;
                    }

                    match reader.read(&mut buffer) {
                        Ok(0) => {
                            // EOF - 进程结束
                            let _ = status_tx_clone.send(SessionStatus::Exited(0));
                            break;
                        }
                        Ok(n) => {
                            let data = buffer[..n].to_vec();
                            let boxed_data = Box::new(data);

                            // 发送输出数据，如果接收者都断开了就退出
                            if out_tx_clone.send(PtyOutMessage::Data { data: boxed_data }).is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            let _ = status_tx_clone.send(SessionStatus::Error(e.to_string()));
                            break;
                        }
                    }
                }

                cancel_clone.cancel();
                let _ = read_input_tx.try_send(PtyInMessage::Exit);
                let _ = out_tx_clone.send(PtyOutMessage::Exit { msg: "exit".to_string() });
                tracing::info!(session = %read_session_key, "[web pty]: exit out loop pty");
            },
        )
        .map_err(PtyError::OpenPty)?;

        // 克隆状态发送器用于写入任务
        let status_tx_write = status_tx.clone();
        let cancel_write = cancel.clone();
        let write_session_key = session_key.clone();

        spawn_named_thread(
            short_thread_name(thread_name::prefix::PTY_WRITE, &session_key),
            move || {
                while let Some(data) = input_rx.blocking_recv() {
                    if cancel_write.is_cancelled() {
                        break;
                    }

                    match data {
                        PtyInMessage::Size { size } => {
                            if let Err(e) = pair.master.resize(PtySize {
                                rows: size.rows,
                                cols: size.cols,
                                pixel_width: size.pixel_width,
                                pixel_height: size.pixel_height,
                            }) {
                                let _ = status_tx_write.send(SessionStatus::Error(e.to_string()));
                                break;
                            }
                        }
                        PtyInMessage::Data { data } => {
                            if let Err(e) = writer.write_all(&data) {
                                let _ = status_tx_write.send(SessionStatus::Error(e.to_string()));
                                break;
                            }

                            if let Err(e) = writer.flush() {
                                let _ = status_tx_write.send(SessionStatus::Error(e.to_string()));
                                break;
                            }
                        }
                        PtyInMessage::Exit => {
                            cancel_write.cancel();
                            break;
                        }
                    }
                }

                tracing::info!(session = %write_session_key, "[web pty]: exit in loop pty");
            },
        )
        .map_err(PtyError::OpenPty)?;

        // 启动进程监控任务
        let status_tx_monitor = status_tx.clone();
        let cancel_monitor = cancel.clone();
        let monitor_input_tx = input_tx.clone();
        let monitor_session_key = session_key.clone();

        spawn_named_thread(
            short_thread_name(thread_name::prefix::PTY_WAIT, &session_key),
            move || {
                let exit_status = child.wait();
                if !cancel_monitor.is_cancelled() {
                    match exit_status {
                        Ok(status) => {
                            let _ =
                                status_tx_monitor.send(SessionStatus::Exited(status.exit_code()));
                        }
                        Err(e) => {
                            let _ = status_tx_monitor.send(SessionStatus::Error(e.to_string()));
                        }
                    }
                }

                cancel_monitor.cancel();
                let _ = monitor_input_tx.try_send(PtyInMessage::Exit);
                tracing::info!(session = %monitor_session_key, "[web pty]: child wait thread exit");
            },
        )
        .map_err(PtyError::OpenPty)?;

        Ok(LandscapePtySession {
            session_key,
            out_events: out_tx,
            input_events: input_tx,
            status: status_tx,
            cancel,
        })
    }
}
