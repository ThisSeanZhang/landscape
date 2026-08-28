use std::os::fd::{FromRawFd, OwnedFd};

use landscape_common::event::ConnectMessage;
use landscape_common::metric::connect::ConnectMetric;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::map_setting::share_map::types::nat_conn_metric_event;
use crate::MAP_PATHS;


fn build_connect_ringbuf(
    connect_msg_tx: mpsc::Sender<ConnectMessage>,
) -> libbpf_rs::RingBuffer<'static> {
    // let firewall_conn_metric_events =
    //     libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.firewall_conn_metric_events).unwrap();

    let nat_metric_events =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.nat_metric_events).unwrap();

    // let firewall_metric_tx = connect_msg_tx.clone();
    // let firewall_metric_callback = move |data: &[u8]| -> i32 {
    //     // let time = landscape_core::time::get_boot_time_ns().unwrap_or_default();
    //     let firewall_conn_event_value = plain::from_bytes::<firewall_conn_metric_event>(data);
    //     if let Ok(data) = firewall_conn_event_value {
    //         let mut event = ConnectMetric::from(data);
    //         event.key.create_time = revise_time(event.key.create_time);
    //         event.report_time = revise_time(event.report_time);
    //         // println!("FirewallMetric, {:#?}, time: {time}", event);
    //         let _ = firewall_metric_tx.try_send(ConnectMessage::Metric(event));
    //     }
    //     0
    // };

    let nat_metric_tx = connect_msg_tx.clone();
    let nat_metric_callback = move |data: &[u8]| -> i32 {
        // let time = landscape_core::time::get_boot_time_ns().unwrap_or_default();
        let conn_event_value = plain::from_bytes::<nat_conn_metric_event>(data);
        if let Ok(data) = conn_event_value {
            let mut event = ConnectMetric::from(data);
            event.key.create_time = data.create_time;
            event.create_time_ms = data.create_time / 1_000_000;
            event.report_time = data.time / 1_000_000;
            // println!("NAT Metric, {:#?}", event);
            let _ = nat_metric_tx.try_send(ConnectMessage::Metric(event));
        }
        0
    };

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        // .add(&firewall_conn_metric_events, firewall_metric_callback)
        // .expect("failed to add firewall_conn_metric_events ringbuf")
        .add(&nat_metric_events, nat_metric_callback)
        .expect("failed to add nat_metric_events ringbuf");
    builder.build().expect("failed to build")
}

pub async fn new_metric(cancel: CancellationToken, connect_msg_tx: mpsc::Sender<ConnectMessage>) {
    run_ringbuf_loop(build_connect_ringbuf(connect_msg_tx), cancel).await;
}

pub async fn run_ringbuf_loop(ringbuf: libbpf_rs::RingBuffer<'_>, cancel: CancellationToken) {
    // dup 一份 epoll fd 避免与 ringbuf 内部 fd 生命周期纠缠。
    let epoll_fd = unsafe { libc::dup(ringbuf.epoll_fd()) };
    if epoll_fd < 0 {
        tracing::error!("failed to dup ringbuf epoll fd: {}", std::io::Error::last_os_error());
        return;
    }
    let async_fd = match AsyncFd::new(unsafe { OwnedFd::from_raw_fd(epoll_fd) }) {
        Ok(fd) => fd,
        Err(error) => {
            tracing::error!("failed to create AsyncFd for ringbuf epoll fd: {}", error);
            return;
        }
    };

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            readable = async_fd.readable() => {
                match readable {
                    Ok(mut guard) => {
                        guard.clear_ready();
                        if let Err(error) = ringbuf.consume() {
                            tracing::error!("failed to consume ringbuf events: {}", error);
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}
