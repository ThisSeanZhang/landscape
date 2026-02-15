use std::time::Duration;

use landscape_common::event::ConnectMessage;
use landscape_common::metric::connect::ConnectMetric;
use tokio::sync::mpsc;
use tokio::sync::oneshot::{self, error::TryRecvError};

use crate::map_setting::share_map::types::nat_conn_metric_event;
use crate::MAP_PATHS;

pub fn new_metric(
    mut service_status: oneshot::Receiver<()>,
    connect_msg_tx: mpsc::Sender<ConnectMessage>,
) {
    // let firewall_conn_metric_events =
    //     libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.firewall_conn_metric_events).unwrap();

    let nat_conn_metric_events =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.nat_conn_metric_events).unwrap();

    let offset_time = landscape_common::utils::time::get_relative_time_ns().unwrap_or_default();

    let revise_time = |time: u64| -> u64 { (time + offset_time) / 1_000_000 };
    let key_time = |time: u64| -> u64 { time + offset_time };

    // let firewall_metric_tx = connect_msg_tx.clone();
    // let firewall_metric_callback = move |data: &[u8]| -> i32 {
    //     // let time = landscape_common::utils::time::get_boot_time_ns().unwrap_or_default();
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
        // let time = landscape_common::utils::time::get_boot_time_ns().unwrap_or_default();
        let conn_event_value = plain::from_bytes::<nat_conn_metric_event>(data);
        if let Ok(data) = conn_event_value {
            let mut event = ConnectMetric::from(data);
            let raw_create_time = data.create_time;
            event.key.create_time = key_time(raw_create_time);
            event.create_time_ms = revise_time(raw_create_time);
            event.report_time = revise_time(data.time);
            // println!("NAT Metric, {:#?}", event);
            let _ = nat_metric_tx.try_send(ConnectMessage::Metric(event));
        }
        0
    };

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        // .add(&firewall_conn_metric_events, firewall_metric_callback)
        // .expect("failed to add firewall_conn_metric_events ringbuf")
        .add(&nat_conn_metric_events, nat_metric_callback)
        .expect("failed to add nat_conn_metric_events ringbuf");
    let mgr = builder.build().expect("failed to build");

    'wait_stop: loop {
        let _ = mgr.poll(Duration::from_millis(1000));
        match service_status.try_recv() {
            Ok(_) => break 'wait_stop,
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Closed) => break 'wait_stop,
        }
    }
}
