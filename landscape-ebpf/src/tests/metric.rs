use arc_swap::ArcSwapOption;
use std::mem::MaybeUninit;
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use landscape_common::event::ConnectMessage;
use landscape_common::metric::connect::{ConnectKey, ConnectMetric, ConnectStatusType};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput, RingBufferBuilder,
};
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use zerocopy::IntoBytes;

use crate::maps::share_map::types::{nat_conn_metric_event, u_inet_addr};
use crate::metric::{ConnectMetricEventSource, EventSourceStopOutcome, MetricSourceHandle};
use crate::tests::TestSkb;

pub(crate) mod test_metric_ringbuf {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_metric_ringbuf.skel.rs"));
}

use test_metric_ringbuf::{types, TestMetricRingbufSkel, TestMetricRingbufSkelBuilder};

fn run_emit(skel: &TestMetricRingbufSkel, mark: u32) {
    let pkt = vec![0u8; 64];
    let mut ctx = TestSkb { mark, ..Default::default() };
    let mut packet_out = vec![0u8; 64];
    let input = ProgramInput {
        data_in: Some(&pkt),
        context_in: Some(ctx.as_mut_bytes()),
        data_out: Some(&mut packet_out),
        ..Default::default()
    };
    let result =
        skel.progs.test_emit_metric.test_run(input).expect("test_emit_metric test_run failed");
    assert_eq!(result.return_value, 0, "test_emit_metric should return 0");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_poll_receives_ringbuf_events() {
        let builder = TestMetricRingbufSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).expect("open skeleton");
        let skel = open_skel.load().expect("load skeleton");

        let received: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let received_cb = received.clone();
        let mut rb_builder = RingBufferBuilder::new();
        rb_builder
            .add(&skel.maps.test_metric_events, move |data: &[u8]| {
                let event = unsafe {
                    std::ptr::read_unaligned(data.as_ptr().cast::<types::test_metric_event>())
                };
                received_cb.lock().unwrap().push(event.seq);
                0
            })
            .expect("add ringbuf map");
        let ringbuf = rb_builder.build().expect("build ringbuf");

        for mark in 1..=10 {
            run_emit(&skel, mark);
        }

        ringbuf.poll(Duration::from_millis(100)).expect("poll ringbuf");

        let got = received.lock().unwrap().clone();
        assert_eq!(
            got,
            (1..=10).collect::<Vec<u32>>(),
            "sync poll should receive all events in order"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn async_loop_receives_ringbuf_events() {
        let builder = TestMetricRingbufSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).expect("open skeleton");
        let skel = open_skel.load().expect("load skeleton");

        let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(64);
        let mut rb_builder = RingBufferBuilder::new();
        rb_builder
            .add(&skel.maps.test_metric_events, move |data: &[u8]| {
                let event = unsafe {
                    std::ptr::read_unaligned(data.as_ptr().cast::<types::test_metric_event>())
                };
                let _ = tx.try_send(event.seq);
                0
            })
            .expect("add ringbuf map");
        let ringbuf = rb_builder.build().expect("build ringbuf");

        let cancel = CancellationToken::new();
        let async_fd = crate::metric::dup_epoll_async_fd(ringbuf.epoll_fd()).expect("dup epoll fd");
        let reader =
            tokio::spawn(crate::metric::run_ringbuf_loop(ringbuf, async_fd, cancel.clone()));

        for mark in 1001..=1010 {
            run_emit(&skel, mark);
        }

        let mut seqs = Vec::new();
        for _ in 1001..=1010 {
            let seq = timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("timed out waiting for async ringbuf event")
                .expect("event channel closed");
            seqs.push(seq);
        }
        assert_eq!(
            seqs,
            (1001..=1010).collect::<Vec<u32>>(),
            "async loop should receive all events in order"
        );

        cancel.cancel();
        timeout(Duration::from_secs(1), reader)
            .await
            .expect("reader should exit after cancel")
            .expect("reader task should not panic");
    }

    #[test]
    fn connect_metric_layout_matches_wire() {
        assert_eq!(size_of::<u_inet_addr>(), 16, "u_inet_addr must be 16 bytes");
        assert_eq!(
            size_of::<ConnectMetric>(),
            size_of::<nat_conn_metric_event>(),
            "ConnectMetric wire size must match nat_conn_metric_event"
        );

        assert_eq!(
            offset_of!(ConnectMetric, src_addr),
            offset_of!(nat_conn_metric_event, src_addr)
        );
        assert_eq!(
            offset_of!(ConnectMetric, dst_addr),
            offset_of!(nat_conn_metric_event, dst_addr)
        );
        assert_eq!(
            offset_of!(ConnectMetric, src_port),
            offset_of!(nat_conn_metric_event, src_port)
        );
        assert_eq!(
            offset_of!(ConnectMetric, dst_port),
            offset_of!(nat_conn_metric_event, dst_port)
        );
        assert_eq!(offset_of!(ConnectMetric, pad), offset_of!(nat_conn_metric_event, __pad_36));
        assert_eq!(
            offset_of!(ConnectMetric, create_time),
            offset_of!(nat_conn_metric_event, create_time)
        );
        assert_eq!(offset_of!(ConnectMetric, report_time), offset_of!(nat_conn_metric_event, time));
        assert_eq!(
            offset_of!(ConnectMetric, ingress_bytes),
            offset_of!(nat_conn_metric_event, ingress_bytes)
        );
        assert_eq!(
            offset_of!(ConnectMetric, ingress_packets),
            offset_of!(nat_conn_metric_event, ingress_packets)
        );
        assert_eq!(
            offset_of!(ConnectMetric, egress_bytes),
            offset_of!(nat_conn_metric_event, egress_bytes)
        );
        assert_eq!(
            offset_of!(ConnectMetric, egress_packets),
            offset_of!(nat_conn_metric_event, egress_packets)
        );
        assert_eq!(
            offset_of!(ConnectMetric, l4_proto),
            offset_of!(nat_conn_metric_event, l4_proto)
        );
        assert_eq!(
            offset_of!(ConnectMetric, l3_proto),
            offset_of!(nat_conn_metric_event, l3_proto)
        );
        assert_eq!(offset_of!(ConnectMetric, flow_id), offset_of!(nat_conn_metric_event, flow_id));
        assert_eq!(
            offset_of!(ConnectMetric, trace_id),
            offset_of!(nat_conn_metric_event, trace_id)
        );
        assert_eq!(offset_of!(ConnectMetric, cpu_id), offset_of!(nat_conn_metric_event, cpu_id));
        assert_eq!(offset_of!(ConnectMetric, ifindex), offset_of!(nat_conn_metric_event, ifindex));
        assert_eq!(offset_of!(ConnectMetric, status), offset_of!(nat_conn_metric_event, status));
        assert_eq!(offset_of!(ConnectMetric, gress), offset_of!(nat_conn_metric_event, gress));

        assert_eq!(size_of::<ConnectMetric>(), 104, "wire size must stay 104 (with tail padding)");
    }

    #[test]
    fn connect_metric_roundtrip_v4() {
        let mut bytes = [0u8; 104];
        bytes[0..4].copy_from_slice(&[192, 0, 2, 1]); // src_addr 192.0.2.1
        bytes[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst_addr 10.0.0.1
        bytes[32..34].copy_from_slice(&[0x12, 0x34]); // src_port BE
        bytes[34..36].copy_from_slice(&[0xab, 0xcd]); // dst_port BE
        bytes[40..48].copy_from_slice(&9876543210u64.to_le_bytes()); // create_time ns
        bytes[48..56].copy_from_slice(&1234567890u64.to_le_bytes()); // time ns
        bytes[56..64].copy_from_slice(&111u64.to_le_bytes());
        bytes[64..72].copy_from_slice(&22u64.to_le_bytes());
        bytes[72..80].copy_from_slice(&333u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&44u64.to_le_bytes());
        bytes[88] = 6; // l4_proto tcp
        bytes[89] = 0; // l3_proto v4
        bytes[90] = 7; // flow_id
        bytes[91] = 8; // trace_id
        bytes[92..96].copy_from_slice(&5u32.to_le_bytes()); // cpu_id
        bytes[96..100].copy_from_slice(&9u32.to_le_bytes()); // ifindex
        bytes[100] = 1; // status active
        bytes[101] = 2; // gress

        let m = ConnectMetric::try_from(&bytes[..]).expect("read wire bytes");

        assert_eq!(m.src_ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(m.dst_ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(m.src_port, 0x1234);
        assert_eq!(m.dst_port, 0xabcd);
        assert_eq!(m.create_time, 9876543210);
        assert_eq!(m.report_time, 1234, "time ns must be fixed up to ms");
        assert_eq!(m.create_time_ms(), 9876);
        assert_eq!(m.key(), ConnectKey { create_time: 9876543210, cpu_id: 5 });
        assert_eq!(m.ingress_bytes, 111);
        assert_eq!(m.ingress_packets, 22);
        assert_eq!(m.egress_bytes, 333);
        assert_eq!(m.egress_packets, 44);
        assert_eq!(m.l4_proto, 6);
        assert_eq!(m.l3_proto, 0);
        assert_eq!(m.flow_id, 7);
        assert_eq!(m.trace_id, 8);
        assert_eq!(m.cpu_id, 5);
        assert_eq!(m.ifindex, 9);
        assert_eq!(m.status_type(), ConnectStatusType::Active);
        assert_eq!(m.gress, 2);
    }

    #[test]
    fn connect_metric_roundtrip_v6_and_unknown_status() {
        let mut bytes = [0u8; 104];
        bytes[0..16].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        bytes[16..32].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        bytes[32..34].copy_from_slice(&[0x00, 0x50]); // src_port 80 BE
        bytes[34..36].copy_from_slice(&[0x00, 0x35]); // dst_port 53 BE
        bytes[40..48].copy_from_slice(&1000u64.to_le_bytes()); // create_time ns
        bytes[48..56].copy_from_slice(&2_000_000_000u64.to_le_bytes()); // time ns -> 2000 ms
        bytes[88] = 17; // l4_proto udp
        bytes[89] = 1; // l3_proto v6
        bytes[90] = 7; // flow_id
        bytes[100] = 99; // unknown status

        let m = ConnectMetric::try_from(&bytes[..]).expect("read wire bytes");

        assert_eq!(m.src_ip(), IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert_eq!(m.dst_ip(), IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)));
        assert_eq!(m.src_port, 80);
        assert_eq!(m.dst_port, 53);
        assert_eq!(m.report_time, 2000);
        assert_eq!(m.status_type(), ConnectStatusType::Unknow);
    }

    #[test]
    fn connect_metric_rejects_wrong_size() {
        assert!(ConnectMetric::try_from(&[0u8; 103][..]).is_err());
        assert!(ConnectMetric::try_from(&[0u8; 105][..]).is_err());
    }

    #[tokio::test]
    async fn event_source_stop_cleans_up_running_task() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<ConnectMessage>(16);
        let cancel = CancellationToken::new();
        let cancel_waiter = cancel.clone();
        let handle = tokio::spawn(async move {
            cancel_waiter.cancelled().await;
        });
        let source = ConnectMetricEventSource::test_new(
            cancel,
            handle,
            Arc::new(ArcSwapOption::new(Some(Arc::new(tx)))),
        );

        let outcome = Box::new(source).stop_with_budget(Duration::from_secs(1)).await;
        assert_eq!(outcome, EventSourceStopOutcome::Clean);
    }

    #[tokio::test]
    async fn event_source_stop_aborts_stuck_task() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<ConnectMessage>(16);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(std::future::pending::<()>());
        let source = ConnectMetricEventSource::test_new(
            cancel,
            handle,
            Arc::new(ArcSwapOption::new(Some(Arc::new(tx)))),
        );

        let outcome = Box::new(source).stop_with_budget(Duration::from_millis(100)).await;
        assert_eq!(outcome, EventSourceStopOutcome::Aborted);
    }

    #[tokio::test]
    async fn event_source_stop_marks_panicked_task() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<ConnectMessage>(16);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(async {
            panic!("intentional test panic");
        });
        let source = ConnectMetricEventSource::test_new(
            cancel,
            handle,
            Arc::new(ArcSwapOption::new(Some(Arc::new(tx)))),
        );

        let outcome = Box::new(source).stop_with_budget(Duration::from_secs(1)).await;
        assert_eq!(outcome, EventSourceStopOutcome::Panicked);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn event_source_attach_channel_redirects_following_events() {
        let builder = TestMetricRingbufSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).expect("open skeleton");
        let skel = open_skel.load().expect("load skeleton");

        let (tx1, mut rx1) = tokio::sync::mpsc::channel::<ConnectMessage>(16);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel::<ConnectMessage>(16);
        let tx_slot = Arc::new(ArcSwapOption::new(Some(Arc::new(tx1))));

        let mut rb_builder = RingBufferBuilder::new();
        rb_builder
            .add(&skel.maps.test_metric_events, {
                let tx_slot = tx_slot.clone();
                move |data: &[u8]| {
                    let event = unsafe {
                        std::ptr::read_unaligned(data.as_ptr().cast::<types::test_metric_event>())
                    };
                    let tx = tx_slot.load();
                    let Some(tx) = tx.as_ref() else {
                        return 0;
                    };
                    let metric = ConnectMetric::from_domain(
                        event.seq as u64,
                        0,
                        0,
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        ConnectStatusType::Active,
                    );
                    let _ = tx.try_send(ConnectMessage::Metric(metric));
                    0
                }
            })
            .expect("add ringbuf map");
        let ringbuf = rb_builder.build().expect("build ringbuf");

        let cancel = CancellationToken::new();
        let async_fd = crate::metric::dup_epoll_async_fd(ringbuf.epoll_fd()).expect("dup epoll fd");
        let handle =
            tokio::spawn(crate::metric::run_ringbuf_loop(ringbuf, async_fd, cancel.clone()));
        let source = ConnectMetricEventSource::test_new(cancel, handle, tx_slot.clone());

        run_emit(&skel, 7);
        let first = timeout(Duration::from_secs(2), rx1.recv())
            .await
            .expect("timed out waiting for first event")
            .expect("first channel closed");
        let ConnectMessage::Metric(metric) = first;
        assert_eq!(metric.create_time_ms(), 7);

        source.attach_channel(tx2);
        run_emit(&skel, 8);
        let second = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("timed out waiting for redirected event")
            .expect("second channel closed");
        let ConnectMessage::Metric(metric) = second;
        assert_eq!(metric.create_time_ms(), 8);

        match timeout(Duration::from_millis(200), rx1.recv()).await {
            Ok(None) => {}
            Ok(Some(ConnectMessage::Metric(m))) => {
                panic!("old channel received seq={} after attach", m.create_time_ms())
            }
            Err(_) => panic!("old channel stayed open after attach"),
        }

        let outcome = Box::new(source).stop_with_budget(Duration::from_secs(1)).await;
        assert_eq!(outcome, EventSourceStopOutcome::Clean);
    }

    #[tokio::test]
    async fn event_source_request_stop_exits_task() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<ConnectMessage>(16);
        let cancel = CancellationToken::new();
        let cancel_waiter = cancel.clone();
        let handle = tokio::spawn(async move {
            cancel_waiter.cancelled().await;
        });
        let source = ConnectMetricEventSource::test_new(
            cancel,
            handle,
            Arc::new(ArcSwapOption::new(Some(Arc::new(tx)))),
        );

        source.request_stop();

        let outcome = Box::new(source).stop_with_budget(Duration::from_secs(1)).await;
        assert_eq!(outcome, EventSourceStopOutcome::Clean);
    }

    #[test]
    fn dup_epoll_async_fd_rejects_bad_fd() {
        assert!(crate::metric::dup_epoll_async_fd(-1).is_err());
    }
}
