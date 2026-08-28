use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput, RingBufferBuilder,
};
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use zerocopy::IntoBytes;

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
        let reader = tokio::spawn(crate::metric::run_ringbuf_loop(ringbuf, cancel.clone()));

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
}
