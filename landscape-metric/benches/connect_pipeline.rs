//! From the workspace root, choose an allowed logical CPU and a disk-backed TMPDIR:
//! TMPDIR="$PWD/target" taskset -c 2 cargo bench -p landscape-metric --features metric-persistent --bench connect_pipeline
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use landscape_common::metric::connect::{
    ConnectKey, ConnectMetric, ConnectStatusType, MetricResolution,
};
use landscape_common::sys_config::{ConnectMetricConfig, MetricStoreBackend, RuntimeConfigSource};
use landscape_common::utils::time::now_ms;
use landscape_metric::ConnectMetricEngine;

const CONNECTIONS: usize = 8_192;
const ROUNDS: usize = 5;
const MINUTE_MS: u64 = 60_000;

fn events(reports: usize) -> Vec<ConnectMetric> {
    // Keep both workloads inside the live window and away from a ten-minute refresh.
    let mut start = (now_ms() / MINUTE_MS - 2) * MINUTE_MS;
    if (start + MINUTE_MS).is_multiple_of(10 * MINUTE_MS) {
        start -= MINUTE_MS;
    }
    let mut events = Vec::with_capacity(CONNECTIONS * reports);
    for tick in 0..reports {
        for id in 0..CONNECTIONS {
            let created = start + (id / 8) as u64;
            let packets = (tick + 1) as u64;
            events.push(ConnectMetric::from_domain(
                created,
                (id % 8) as u32,
                created + tick as u64 * 5_000,
                Ipv4Addr::new(192, 0, 2, (id % 250 + 1) as u8).into(),
                Ipv4Addr::new(198, 51, 100, (id % 200 + 1) as u8).into(),
                10_000 + id as u16,
                443,
                (id % 8) as u8,
                0,
                (id % 4 + 1) as u32,
                1024 * packets,
                packets,
                512 * packets,
                packets,
                if tick + 1 == reports {
                    ConnectStatusType::Disabled
                } else {
                    ConnectStatusType::Active
                },
            ));
        }
    }
    events
}

async fn sample(backend: MetricStoreBackend, reports: usize) -> (Duration, Duration) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = ConnectMetricConfig::default().build_runtime();
    config.store.backend = backend;
    let engine = ConnectMetricEngine::new(dir.path().into(), config.clone()).await.unwrap();
    let tx = engine.get_connect_msg_channel().unwrap();
    let input = events(reports);
    let keys: Vec<ConnectKey> = input[..CONNECTIONS].iter().map(ConnectMetric::key).collect();
    let last = input.last().unwrap();
    let last_key = last.key();
    let last_time = last.report_time;
    let minute_buckets = last_time / MINUTE_MS - last.create_time_ms() / MINUTE_MS + 1;

    let start = Instant::now();
    for event in input {
        tx.send(event).await.unwrap();
    }
    drop(tx);
    // FIFO input: seeing the final report means the live worker processed every earlier event.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let points = engine
                .query_metric_by_key(last_key.clone(), MetricResolution::Second)
                .await
                .unwrap();
            if points.last().is_some_and(|point| point.report_time == last_time) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("live worker did not drain");
    let live = start.elapsed();
    engine.shutdown().await;
    let drained = start.elapsed();

    assert_eq!(engine.writer_stats(), (0, 0), "history batches dropped or failed");
    match backend {
        MetricStoreBackend::Memory => {
            for key in keys {
                let points =
                    engine.query_metric_by_key(key, MetricResolution::Second).await.unwrap();
                assert_eq!(points.len(), reports);
                assert_eq!(points.last().unwrap().status, ConnectStatusType::Disabled);
            }
        }
        MetricStoreBackend::Sqlite => {
            let reader = ConnectMetricEngine::new(dir.path().into(), config).await.unwrap();
            let stats = reader.get_global_stats(true).await.unwrap();
            let packets = (CONNECTIONS * reports) as u64;
            assert_eq!(stats.total_connect_count, CONNECTIONS as u64);
            assert_eq!(stats.total_ingress_bytes, packets * 1024);
            assert_eq!(stats.total_egress_bytes, packets * 512);
            for resolution in
                [MetricResolution::Minute, MetricResolution::Hour, MetricResolution::Day]
            {
                let points =
                    reader.query_metric_by_key(last_key.clone(), resolution).await.unwrap();
                let expected_buckets =
                    if resolution == MetricResolution::Minute { minute_buckets } else { 1 };
                assert_eq!(points.len() as u64, expected_buckets);
                let final_point = points.last().unwrap();
                assert_eq!(final_point.status, ConnectStatusType::Disabled);
                assert_eq!(final_point.ingress_bytes, reports as u64 * 1024);
            }
            reader.shutdown().await;
        }
    }
    (live, drained)
}

fn print_rates(label: &str, events: usize, samples: &mut [Duration]) {
    samples.sort_unstable();
    let rate = |t: Duration| events as f64 / t.as_secs_f64();
    let median = samples[samples.len() / 2];
    println!(
        "  {label}: {:.0} reports/s ({median:?}), range {:.0}..{:.0} reports/s",
        rate(median),
        rate(*samples.last().unwrap()),
        rate(samples[0])
    );
}

async fn run() {
    for reports in [2, 24] {
        for backend in [MetricStoreBackend::Memory, MetricStoreBackend::Sqlite] {
            println!("{backend:?}, {CONNECTIONS} connections x {reports} reports:");
            sample(backend, reports).await;
            let mut live = Vec::new();
            let mut drained = Vec::new();
            for _ in 0..ROUNDS {
                let (live_elapsed, drained_elapsed) = sample(backend, reports).await;
                live.push(live_elapsed);
                drained.push(drained_elapsed);
            }
            print_rates("live", CONNECTIONS * reports, &mut live);
            if backend == MetricStoreBackend::Sqlite {
                print_rates("persisted", CONNECTIONS * reports, &mut drained);
            }
        }
    }
}

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}
