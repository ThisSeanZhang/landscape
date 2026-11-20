//! taskset -c 2 cargo bench -p landscape-metric --bench connect_realtime
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use landscape_common::metric::connect::{
    ConnectKey, ConnectMetric, ConnectStatusType, MetricResolution,
};
use landscape_common::sys_config::{ConnectMetricConfig, MetricStoreBackend, RuntimeConfigSource};
use landscape_common::utils::time::now_ms;
use landscape_metric::ConnectMetricEngine;
use tokio::sync::oneshot;

async fn engine() -> Arc<ConnectMetricEngine> {
    let mut config = ConnectMetricConfig::default().build_runtime();
    config.store.backend = MetricStoreBackend::Memory;
    Arc::new(ConnectMetricEngine::new(Default::default(), config).await.unwrap())
}

fn events(
    count: usize,
    start: u64,
    ticks: std::ops::Range<usize>,
    interval_ms: u64,
) -> Vec<ConnectMetric> {
    let mut events = Vec::with_capacity(count * ticks.len());
    for tick in ticks {
        for id in 0..count {
            let src = id % 256;
            let dst = id % 1024;
            let created = start - interval_ms + (id % 1000) as u64;
            let packets = (tick + 1) as u64 * 10;
            let mut metric = ConnectMetric::from_domain(
                created,
                (id % 8) as u32,
                created + (tick + 1) as u64 * interval_ms,
                Ipv4Addr::new(10, 0, 0, src as u8).into(),
                Ipv4Addr::new(10, 1, (dst / 256) as u8, dst as u8).into(),
                10000 + id as u16,
                443,
                (id % 8) as u8,
                0,
                (id % 4 + 1) as u32,
                packets * 100,
                packets,
                packets * 50,
                packets,
                ConnectStatusType::Active,
            );
            metric.create_time += id as u64; // distinguish connections created in the same millisecond
            events.push(metric);
        }
    }
    events
}

async fn ingest(engine: &ConnectMetricEngine, input: Vec<ConnectMetric>) {
    let tx = engine.get_connect_msg_channel().unwrap();
    let last = input.last().unwrap();
    let key = last.key();
    let time = last.report_time;
    for event in input {
        tx.send(event).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let points =
                engine.query_metric_by_key(key.clone(), MetricResolution::Second).await.unwrap();
            if points.last().is_some_and(|point| point.report_time == time) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("live worker did not drain");
}

async fn read(engine: &ConnectMetricEngine, query: &str, key: &ConnectKey) -> usize {
    match query {
        "connections" => black_box(engine.connect_infos().await).len(),
        "src" => black_box(engine.get_realtime_ip_stats(true).await).len(),
        "dst" => black_box(engine.get_realtime_ip_stats(false).await).len(),
        "iface" => black_box(engine.get_realtime_iface_stats().await).len(),
        "chart" => black_box(
            engine.query_metric_by_key(key.clone(), MetricResolution::Second).await.unwrap(),
        )
        .len(),
        _ => unreachable!(),
    }
}

async fn read_bench(count: usize) {
    let engine = engine().await;
    let input = events(count, now_ms() - 120_000, 0..24, 5000);
    let keys: Vec<_> = input[..count].iter().map(ConnectMetric::key).collect();
    ingest(&engine, input).await;
    for (query, expected) in
        [("connections", count), ("src", 256), ("dst", 1024), ("iface", 4), ("chart", 24)]
    {
        let mut times = Vec::new();
        for i in 0..110 {
            let key = &keys[i * 997 % count];
            let start = Instant::now();
            let found = read(&engine, query, key).await;
            let elapsed = start.elapsed();
            assert_eq!(found, expected);
            if i >= 10 {
                times.push(elapsed);
            }
        }
        times.sort_unstable();
        println!("{count:5} {query:12} p50={:?} p95={:?}", times[49], times[94]);
    }
    engine.shutdown().await;
}

async fn write_bench(mixed: bool) -> (Duration, usize) {
    const COUNT: usize = 8192;
    let engine = engine().await;
    let start = now_ms() - 205_000;
    ingest(&engine, events(COUNT, start, 0..1, 1000)).await;
    let input = events(COUNT, start, 1..201, 1000);
    let key = input[0].key();
    let (stop, mut stopped) = oneshot::channel::<()>();
    let reader = mixed.then(|| {
        let engine = Arc::clone(&engine);
        let first = tokio::time::Instant::now() + Duration::from_millis(100);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval_at(first, Duration::from_millis(100));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut reads = 0;
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    _ = timer.tick() => {
                        for query in ["connections", "src", "dst", "iface", "chart"] {
                            read(&engine, query, &key).await;
                        }
                        reads += 1;
                    }
                }
            }
            reads
        })
    });
    let before = Instant::now();
    ingest(&engine, input).await;
    let elapsed = before.elapsed();
    let _ = stop.send(());
    let reads = match reader {
        Some(task) => task.await.unwrap(),
        None => 0,
    };
    assert_eq!(engine.connect_infos().await.len(), COUNT);
    engine.shutdown().await;
    (elapsed, reads)
}

async fn run() {
    for count in [1024, 8192, 32768] {
        read_bench(count).await;
    }
    let mut rates = [Vec::new(), Vec::new()];
    for round in 0..6 {
        for mixed in [round % 2 != 0, round % 2 == 0] {
            let (elapsed, reads) = write_bench(mixed).await;
            let rate = 1_638_400.0 / elapsed.as_secs_f64();
            println!("round {round} mixed={mixed} {rate:.0} reports/s, {reads} read cycles");
            if round > 0 {
                rates[usize::from(mixed)].push(rate);
            }
        }
    }
    for (i, values) in rates.iter_mut().enumerate() {
        values.sort_by(f64::total_cmp);
        println!(
            "mixed={} median={:.0} reports/s range={:.0}..{:.0}",
            i == 1,
            values[2],
            values[0],
            values[4]
        );
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
