//! Run with cargo bench -p landscape-metric --features metric-persistent --bench dns_pipeline.
//! Set TMPDIR to the filesystem whose SQLite performance you want to measure.
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{
    Name, RData, Record,
    rdata::{A, AAAA},
};
use landscape_common::metric::dns::{DnsHistoryQueryParams, DnsMetricEvent, DnsOutcome};
use landscape_common::sys_config::{DnsMetricConfig, MetricStoreBackend, RuntimeConfigSource};
use landscape_common::utils::time::now_ms;
use landscape_metric::DnsMetricEngine;

const EVENTS: usize = 30_000;
const ROUNDS: usize = 5;
const READS: usize = 200;

fn events() -> Vec<DnsMetricEvent> {
    // Replay two complete minutes ending before the current minute. A stable set of
    // buckets makes both the read workload and its verified count reproducible.
    let start = now_ms() / 60_000 * 60_000 - 120_000;
    let domains: Vec<Arc<str>> = (0..128).map(|i| format!("host{i}.example").into()).collect();
    (0..EVENTS)
        .map(|i| {
            let domain = domains[(i / 8 + i) % domains.len()].clone();
            let data = if i % 3 == 0 {
                RData::AAAA(AAAA("2001:db8::1".parse().unwrap()))
            } else {
                RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))
            };
            let answer = Record::from_rdata(Name::from_ascii(&*domain).unwrap(), 60, data);
            DnsMetricEvent {
                flow_id: (i % 8) as u32,
                domain,
                query_type: answer.record_type(),
                response_code: ResponseCode::NoError,
                status: if i % 4 == 0 { DnsOutcome::Hit } else { DnsOutcome::Normal },
                report_time: start + (i * 120_000 / EVENTS) as u64,
                duration_ms: (i % 50 + 1) as u32,
                src_ip: Ipv4Addr::new(192, 0, 2, (i % 64 + 1) as u8).into(),
                answers: vec![answer],
            }
        })
        .collect()
}

struct Sample {
    elapsed: Duration,
    reads: Vec<Duration>,
}

async fn sample(backend: MetricStoreBackend) -> Sample {
    let dir = tempfile::tempdir().unwrap();
    let mut config = DnsMetricConfig::default().build_runtime();
    config.store.backend = backend;
    let engine = DnsMetricEngine::new(dir.path().into(), config.clone()).await.unwrap();
    let tx = engine.get_dns_msg_channel().unwrap();
    let input = events();
    let start = Instant::now();
    for event in input {
        tx.send(event).await.unwrap();
    }
    drop(tx);

    let mut reads = Vec::new();
    let elapsed = match backend {
        MetricStoreBackend::Memory => {
            tokio::time::timeout(Duration::from_secs(30), async {
                while engine.get_dns_lightweight_summary(Default::default()).await.total_queries
                    != EVENTS
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("live window did not drain");
            let elapsed = start.elapsed();
            for _ in 0..READS {
                let before = Instant::now();
                let result = engine.get_dns_lightweight_summary(Default::default()).await;
                reads.push(before.elapsed());
                assert_eq!(result.total_queries, EVENTS);
            }
            engine.shutdown().await;
            elapsed
        }
        MetricStoreBackend::Sqlite => {
            engine.shutdown().await;
            let elapsed = start.elapsed();
            let reader = DnsMetricEngine::new(dir.path().into(), config).await.unwrap();
            let history = reader
                .query_dns_history(DnsHistoryQueryParams { limit: Some(1), ..Default::default() })
                .await;
            assert_eq!(history.total, EVENTS);
            assert_eq!(reader.get_dns_summary(Default::default()).await.total_queries, EVENTS);
            reader.shutdown().await;
            elapsed
        }
    };
    assert_eq!(engine.writer_stats(), (0, 0), "history batches dropped or failed");
    Sample { elapsed, reads }
}

async fn run() {
    for backend in [MetricStoreBackend::Memory, MetricStoreBackend::Sqlite] {
        let mut rates = Vec::new();
        let mut reads = Vec::new();
        sample(backend).await;
        for round in 1..=ROUNDS {
            let result = sample(backend).await;
            let rate = EVENTS as f64 / result.elapsed.as_secs_f64();
            println!("{backend:?} round {round}: {rate:.0} events/s ({:?})", result.elapsed);
            rates.push(rate);
            reads.extend(result.reads);
        }
        rates.sort_by(f64::total_cmp);
        println!(
            "{backend:?}: median {:.0} events/s, range {:.0}..{:.0}",
            rates[ROUNDS / 2],
            rates[0],
            rates[ROUNDS - 1]
        );
        if !reads.is_empty() {
            reads.sort_unstable();
            println!(
                "Live summary ({} reads): p50 {:?}, p95 {:?}, p99 {:?}",
                reads.len(),
                reads[reads.len().div_ceil(2) - 1],
                reads[(reads.len() * 95).div_ceil(100) - 1],
                reads[(reads.len() * 99).div_ceil(100) - 1]
            );
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
