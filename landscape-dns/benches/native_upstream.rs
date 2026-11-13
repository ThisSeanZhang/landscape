//! CLI wrapper for the native upstream-pool benchmark.
//!
//! Run with:
//! `cargo bench -p landscape-dns --features bench --bench native_upstream`
//!
//! Optional environment overrides:
//! - `LANDSCAPE_BENCH_WARMUP`
//! - `LANDSCAPE_BENCH_SEQ_SECS`
//! - `LANDSCAPE_BENCH_CONCURRENCY`
//! - `LANDSCAPE_BENCH_CONC_SECS`
//! - `LANDSCAPE_BENCH_ENDPOINTS`
//! - `LANDSCAPE_BENCH_FANOUT`
//! - `LANDSCAPE_BENCH_MARK`
//! - `LANDSCAPE_BENCH_NAME`

use std::env;
use std::time::Duration;

use landscape_dns::benchmark::native_upstream::{BenchOptions, run};

fn main() {
    let mut options = BenchOptions::default();
    if let Ok(value) = env::var("LANDSCAPE_BENCH_WARMUP") {
        options.warmup_queries = value.parse().expect("LANDSCAPE_BENCH_WARMUP must be a usize");
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_SEQ_SECS") {
        options.sequential_duration =
            Duration::from_secs_f64(value.parse().expect("LANDSCAPE_BENCH_SEQ_SECS must be f64"));
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_CONCURRENCY") {
        options.concurrency = value.parse().expect("LANDSCAPE_BENCH_CONCURRENCY must be usize");
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_CONC_SECS") {
        options.concurrent_duration =
            Duration::from_secs_f64(value.parse().expect("LANDSCAPE_BENCH_CONC_SECS must be f64"));
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_ENDPOINTS") {
        options.endpoint_count = value.parse().expect("LANDSCAPE_BENCH_ENDPOINTS must be a usize");
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_FANOUT") {
        options.max_fanout = value.parse().expect("LANDSCAPE_BENCH_FANOUT must be a usize");
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_MARK") {
        options.mark = value.parse().expect("LANDSCAPE_BENCH_MARK must be u32");
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_NAME") {
        options.query_name = value;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build benchmark runtime");
    let report = runtime.block_on(run(options)).expect("run native upstream benchmark");
    println!("{}", report.to_json());
}
