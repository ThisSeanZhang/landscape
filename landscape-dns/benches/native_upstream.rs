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
//! - `LANDSCAPE_BENCH_SCENARIO` (normal, slow_first, drop_first_udp, blackhole_first, servfail_first)
//! - `LANDSCAPE_BENCH_SLOW_MS`
//! - `LANDSCAPE_BENCH_ATTEMPTS`
//! - `LANDSCAPE_BENCH_POOL_CPU` (single CPU shorthand)
//! - `LANDSCAPE_BENCH_POOL_CPUS` (comma-separated CPU IDs)
//! - `LANDSCAPE_BENCH_POOL_WORKERS`
//! - `LANDSCAPE_BENCH_UPSTREAM_CPUS` (comma-separated CPU IDs)
//! - `LANDSCAPE_BENCH_UPSTREAM_WORKERS`
//! - `LANDSCAPE_BENCH_MARK`
//! - `LANDSCAPE_BENCH_NAME`

use std::env;
use std::time::Duration;

use landscape_dns::benchmark::native_upstream::{
    BenchOptions, current_affinity, pin_current_thread, run,
};

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

    if let Ok(value) = env::var("LANDSCAPE_BENCH_SCENARIO") {
        options.scenario = value.parse().expect("valid benchmark scenario");
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_SLOW_MS") {
        options.slow_delay_ms = value.parse().expect("delay in milliseconds");
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_ATTEMPTS") {
        options.attempts = value.parse().expect("attempt count");
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_POOL_CPU") {
        options.pool_cpus = vec![value.parse().expect("pool CPU number")];
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_POOL_CPUS") {
        assert!(options.pool_cpus.is_empty(), "set POOL_CPU or POOL_CPUS, not both");
        options.pool_cpus =
            value.split(',').map(|cpu| cpu.parse().expect("pool CPU number")).collect();
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_POOL_WORKERS") {
        options.pool_workers = value.parse().expect("pool worker count");
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_UPSTREAM_CPUS") {
        options.upstream_cpus =
            value.split(',').map(|cpu| cpu.parse().expect("upstream CPU number")).collect();
    }
    if let Ok(value) = env::var("LANDSCAPE_BENCH_UPSTREAM_WORKERS") {
        options.upstream_workers = value.parse().expect("upstream worker count");
    }
    match (options.pool_cpus.is_empty(), options.upstream_cpus.is_empty()) {
        (false, false) => {
            let allowed = current_affinity().expect("read allowed CPUs");
            assert!(
                options.pool_cpus.iter().chain(&options.upstream_cpus).all(|c| allowed.contains(c)),
                "CPU outside allowed affinity"
            );
            assert!(
                options.pool_cpus.iter().all(|cpu| !options.upstream_cpus.contains(cpu)),
                "pool and upstream CPUs must be disjoint"
            );
            pin_current_thread(&options.pool_cpus).expect("pin pool main thread");
        }
        (true, true) => {}
        _ => panic!("set both pool CPU and upstream CPU set"),
    }
    assert!(options.pool_workers > 0, "pool worker count must be positive");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(options.pool_workers)
        .thread_name("dns-bench-pool")
        .enable_all()
        .build()
        .expect("build benchmark runtime");
    let report = runtime.block_on(run(options)).expect("run native upstream benchmark");
    println!("{}", report.to_json());
}
