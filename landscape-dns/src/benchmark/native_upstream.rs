//! Repeatable end-to-end benchmark for the native DNS upstream pool.
//!
//! The measured path is:
//!
//! ```text
//! UpstreamPool::lookup_name -> native transport -> local UDP/TCP DNS server
//! ```
//!
//! Listener, rule matching, cache and operating-system integration are
//! deliberately excluded so the numbers isolate the pool and transport hot
//! path. Start with a plaintext single-endpoint workload (the common router
//! case), then use the same harness for later before/after measurements.
//!
//! Run with:
//!
//! ```text
//! CARGO_PROFILE_BENCH_LTO=off CARGO_PROFILE_BENCH_CODEGEN_UNITS=16 \
//!   cargo bench -p landscape-dns --features bench --bench native_upstream
//! ```
//!
//! Multi-endpoint/fan-out runs use the endpoint and fan-out overrides:
//!
//! ```text
//! LANDSCAPE_BENCH_ENDPOINTS=2 LANDSCAPE_BENCH_FANOUT=2 \
//!   CARGO_PROFILE_BENCH_LTO=off CARGO_PROFILE_BENCH_CODEGEN_UNITS=16 \
//!   cargo bench -p landscape-dns --features bench --bench native_upstream
//! ```
//!
//! The responder has its own Tokio runtime and configurable CPU set/workers,
//! separate from the pool runtime. They share the process and machine. This is a closed-loop pool benchmark, not a complete
//! DNS-server capacity test. Traffic counters include probes and late replies;
//! a delayed reply can cross a phase boundary. Nonzero responder_overflows
//! invalidates performance comparisons. Histograms are bounded and use 3
//! significant digits; reported latency is rounded to at least one microsecond.
//!
//! Fault scenarios: slow_first, blackhole_first and servfail_first affect
//! endpoint zero; drop_first_udp drops the first UDP request for each unique
//! question at every endpoint. Current plaintext fallback may recover over TCP
//! rather than retransmitting UDP. Unique questions distinguish retries from
//! later lookups. Warmup errors are reported, not treated as harness failures.
//! See scripts/bench_native_dns.py --help for a reproducible scenario matrix.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

use crate::upstream::native::UpstreamPool;
use crate::upstream::native::mark::MarkRuntimeProvider;
use crate::upstream::native::pool_config::PoolSettings;

/// Linux affinity applies to the calling thread; new threads inherit its mask.
pub fn current_affinity() -> Result<Vec<usize>, String> {
    // SAFETY: cpu_set_t is initialized and passed with its exact size.
    unsafe {
        let mut mask: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of_val(&mask), &mut mask) != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok((0..libc::CPU_SETSIZE as usize).filter(|&cpu| libc::CPU_ISSET(cpu, &mask)).collect())
    }
}

pub fn pin_current_thread(cpus: &[usize]) -> Result<(), String> {
    if cpus.is_empty() || cpus.iter().any(|&cpu| cpu >= libc::CPU_SETSIZE as usize) {
        return Err("CPU set must be nonempty and fit cpu_set_t".into());
    }
    // SAFETY: indices are bounds checked, mask initialized, and size matches cpu_set_t.
    unsafe {
        let mut mask: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut mask);
        for &cpu in cpus {
            libc::CPU_SET(cpu, &mut mask);
        }
        if libc::sched_setaffinity(0, std::mem::size_of_val(&mask), &mask) != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    let mut requested = cpus.to_vec();
    requested.sort_unstable();
    requested.dedup();
    if current_affinity()? != requested {
        return Err("kernel did not apply the complete requested CPU set".into());
    }
    Ok(())
}

/// Faults apply to the first endpoint, except DropFirstUdp, which applies to all.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scenario {
    #[default]
    Normal,
    SlowFirst,
    DropFirstUdp,
    BlackholeFirst,
    ServfailFirst,
}

impl FromStr for Scenario {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "normal" => Ok(Self::Normal),
            "slow_first" => Ok(Self::SlowFirst),
            "drop_first_udp" => Ok(Self::DropFirstUdp),
            "blackhole_first" => Ok(Self::BlackholeFirst),
            "servfail_first" => Ok(Self::ServfailFirst),
            _ => Err(format!("unknown scenario: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchOptions {
    pub warmup_queries: usize,
    pub sequential_duration: Duration,
    pub concurrency: usize,
    pub concurrent_duration: Duration,
    pub query_name: String,
    pub endpoint_count: usize,
    pub max_fanout: usize,
    pub mark: u32,
    pub scenario: Scenario,
    pub slow_delay_ms: u64,
    pub attempts: u8,
    pub pool_cpus: Vec<usize>,
    pub pool_workers: usize,
    pub upstream_cpus: Vec<usize>,
    pub upstream_workers: usize,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            warmup_queries: 500,
            sequential_duration: Duration::from_secs(3),
            concurrency: 32,
            concurrent_duration: Duration::from_secs(5),
            query_name: "www.example.com.".into(),
            endpoint_count: 1,
            max_fanout: 2,
            mark: 0,
            scenario: Scenario::Normal,
            slow_delay_ms: 50,
            attempts: 3,
            pool_cpus: Vec::new(),
            pool_workers: 1,
            upstream_cpus: Vec::new(),
            upstream_workers: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub count: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

impl LatencyStats {
    fn from_histogram(h: &Histogram<u64>) -> Self {
        Self {
            count: h.len(),
            p50_us: h.value_at_quantile(0.5),
            p95_us: h.value_at_quantile(0.95),
            p99_us: h.value_at_quantile(0.99),
            max_us: h.max(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EndpointTraffic {
    pub udp_requests: u64,
    pub tcp_requests: u64,
    pub responses: u64,
    pub dropped: u64,
    pub responder_overflows: u64,
}

#[derive(Default)]
struct Counters {
    udp: AtomicU64,
    tcp: AtomicU64,
    responses: AtomicU64,
    dropped: AtomicU64,
    overflows: AtomicU64,
}
impl Counters {
    fn snapshot(&self) -> EndpointTraffic {
        EndpointTraffic {
            udp_requests: self.udp.load(Ordering::Relaxed),
            tcp_requests: self.tcp.load(Ordering::Relaxed),
            responses: self.responses.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            responder_overflows: self.overflows.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PhaseStats {
    pub queries: u64,
    pub errors: u64,
    pub elapsed_secs: f64,
    /// Includes errors; use success_qps to compare useful throughput.
    pub completion_qps: f64,
    pub success_qps: f64,
    pub error_rate: f64,
    pub success_latency: LatencyStats,
    pub error_latency: LatencyStats,
    pub upstream: Vec<EndpointTraffic>,
    pub upstream_requests_per_query: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchReport {
    pub options: BenchOptions,
    pub warmup_errors: u64,
    pub pool_affinity: Vec<usize>,
    pub upstream_affinity: Vec<usize>,
    pub sequential: PhaseStats,
    pub concurrent: PhaseStats,
}
impl BenchReport {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serializable benchmark report")
    }
}

/// Fixed memory per worker, independent of benchmark duration or QPS.
struct Samples {
    success: Histogram<u64>,
    error: Histogram<u64>,
}
impl Samples {
    fn new() -> Self {
        Self {
            success: Histogram::new_with_bounds(1, 3_600_000_000, 3).unwrap(),
            error: Histogram::new_with_bounds(1, 3_600_000_000, 3).unwrap(),
        }
    }
    fn record(&mut self, success: bool, duration: Duration) {
        let h = if success { &mut self.success } else { &mut self.error };
        h.record(duration.as_micros().clamp(1, 3_600_000_000) as u64).unwrap();
    }
    fn merge(&mut self, other: Self) {
        self.success.add(other.success).unwrap();
        self.error.add(other.error).unwrap();
    }
}

pub async fn run(options: BenchOptions) -> Result<BenchReport, String> {
    if !(1..=254).contains(&options.endpoint_count)
        || !(1..=8).contains(&options.max_fanout)
        || options.concurrency == 0
        || options.upstream_workers == 0
        || options.pool_workers == 0
        || options.sequential_duration.is_zero()
        || options.concurrent_duration.is_zero()
        || !(1..=5).contains(&options.attempts)
    {
        return Err("invalid options: endpoints 1..254, fanout 1..8, positive concurrency/durations, attempts 1..5 required".into());
    }
    let server = LocalDnsServer::spawn(options.clone()).await?;
    let settings = PoolSettings {
        max_fanout: Some(options.max_fanout as u8),
        attempts: Some(options.attempts),
        ..Default::default()
    };
    let pool = UpstreamPool::new(
        1,
        options.mark,
        &DnsUpstreamConfig {
            mode: DnsUpstreamMode::Plaintext,
            ips: endpoint_ips(options.endpoint_count),
            port: Some(server.port),
            ..Default::default()
        },
        MarkRuntimeProvider::new(options.mark, Default::default()),
        &settings,
        None,
    )
    .ok_or("failed to build native upstream pool")?;
    let name = Name::from_str(&options.query_name).map_err(|e| e.to_string())?;
    // A unique question lets the responder identify a lookup across retry IDs/sockets.
    // The normal scenario retains the fixed-name workload for baseline comparisons.
    let sequence = Arc::new(AtomicU64::new(0));
    if options.scenario == Scenario::DropFirstUdp {
        unique_name(&name, u64::MAX)?;
    }
    let mut warmup_errors = 0;
    for _ in 0..options.warmup_queries {
        if !lookup(&pool, &name, &sequence, options.scenario).await? {
            warmup_errors += 1;
        }
    }
    let sequential =
        phase(&pool, &name, &sequence, &options, &server, 1, options.sequential_duration).await?;
    let concurrent = phase(
        &pool,
        &name,
        &sequence,
        &options,
        &server,
        options.concurrency,
        options.concurrent_duration,
    )
    .await?;
    Ok(BenchReport {
        pool_affinity: current_affinity()?,
        upstream_affinity: server.affinity.clone(),
        options,
        warmup_errors,
        sequential,
        concurrent,
    })
}

fn unique_name(base: &Name, sequence: u64) -> Result<Name, String> {
    Name::from_str(&format!("q{sequence}.{base}")).map_err(|e| e.to_string())
}
async fn lookup(
    pool: &Arc<UpstreamPool>,
    name: &Name,
    sequence: &AtomicU64,
    scenario: Scenario,
) -> Result<bool, String> {
    let name = if scenario == Scenario::DropFirstUdp {
        unique_name(name, sequence.fetch_add(1, Ordering::Relaxed))?
    } else {
        name.clone()
    };
    Ok(match pool.lookup_name(name.clone(), RecordType::A).await {
        Ok(answer) => {
            answer.response_code == ResponseCode::NoError
                && answer.records.iter().any(|r| {
                    r.name == name
                        && matches!(&r.data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1,2,3,4))
                })
        }
        Err(_) => false,
    })
}

async fn phase(
    pool: &Arc<UpstreamPool>,
    name: &Name,
    sequence: &Arc<AtomicU64>,
    options: &BenchOptions,
    server: &LocalDnsServer,
    concurrency: usize,
    duration: Duration,
) -> Result<PhaseStats, String> {
    let before: Vec<_> = server.counters.iter().map(|c| c.snapshot()).collect();
    let start = Instant::now();
    let deadline = start + duration;
    let mut workers = JoinSet::new();
    for _ in 0..concurrency {
        let (pool, name, sequence, scenario) =
            (pool.clone(), name.clone(), sequence.clone(), options.scenario);
        workers.spawn(async move {
            let mut samples = Samples::new();
            while Instant::now() < deadline {
                let started = Instant::now();
                let success = lookup(&pool, &name, &sequence, scenario).await?;
                samples.record(success, started.elapsed());
            }
            Ok::<_, String>(samples)
        });
    }
    let mut samples = Samples::new();
    while let Some(result) = workers.join_next().await {
        samples.merge(result.map_err(|e| e.to_string())??);
    }
    let elapsed = start.elapsed().as_secs_f64();
    let upstream: Vec<_> = server
        .counters
        .iter()
        .zip(before)
        .map(|(c, b)| {
            let a = c.snapshot();
            EndpointTraffic {
                udp_requests: a.udp_requests - b.udp_requests,
                tcp_requests: a.tcp_requests - b.tcp_requests,
                responses: a.responses - b.responses,
                dropped: a.dropped - b.dropped,
                responder_overflows: a.responder_overflows - b.responder_overflows,
            }
        })
        .collect();
    let queries = samples.success.len() + samples.error.len();
    let requests: u64 = upstream.iter().map(|t| t.udp_requests + t.tcp_requests).sum();
    Ok(PhaseStats {
        queries,
        errors: samples.error.len(),
        elapsed_secs: elapsed,
        completion_qps: queries as f64 / elapsed,
        success_qps: samples.success.len() as f64 / elapsed,
        error_rate: samples.error.len() as f64 / queries.max(1) as f64,
        success_latency: LatencyStats::from_histogram(&samples.success),
        error_latency: LatencyStats::from_histogram(&samples.error),
        upstream,
        upstream_requests_per_query: requests as f64 / queries.max(1) as f64,
    })
}

struct LocalDnsServer {
    port: u16,
    affinity: Vec<usize>,
    counters: Vec<Arc<Counters>>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for LocalDnsServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl LocalDnsServer {
    async fn spawn(options: BenchOptions) -> Result<Self, String> {
        let counters: Vec<_> =
            (0..options.endpoint_count).map(|_| Arc::new(Counters::default())).collect();
        let worker_counters = counters.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("dns-bench-upstream".into())
            .spawn(move || {
                let setup = (|| -> Result<_, String> {
                    if !options.upstream_cpus.is_empty() {
                        pin_current_thread(&options.upstream_cpus)?;
                    }
                    let affinity = current_affinity()?;
                    // Runtime threads inherit the upstream coordinator's CPU mask,
                    // independently of the pool thread that created it.
                    let mut builder = if options.upstream_workers == 1 {
                        tokio::runtime::Builder::new_current_thread()
                    } else {
                        let mut builder = tokio::runtime::Builder::new_multi_thread();
                        builder.worker_threads(options.upstream_workers);
                        builder.thread_name("dns-bench-up");
                        builder
                    };
                    let runtime = builder.enable_all().build().map_err(|e| e.to_string())?;
                    Ok((runtime, affinity))
                })();
                let (runtime, affinity) = match setup {
                    Ok(setup) => setup,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                runtime.block_on(async move {
                    match bind_servers(&options, &worker_counters).await {
                        Ok((port, mut tasks)) => {
                            if ready_tx.send(Ok((port, affinity))).is_ok() {
                                let _ = stop_rx.await;
                            }
                            tasks.abort_all();
                            while tasks.join_next().await.is_some() {}
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                        }
                    }
                });
            })
            .map_err(|e| e.to_string())?;
        let mut server = Self {
            port: 0,
            affinity: Vec::new(),
            counters,
            stop: Some(stop_tx),
            thread: Some(thread),
        };
        (server.port, server.affinity) = ready_rx.await.map_err(|e| e.to_string())??;
        Ok(server)
    }
}

async fn bind_servers(
    options: &BenchOptions,
    counters: &[Arc<Counters>],
) -> Result<(u16, JoinSet<()>), String> {
    for _ in 0..8 {
        let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.map_err(|e| e.to_string())?;
        let port = first.local_addr().map_err(|e| e.to_string())?.port();
        let mut udp = vec![first];
        let mut tcp = Vec::new();
        let mut failed = false;
        for (index, ip) in endpoint_ips(options.endpoint_count).into_iter().enumerate() {
            if index > 0 {
                match UdpSocket::bind((ip, port)).await {
                    Ok(s) => udp.push(s),
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            match TcpListener::bind((ip, port)).await {
                Ok(s) => tcp.push(s),
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            continue;
        }
        let mut tasks = JoinSet::new();
        for (index, (udp, tcp)) in udp.into_iter().zip(tcp).enumerate() {
            tasks.spawn(run_udp(udp, index, options.clone(), counters[index].clone()));
            tasks.spawn(run_tcp(tcp, index, options.clone(), counters[index].clone()));
        }
        return Ok((port, tasks));
    }
    Err("could not bind benchmark endpoints".into())
}
fn endpoint_ips(count: usize) -> Vec<IpAddr> {
    (0..count).map(|i| Ipv4Addr::new(127, 0, 0, 1 + i as u8).into()).collect()
}

// Explicit limit makes a saturated responder visible instead of consuming unbounded memory.
const RESPONDER_LIMIT: usize = 65_536;
async fn run_udp(socket: UdpSocket, index: usize, options: BenchOptions, counters: Arc<Counters>) {
    let socket = Arc::new(socket);
    let mut pending = JoinSet::new();
    let mut dropped_names = HashSet::new();
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            _ = pending.join_next(), if !pending.is_empty() => {},
            received = socket.recv_from(&mut buf) => {
                let Ok((len, peer)) = received else { break };
                counters.udp.fetch_add(1, Ordering::Relaxed);
                if index == 0 && options.scenario == Scenario::BlackholeFirst {
                    counters.dropped.fetch_add(1, Ordering::Relaxed); continue;
                }
                if options.scenario == Scenario::DropFirstUdp {
                    let Ok(message) = Message::from_vec(&buf[..len]) else { continue };
                    let Some(question) = message.queries.first() else { continue };
                    let key = (question.name().clone(), question.query_type());
                    if !dropped_names.remove(&key) {
                        if dropped_names.len() >= RESPONDER_LIMIT {
                            counters.overflows.fetch_add(1, Ordering::Relaxed);
                        } else { dropped_names.insert(key); }
                        counters.dropped.fetch_add(1, Ordering::Relaxed); continue;
                    }
                }
                let Some(response) = answer_query(&buf[..len], index == 0 && options.scenario == Scenario::ServfailFirst) else { continue };
                if index == 0 && options.scenario == Scenario::SlowFirst {
                    if pending.len() >= RESPONDER_LIMIT { counters.overflows.fetch_add(1, Ordering::Relaxed); continue; }
                    let (socket, counters, delay) = (socket.clone(), counters.clone(), options.slow_delay_ms);
                    pending.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        if socket.send_to(&response, peer).await.is_ok() { counters.responses.fetch_add(1, Ordering::Relaxed); }
                    });
                } else if socket.send_to(&response, peer).await.is_ok() { counters.responses.fetch_add(1, Ordering::Relaxed); }
            }
        }
    }
}
async fn run_tcp(
    listener: TcpListener,
    index: usize,
    options: BenchOptions,
    counters: Arc<Counters>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                if connections.len() >= RESPONDER_LIMIT { counters.overflows.fetch_add(1, Ordering::Relaxed); continue; }
                connections.spawn(handle_tcp(stream, index, options.clone(), counters.clone()));
            }
        }
    }
}
async fn handle_tcp(
    mut stream: TcpStream,
    index: usize,
    options: BenchOptions,
    counters: Arc<Counters>,
) {
    loop {
        let Ok(len) = stream.read_u16().await else { return };
        let mut bytes = vec![0; len as usize];
        if stream.read_exact(&mut bytes).await.is_err() {
            return;
        }
        counters.tcp.fetch_add(1, Ordering::Relaxed);
        if index == 0 && options.scenario == Scenario::BlackholeFirst {
            counters.dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if index == 0 && options.scenario == Scenario::SlowFirst {
            tokio::time::sleep(Duration::from_millis(options.slow_delay_ms)).await;
        }
        let Some(response) =
            answer_query(&bytes, index == 0 && options.scenario == Scenario::ServfailFirst)
        else {
            continue;
        };
        if stream.write_u16(response.len() as u16).await.is_err()
            || stream.write_all(&response).await.is_err()
        {
            return;
        }
        counters.responses.fetch_add(1, Ordering::Relaxed);
    }
}
fn answer_query(request: &[u8], servfail: bool) -> Option<Vec<u8>> {
    let mut response = Message::from_vec(request).ok()?;
    let question = response.queries.first()?.clone();
    response.metadata.message_type = MessageType::Response;
    response.metadata.response_code =
        if servfail { ResponseCode::ServFail } else { ResponseCode::NoError };
    response.answers.clear();
    if !servfail {
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
    }
    response.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(scenario: Scenario) -> BenchOptions {
        BenchOptions {
            scenario,
            warmup_queries: 0,
            sequential_duration: Duration::from_millis(20),
            concurrent_duration: Duration::from_millis(20),
            concurrency: 2,
            ..Default::default()
        }
    }

    #[test]
    fn failures_do_not_pollute_success_latency() {
        let mut samples = Samples::new();
        samples.record(true, Duration::from_micros(100));
        samples.record(false, Duration::from_secs(1));
        let mut other = Samples::new();
        other.record(true, Duration::from_micros(200));
        samples.merge(other);
        assert_eq!(samples.success.len(), 2);
        assert_eq!(samples.error.len(), 1);
        assert!(samples.success.max() < 210);
        assert!(samples.error.min() >= 999_000);
    }

    #[tokio::test]
    async fn successful_report_contains_only_phase_traffic_and_valid_json() {
        let report =
            run(BenchOptions { warmup_queries: 3, ..options(Scenario::Normal) }).await.unwrap();
        assert_eq!(report.warmup_errors, 0);
        for phase in [&report.sequential, &report.concurrent] {
            assert!(phase.queries > 0);
            assert_eq!(phase.errors, 0);
            assert_eq!(phase.success_latency.count, phase.queries);
            assert_eq!(phase.error_latency.count, 0);
            assert_eq!(phase.upstream[0].udp_requests, phase.queries);
            assert_eq!(phase.upstream[0].responder_overflows, 0);
            assert_eq!(phase.success_qps, phase.completion_qps);
        }
        let json: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(json["options"]["scenario"], "normal");
    }

    #[tokio::test]
    async fn servfail_is_counted_as_failure_not_successful_throughput() {
        let report = run(options(Scenario::ServfailFirst)).await.unwrap();
        for phase in [&report.sequential, &report.concurrent] {
            assert!(phase.queries > 0);
            assert_eq!(phase.errors, phase.queries);
            assert_eq!(phase.success_qps, 0.0);
            assert_eq!(phase.error_rate, 1.0);
            assert_eq!(phase.success_latency.count, 0);
        }
    }

    #[tokio::test]
    async fn first_packet_loss_recovers_via_tcp_fallback() {
        let report = run(options(Scenario::DropFirstUdp)).await.unwrap();
        for phase in [&report.sequential, &report.concurrent] {
            assert!(phase.queries > 0);
            assert_eq!(phase.errors, 0);
            assert_eq!(phase.upstream[0].dropped, phase.queries);
            assert_eq!(phase.upstream[0].udp_requests, phase.queries);
            assert_eq!(phase.upstream[0].tcp_requests, phase.queries);
            assert!(phase.success_latency.p50_us >= 900_000);
        }
    }

    #[tokio::test]
    async fn second_endpoint_answers_when_first_is_blackholed_or_slow() {
        for scenario in [Scenario::BlackholeFirst, Scenario::SlowFirst, Scenario::ServfailFirst] {
            let report = run(BenchOptions {
                endpoint_count: 2,
                max_fanout: 2,
                slow_delay_ms: 50,
                ..options(scenario)
            })
            .await
            .unwrap();
            for phase in [&report.sequential, &report.concurrent] {
                assert_eq!(phase.errors, 0, "{scenario:?}");
                assert!(phase.upstream[1].udp_requests > 0);
                assert_eq!(phase.upstream[0].responder_overflows, 0);
            }
        }
    }

    #[tokio::test]
    async fn slow_responder_delays_answers_and_blackhole_does_not_answer() {
        use hickory_proto::op::Query;
        let question = Query::query(Name::from_str("fault.example.").unwrap(), RecordType::A);
        let mut request = Message::query();
        request.queries.push(question);
        let request = request.to_vec().unwrap();
        let server = LocalDnsServer::spawn(BenchOptions {
            slow_delay_ms: 50,
            ..options(Scenario::SlowFirst)
        })
        .await
        .unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.connect((Ipv4Addr::LOCALHOST, server.port)).await.unwrap();
        let started = Instant::now();
        client.send(&request).await.unwrap();
        let mut buf = [0u8; 4096];
        let len = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert_eq!(Message::from_vec(&buf[..len]).unwrap().answers.len(), 1);
        drop(server);

        let server = LocalDnsServer::spawn(options(Scenario::BlackholeFirst)).await.unwrap();
        client.connect((Ipv4Addr::LOCALHOST, server.port)).await.unwrap();
        client.send(&request).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), client.recv(&mut buf)).await.is_err()
        );
        assert_eq!(server.counters[0].snapshot().dropped, 1);
    }

    #[test]
    fn affinity_changes_are_thread_local_and_inherited_by_children() {
        let original = current_affinity().unwrap();
        let cpu = original[0];
        let child = std::thread::spawn(move || {
            pin_current_thread(&[cpu]).unwrap();
            assert_eq!(current_affinity().unwrap(), vec![cpu]);
            let inherited = std::thread::spawn(current_affinity).join().unwrap().unwrap();
            assert_eq!(inherited, vec![cpu]);
            assert!(pin_current_thread(&[]).is_err());
            assert!(pin_current_thread(&[libc::CPU_SETSIZE as usize]).is_err());
        });
        child.join().unwrap();
        assert_eq!(current_affinity().unwrap(), original);
    }

    #[tokio::test]
    async fn upstream_runtime_reports_requested_cpu_set() {
        let cpus: Vec<_> = current_affinity().unwrap().into_iter().take(2).collect();
        let server = LocalDnsServer::spawn(BenchOptions {
            upstream_cpus: cpus.clone(),
            upstream_workers: 2,
            ..options(Scenario::Normal)
        })
        .await
        .unwrap();
        assert_eq!(server.affinity, cpus);
    }

    #[tokio::test]
    async fn invalid_options_fail_before_starting_the_responder() {
        assert!(run(BenchOptions { concurrency: 0, ..options(Scenario::Normal) }).await.is_err());
        assert!(run(BenchOptions { attempts: 0, ..options(Scenario::Normal) }).await.is_err());
    }
}
