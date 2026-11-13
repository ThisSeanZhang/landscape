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
//! Baseline (2026-11-12, commit 4877386b, AMD EPYC 7302 16 vCPU, Linux
//! 6.12.111 x86_64, median of 3 runs; use the same command for comparisons):
//! sequential 1 in-flight: 6999 qps, p50 134 us, p95 214 us, p99 276 us;
//! concurrent 32 workers: 73694 qps, p50 415 us, p95 666 us, p99 873 us;
//! zero errors in both phases.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::upstream::native::UpstreamPool;
use crate::upstream::native::mark::MarkRuntimeProvider;
use crate::upstream::native::pool_config::PoolSettings;

/// Benchmark knobs. Defaults are intentionally short enough for repeated
/// local runs but long enough that scheduling noise does not dominate.
#[derive(Debug, Clone)]
pub struct BenchOptions {
    /// Queries used to warm the pool before any measurement.
    pub warmup_queries: usize,
    /// Duration of the single-client latency phase.
    pub sequential_duration: Duration,
    /// Number of concurrent workers in the throughput phase.
    pub concurrency: usize,
    /// Duration of the concurrent throughput phase.
    pub concurrent_duration: Duration,
    /// Fully-qualified name queried in every lookup.
    pub query_name: String,
    /// SO_MARK applied to upstream sockets. Zero avoids CAP_NET_ADMIN in
    /// environments where SO_MARK is privileged.
    pub mark: u32,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            warmup_queries: 500,
            sequential_duration: Duration::from_secs(3),
            concurrency: 32,
            concurrent_duration: Duration::from_secs(5),
            query_name: "www.example.com.".to_string(),
            mark: 0,
        }
    }
}

/// Statistics for one benchmark phase.
#[derive(Debug, Clone)]
pub struct PhaseStats {
    pub queries: u64,
    pub errors: u64,
    pub elapsed: Duration,
    pub qps: f64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

/// Full benchmark result, serializable to a line-oriented JSON object without
/// pulling a serialization dependency into this feature.
#[derive(Debug, Clone)]
pub struct BenchReport {
    pub query_name: String,
    pub warmup_queries: usize,
    pub sequential: PhaseStats,
    pub concurrent: PhaseStats,
}

impl BenchReport {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            concat!(
                "{{\"query_name\":\"{}\",\"warmup_queries\":{},",
                "\"sequential\":{},\"concurrent\":{}}}"
            ),
            json_escape(&self.query_name),
            self.warmup_queries,
            phase_json(&self.sequential),
            phase_json(&self.concurrent),
        );
        out
    }
}

fn phase_json(s: &PhaseStats) -> String {
    format!(
        concat!(
            "{{\"queries\":{},\"errors\":{},\"elapsed_secs\":{:.6},",
            "\"qps\":{:.3},\"p50_us\":{},\"p95_us\":{},\"p99_us\":{},\"max_us\":{}}}"
        ),
        s.queries,
        s.errors,
        s.elapsed.as_secs_f64(),
        s.qps,
        s.p50_us,
        s.p95_us,
        s.p99_us,
        s.max_us,
    )
}

fn json_escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Runs the complete benchmark against an in-process local DNS server.
pub async fn run(options: BenchOptions) -> Result<BenchReport, String> {
    let server = LocalDnsServer::spawn().await?;
    let upstream = DnsUpstreamConfig {
        remark: "native upstream benchmark".to_string(),
        mode: DnsUpstreamMode::Plaintext,
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(server.port),
        ..Default::default()
    };
    let pool = UpstreamPool::new(
        1,
        options.mark,
        &upstream,
        MarkRuntimeProvider::new(options.mark, upstream.bind_config.clone()),
        &PoolSettings::default(),
        None,
    )
    .ok_or_else(|| "failed to build native upstream pool".to_string())?;
    let name = Name::from_str(&options.query_name)
        .map_err(|e| format!("invalid benchmark query name: {e}"))?;

    for _ in 0..options.warmup_queries {
        lookup_ok(&pool, &name).await?;
    }

    let sequential = run_sequential(&pool, &name, options.sequential_duration).await?;
    let concurrent =
        run_concurrent(&pool, &name, options.concurrency, options.concurrent_duration).await?;

    // Keep the server alive for the whole measurement; dropping it aborts its
    // tasks and closes both listeners.
    drop(server);
    Ok(BenchReport {
        query_name: options.query_name,
        warmup_queries: options.warmup_queries,
        sequential,
        concurrent,
    })
}

async fn lookup_ok(pool: &Arc<UpstreamPool>, name: &Name) -> Result<(), String> {
    let answer = pool
        .lookup_name(name.clone(), RecordType::A)
        .await
        .map_err(|e| format!("native pool lookup failed: {e}"))?;
    if answer.records.is_empty() {
        return Err("native pool returned an empty answer".to_string());
    }
    Ok(())
}

async fn run_sequential(
    pool: &Arc<UpstreamPool>,
    name: &Name,
    duration: Duration,
) -> Result<PhaseStats, String> {
    let start = Instant::now();
    let deadline = start + duration;
    let mut samples = Vec::new();
    let mut errors = 0u64;

    while Instant::now() < deadline {
        let query_start = Instant::now();
        match pool.lookup_name(name.clone(), RecordType::A).await {
            Ok(answer) if !answer.records.is_empty() => {
                samples.push(elapsed_us(query_start));
            }
            Ok(_) => {
                errors += 1;
                samples.push(elapsed_us(query_start));
            }
            Err(_) => {
                errors += 1;
                samples.push(elapsed_us(query_start));
            }
        }
    }

    Ok(summarize(samples, errors, start.elapsed()))
}

async fn run_concurrent(
    pool: &Arc<UpstreamPool>,
    name: &Name,
    concurrency: usize,
    duration: Duration,
) -> Result<PhaseStats, String> {
    if concurrency == 0 {
        return Err("concurrency must be greater than zero".to_string());
    }

    let start = Instant::now();
    let deadline = start + duration;
    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let pool = pool.clone();
        let name = name.clone();
        workers.push(tokio::spawn(async move {
            let mut samples = Vec::new();
            let mut errors = 0u64;
            while Instant::now() < deadline {
                let query_start = Instant::now();
                match pool.lookup_name(name.clone(), RecordType::A).await {
                    Ok(answer) if !answer.records.is_empty() => {
                        samples.push(elapsed_us(query_start));
                    }
                    Ok(_) | Err(_) => {
                        errors += 1;
                        samples.push(elapsed_us(query_start));
                    }
                }
            }
            (samples, errors)
        }));
    }

    let mut samples = Vec::new();
    let mut errors = 0u64;
    for worker in workers {
        let (worker_samples, worker_errors) =
            worker.await.map_err(|e| format!("benchmark worker panicked: {e}"))?;
        samples.extend(worker_samples);
        errors += worker_errors;
    }

    Ok(summarize(samples, errors, start.elapsed()))
}

fn elapsed_us(start: Instant) -> u64 {
    start.elapsed().as_micros().min(u64::MAX as u128) as u64
}

fn summarize(mut samples: Vec<u64>, errors: u64, elapsed: Duration) -> PhaseStats {
    samples.sort_unstable();
    let queries = samples.len() as u64;
    let qps = if elapsed.is_zero() { 0.0 } else { queries as f64 / elapsed.as_secs_f64() };
    PhaseStats {
        queries,
        errors,
        elapsed,
        qps,
        p50_us: percentile(&samples, 0.50),
        p95_us: percentile(&samples, 0.95),
        p99_us: percentile(&samples, 0.99),
        max_us: samples.last().copied().unwrap_or(0),
    }
}

fn percentile(samples: &[u64], p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let index = ((samples.len() - 1) as f64 * p).ceil() as usize;
    samples[index]
}

/// A minimal authoritative-style DNS responder used only by the benchmark.
/// It answers every A query with 1.2.3.4 and mirrors the query id/questions.
struct LocalDnsServer {
    port: u16,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for LocalDnsServer {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl LocalDnsServer {
    async fn spawn() -> Result<Self, String> {
        // Binding UDP first gives us a free port; binding TCP to the same
        // port mirrors the native plaintext topology (one endpoint exposing
        // both transports).
        for _ in 0..8 {
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|e| format!("bind benchmark UDP socket: {e}"))?;
            let port = udp.local_addr().map_err(|e| format!("read UDP local addr: {e}"))?.port();
            let tcp = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                Ok(tcp) => tcp,
                Err(_) => continue,
            };

            let udp_task = tokio::spawn(run_udp_server(udp));
            let tcp_task = tokio::spawn(run_tcp_server(tcp));
            return Ok(Self { port, tasks: vec![udp_task, tcp_task] });
        }
        Err("could not bind UDP and TCP benchmark server on the same port".to_string())
    }
}

async fn run_udp_server(socket: UdpSocket) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else { break };
        if let Some(response) = answer_query(&buf[..len]) {
            let _ = socket.send_to(&response, peer).await;
        }
    }
}

async fn run_tcp_server(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { break };
        tokio::spawn(handle_tcp_connection(stream));
    }
}

async fn handle_tcp_connection(mut stream: TcpStream) {
    loop {
        let mut length = [0u8; 2];
        if stream.read_exact(&mut length).await.is_err() {
            break;
        }
        let len = u16::from_be_bytes(length) as usize;
        let mut request = vec![0u8; len];
        if stream.read_exact(&mut request).await.is_err() {
            break;
        }
        let Some(response) = answer_query(&request) else { break };
        let Ok(response_len) = u16::try_from(response.len()) else { break };
        if stream.write_all(&response_len.to_be_bytes()).await.is_err() {
            break;
        }
        if stream.write_all(&response).await.is_err() {
            break;
        }
    }
}

fn answer_query(request: &[u8]) -> Option<Vec<u8>> {
    let mut response = Message::from_vec(request).ok()?;
    let question = response.queries.first()?.clone();
    response.metadata.message_type = MessageType::Response;
    response.metadata.response_code = ResponseCode::NoError;
    response.answers.clear();
    response.add_answer(Record::from_rdata(
        question.name().clone(),
        60,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    ));
    response.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_handles_empty_and_upper_tail() {
        assert_eq!(percentile(&[], 0.99), 0);
        let samples = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(percentile(&samples, 0.0), 1);
        assert_eq!(percentile(&samples, 0.5), 6);
        assert_eq!(percentile(&samples, 0.99), 10);
    }

    #[test]
    fn report_json_is_valid_json() {
        let stats = PhaseStats {
            queries: 10,
            errors: 1,
            elapsed: Duration::from_secs(2),
            qps: 5.0,
            p50_us: 10,
            p95_us: 20,
            p99_us: 30,
            max_us: 40,
        };
        let report = BenchReport {
            query_name: "www.example.com.".to_string(),
            warmup_queries: 100,
            sequential: stats.clone(),
            concurrent: stats,
        };
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(value["sequential"]["queries"], 10);
        assert_eq!(value["concurrent"]["errors"], 1);
    }

    #[tokio::test]
    async fn udp_and_tcp_benchmark_server_answers() {
        let server = LocalDnsServer::spawn().await.unwrap();
        let pool = UpstreamPool::new(
            1,
            0,
            &DnsUpstreamConfig {
                mode: DnsUpstreamMode::Plaintext,
                ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                port: Some(server.port),
                ..Default::default()
            },
            MarkRuntimeProvider::new(0, Default::default()),
            &PoolSettings::default(),
            None,
        )
        .unwrap();
        let name = Name::from_str("www.example.com.").unwrap();
        let answer = pool.lookup_name(name, RecordType::A).await.unwrap();
        assert_eq!(answer.records.len(), 1);
    }
}
