//! Scripted mock connectors for pool unit tests (test-only, used by both the
//! `upstream` and `rule` test suites).

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{DnsRequestOptions, Message, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record};

use crate::connection::upstream::traits::{DnsConn, DnsConnError, DnsConnector, DnsTransport};

/// One scripted outcome for a mock connection; `After` completes only after
/// the delay (used to make race outcomes deterministic).
#[derive(Debug, Clone)]
pub(crate) enum MockOutcome {
    Now(Result<Message, DnsConnError>),
    After(Duration, Result<Message, DnsConnError>),
}

/// A scripted mock connection: each `query()` pops the next outcome from a
/// shared queue (connector-level), so a retry that dials a fresh connection
/// keeps consuming the script.
#[derive(Debug, Clone)]
pub(crate) struct MockConn {
    ip: IpAddr,
    transport: DnsTransport,
    outcomes: Arc<Mutex<VecDeque<MockOutcome>>>,
    query_count: Arc<AtomicU32>,
    shutdown_count: Arc<AtomicU32>,
}

#[async_trait]
impl DnsConn for MockConn {
    async fn query(
        &self,
        _query: &Query,
        _options: &DnsRequestOptions,
    ) -> Result<Message, DnsConnError> {
        self.query_count.fetch_add(1, Ordering::Relaxed);
        let outcome = {
            let mut outcomes = self.outcomes.lock().unwrap_or_else(|e| e.into_inner());
            outcomes.pop_front()
        };
        match outcome {
            Some(MockOutcome::Now(outcome)) => outcome,
            Some(MockOutcome::After(delay, outcome)) => {
                tokio::time::sleep(delay).await;
                outcome
            }
            None => Err(DnsConnError::Timeout),
        }
    }

    fn transport(&self) -> DnsTransport {
        self.transport
    }

    fn ip(&self) -> IpAddr {
        self.ip
    }

    fn shutdown(&self) {
        self.shutdown_count.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub(crate) struct MockConnector {
    ip: IpAddr,
    transport: DnsTransport,
    outcomes: Arc<Mutex<VecDeque<MockOutcome>>>,
    dial_count: Arc<AtomicU32>,
    dial_failures: Arc<AtomicU32>,
    /// Millis every dial sleeps before completing (forces dial overlap).
    dial_delay_ms: Arc<AtomicU64>,
    /// Dial ordinal (1-based) above which `connect` panics; u32::MAX never.
    panic_dials_over: Arc<AtomicU32>,
    conns: Arc<Mutex<Vec<Arc<MockConn>>>>,
}

impl MockConnector {
    pub(crate) fn new(ip: [u8; 4], transport: DnsTransport) -> Arc<Self> {
        Arc::new(Self {
            ip: IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            transport,
            outcomes: Arc::new(Mutex::new(VecDeque::new())),
            dial_count: Arc::new(AtomicU32::new(0)),
            dial_failures: Arc::new(AtomicU32::new(0)),
            dial_delay_ms: Arc::new(AtomicU64::new(0)),
            panic_dials_over: Arc::new(AtomicU32::new(u32::MAX)),
            conns: Arc::new(Mutex::new(vec![])),
        })
    }

    /// Makes every dial past the `n`-th panic (panic-isolation probes for
    /// callers that dial in the background, e.g. `scale_up`).
    pub(crate) fn panic_dials_over(&self, n: u32) {
        self.panic_dials_over.store(n, Ordering::Relaxed);
    }

    pub(crate) fn push(&self, outcome: Result<Message, DnsConnError>) {
        self.outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(MockOutcome::Now(outcome));
    }

    pub(crate) fn push_after(&self, delay: Duration, outcome: Result<Message, DnsConnError>) {
        self.outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(MockOutcome::After(delay, outcome));
    }

    /// Scripts the next `count` dials to fail with an I/O error.
    pub(crate) fn fail_next_dial(&self, count: u32) {
        self.dial_failures.fetch_add(count, Ordering::Relaxed);
    }

    /// Makes every dial take at least `ms` milliseconds (forces dials from
    /// concurrent tasks to overlap).
    pub(crate) fn set_dial_delay_ms(&self, ms: u64) {
        self.dial_delay_ms.store(ms, Ordering::Relaxed);
    }

    pub(crate) fn dials(&self) -> u32 {
        self.dial_count.load(Ordering::Relaxed)
    }

    pub(crate) fn queries(&self) -> u32 {
        self.conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|c| c.query_count.load(Ordering::Relaxed))
            .sum()
    }

    pub(crate) fn shutdowns(&self) -> u32 {
        self.conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|c| c.shutdown_count.load(Ordering::Relaxed))
            .sum()
    }

    pub(crate) fn alive_conns(&self) -> usize {
        self.conns.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[async_trait]
impl DnsConnector for MockConnector {
    async fn connect(&self) -> Result<Arc<dyn DnsConn>, DnsConnError> {
        self.dial_count.fetch_add(1, Ordering::Relaxed);
        let delay = self.dial_delay_ms.load(Ordering::Relaxed);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        let failures = self.dial_failures.load(Ordering::Relaxed);
        if failures > 0 {
            self.dial_failures.store(failures - 1, Ordering::Relaxed);
            return Err(DnsConnError::Io("scripted dial failure".into()));
        }
        if self.dial_count.load(Ordering::Relaxed) > self.panic_dials_over.load(Ordering::Relaxed) {
            panic!("scripted dial panic (past panic_dials_over threshold)");
        }
        let conn = Arc::new(MockConn {
            ip: self.ip,
            transport: self.transport,
            outcomes: self.outcomes.clone(),
            query_count: Arc::new(AtomicU32::new(0)),
            shutdown_count: Arc::new(AtomicU32::new(0)),
        });
        self.conns.lock().unwrap_or_else(|e| e.into_inner()).push(conn.clone());
        Ok(conn)
    }

    fn transport(&self) -> DnsTransport {
        self.transport
    }

    fn ip(&self) -> IpAddr {
        self.ip
    }
}

/// A successful A-record answer for `example.com.`.
pub(crate) fn ok_answer() -> Message {
    let mut message = Message::response(0, OpCode::Query);
    message.answers.push(Record::from_rdata(
        Name::from_str("example.com.").unwrap(),
        60,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    ));
    message
}

/// A truncated variant of [`ok_answer`] (the UDP truncation fallback trigger).
pub(crate) fn truncated_answer() -> Message {
    let mut message = ok_answer();
    message.metadata.truncation = true;
    message
}

/// A degenerate truncated answer: the TC bit with no records at all. A
/// server answering this over the stream phase of a truncation retry is
/// what the pool must survive without discarding a stored UDP partial.
pub(crate) fn empty_truncated_answer() -> Message {
    let mut message = Message::response(0, OpCode::Query);
    message.metadata.truncation = true;
    message
}

/// An answer message containing the given records (no other sections).
pub(crate) fn answer_with(answers: Vec<Record>) -> Message {
    let mut message = Message::response(0, OpCode::Query);
    message.answers = answers;
    message
}

/// An `A` record for the given IPv4 address.
pub(crate) fn a_record(ip: [u8; 4]) -> Record {
    a_record_named("example.com.", ip)
}

/// An `A` record with an explicit owner name.
pub(crate) fn a_record_named(owner: &str, ip: [u8; 4]) -> Record {
    Record::from_rdata(
        Name::from_str(owner).unwrap(),
        60,
        RData::A(A(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))),
    )
}

/// A connector whose `connect` panics: proves panic isolation boundaries
/// (fan-out legs, the maintenance task) contain a broken connector instead
/// of letting it take down shared machinery.
#[derive(Debug)]
pub(crate) struct PanicConnector {
    pub(crate) ip: IpAddr,
}

#[async_trait]
impl DnsConnector for PanicConnector {
    async fn connect(&self) -> Result<Arc<dyn DnsConn>, DnsConnError> {
        panic!("scripted panic")
    }

    fn transport(&self) -> DnsTransport {
        DnsTransport::Stream
    }

    fn ip(&self) -> IpAddr {
        self.ip
    }
}

/// An `AAAA` record for the given IPv6 address.
pub(crate) fn aaaa_record(ip: [u16; 8]) -> Record {
    Record::from_rdata(
        Name::from_str("example.com.").unwrap(),
        60,
        RData::AAAA(hickory_proto::rr::rdata::AAAA(std::net::Ipv6Addr::new(
            ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
        ))),
    )
}

/// A `CNAME` record: `owner` chains to `target`.
pub(crate) fn cname_record(owner: &str, target: &str) -> Record {
    Record::from_rdata(
        Name::from_str(owner).unwrap(),
        60,
        RData::CNAME(hickory_proto::rr::rdata::CNAME(Name::from_str(target).unwrap())),
    )
}
