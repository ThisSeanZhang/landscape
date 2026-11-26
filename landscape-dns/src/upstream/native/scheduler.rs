//! Endpoint selection and response arbitration for one upstream pool.

use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use hickory_proto::op::{DnsRequestOptions, Message, Query, ResponseCode};
use hickory_proto::rr::RData;
use tokio::task::JoinSet;

use super::traits::{DnsConnector, DnsTransport};
use super::{UpstreamError, UpstreamPool, pool_config, select_better_error};
use crate::resolve::answer::DnsAnswer;

const INITIAL_RTT_US: u64 = 10_000;
const MAX_RTT_US: u64 = 600_000_000;
// Periodically give one slot to each endpoint, even if its last query failed.
const EXPLORE_INTERVAL: usize = 8;

#[derive(Debug, Default)]
struct EndpointGroup {
    indices: Vec<usize>,
    turn: AtomicUsize,
}

/// Per-lookup retry history. A capacity rejection leaves the endpoint eligible
/// after a different endpoint's application error frees a stream slot.
#[derive(Default)]
pub(super) struct AttemptHistory {
    blocked: Vec<usize>,
    failed: Vec<usize>,
}

impl AttemptHistory {
    fn record_failure(&mut self, index: usize, error: &UpstreamError) {
        let entries = match error {
            UpstreamError::NoConnections => &mut self.blocked,
            _ => &mut self.failed,
        };
        if !entries.contains(&index) {
            entries.push(index);
        }
    }

    fn priority(&self, index: usize) -> u8 {
        if self.failed.contains(&index) {
            2
        } else if self.blocked.contains(&index) {
            1
        } else {
            0
        }
    }
}

type LegResult = (usize, Result<Message, UpstreamError>);

#[derive(Debug)]
pub(super) struct EndpointScheduler {
    udp: EndpointGroup,
    stream: EndpointGroup,
    srtt_us: Vec<AtomicU64>,
}

impl EndpointScheduler {
    pub(super) fn new(connectors: &[Arc<dyn DnsConnector>]) -> Self {
        let mut udp = EndpointGroup::default();
        let mut stream = EndpointGroup::default();
        for (index, connector) in connectors.iter().enumerate() {
            match connector.transport() {
                DnsTransport::Udp => udp.indices.push(index),
                DnsTransport::Stream => stream.indices.push(index),
            }
        }
        Self {
            udp,
            stream,
            srtt_us: connectors.iter().map(|_| AtomicU64::new(INITIAL_RTT_US)).collect(),
        }
    }

    fn group(&self, force_stream: bool) -> &EndpointGroup {
        if force_stream || self.udp.indices.is_empty() { &self.stream } else { &self.udp }
    }

    fn select<'a>(
        &self,
        group: &'a EndpointGroup,
        cap: usize,
        history: &AttemptHistory,
    ) -> Cow<'a, [usize]> {
        let indices = &group.indices;
        if cap == 0 {
            return Cow::Borrowed(&[]);
        }
        if indices.len() <= cap {
            return Cow::Borrowed(indices);
        }
        let turn = group.turn.fetch_add(1, Ordering::Relaxed);
        let mut ranked = indices.clone();
        ranked.rotate_left(turn % indices.len());
        // Snapshot each score once so concurrent observations cannot change the ordering mid-sort.
        // Give retries an untried endpoint before reusing a preferred but busy one.
        ranked.sort_by_cached_key(|&i| {
            (history.priority(i), self.srtt_us[i].load(Ordering::Relaxed))
        });
        ranked.truncate(cap);
        if turn.is_multiple_of(EXPLORE_INTERVAL) {
            let explore = indices[(turn / EXPLORE_INTERVAL) % indices.len()];
            if history.priority(explore) == 0 && !ranked.contains(&explore) {
                ranked[cap - 1] = explore;
            }
        }
        Cow::Owned(ranked)
    }

    pub(super) fn remaining_fanout(
        &self,
        force_stream: bool,
        cap: usize,
        history: &AttemptHistory,
    ) -> usize {
        let group = self.group(force_stream);
        cap.min(group.indices.iter().filter(|i| !history.failed.contains(i)).count())
    }

    fn observe(&self, index: usize, elapsed_us: u64, result: &Result<Message, UpstreamError>) {
        let sample = match result {
            Ok(_)
            | Err(UpstreamError::Protocol(ResponseCode::NXDomain | ResponseCode::NoError, _)) => {
                Some(elapsed_us.clamp(1, MAX_RTT_US))
            }
            Err(
                UpstreamError::Timeout
                | UpstreamError::Protocol(..)
                | UpstreamError::Internal(_)
                | UpstreamError::Response(_)
                | UpstreamError::Tls(_),
            ) => None,
            Err(UpstreamError::NoConnections | UpstreamError::Offline) => return,
        };
        let _ = self.srtt_us[index].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
            Some(match sample {
                Some(us) => (prev * 7 + us) / 8,
                None => (prev * 2 + INITIAL_RTT_US).min(MAX_RTT_US),
            })
        });
    }
}

/// Outcome of one concurrent fan-out attempt.
enum FanOutVerdict {
    /// A usable answer (positive, or truncated when stream legs already ran).
    Answer(Message),
    /// An explicit negative answer (NXDomain/NoData) is final; the SOA
    /// record (when the upstream sent one) rides along so the caller can
    /// honour RFC 2308 negative caching.
    Negative(Message),
    /// A truncated UDP answer arrived and no positive answer did. Preferred
    /// over a negative: truncation means the data exists (it just does not
    /// fit over UDP), so the caller retries stream-only and may recover it,
    /// whereas the negative from another endpoint would be premature.
    Truncated(Message),
    /// Every leg failed with a transient error.
    Failed(UpstreamError),
}

impl UpstreamPool {
    async fn query_endpoint(
        self: &Arc<Self>,
        index: usize,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> LegResult {
        let connector = &self.connectors[index];
        let group = self.scheduler.group(connector.transport() == DnsTransport::Stream);
        // No ranking is needed when every eligible endpoint already participates.
        let start = (group.indices.len() > self.config.fanout).then(Instant::now);
        let result = self.leg_query(connector.clone(), query, options).await;
        if let Some(start) = start {
            self.scheduler.observe(index, start.elapsed().as_micros() as u64, &result);
        }
        (index, result)
    }

    /// One attempt: query up to `config.fanout` primary legs concurrently and
    /// select the outcome with a Balanced strategy — a positive answer wins
    /// immediately (the other legs are aborted), an explicit negative answer
    /// (NXDomain/NoData) waits a short grace for a positive, a truncated UDP
    /// answer is surfaced (ahead of a negative, since the stream retry may
    /// recover the full answer) so the caller retries stream-only, and
    /// transport failures are retried by the caller.
    ///
    /// When every primary leg fails with a transient error, plaintext pools
    /// fall through to their stream (TCP) legs in the same attempt — the old
    /// sequential UDP→TCP fallback, now concurrent.
    pub(super) async fn attempt(
        self: &Arc<Self>,
        query: &Query,
        options: &DnsRequestOptions,
        force_stream: bool,
        fanout: usize,
        history: &mut AttemptHistory,
    ) -> Result<Message, UpstreamError> {
        let primary = self.scheduler.group(force_stream);
        let legs = self.scheduler.select(primary, fanout, history);
        match self.fan_out(query, options, &legs, history).await {
            FanOutVerdict::Answer(message) => Ok(message),
            FanOutVerdict::Negative(message) => Ok(message),
            FanOutVerdict::Truncated(message) => Ok(message),
            FanOutVerdict::Failed(e) => {
                // Explicit protocol answers (ServFail, Refused, ...) and
                // permanent TLS failures are final — matching
                // `lookup_message`'s handling of them and the module doc's
                // "an explicit protocol code is the final answer": the UDP→
                // stream fallback below is only for *transient* transport
                // errors, and re-querying a server that just answered with
                // ServFail would double its latency and load for nothing.
                if e.is_final() {
                    return Err(e);
                }
                // The UDP→stream fallback only applies to the primary UDP
                // phase: a failed stream-only phase (force_stream) must not
                // re-run the same stream legs within the same attempt.
                if !force_stream && !self.scheduler.udp.indices.is_empty() {
                    let stream =
                        self.scheduler.select(&self.scheduler.stream, self.config.fanout, history);
                    if !stream.is_empty() {
                        return match self.fan_out(query, options, &stream, history).await {
                            FanOutVerdict::Answer(message) => Ok(message),
                            FanOutVerdict::Negative(message) => Ok(message),
                            FanOutVerdict::Truncated(message) => Ok(message),
                            FanOutVerdict::Failed(e2) => {
                                // Both phases failed: report the more
                                // informative error instead of letting the
                                // fallback phase's error mask the primary
                                // phase's (e.g. a cap-bound NoConnections
                                // hiding a connectivity Timeout).
                                let mut best = Some(e);
                                select_better_error(&mut best, e2);
                                Err(best.unwrap())
                            }
                        };
                    }
                }
                Err(e)
            }
        }
    }

    /// Queries the given legs concurrently and applies the Balanced response
    /// selection.
    async fn fan_out(
        self: &Arc<Self>,
        query: &Query,
        options: &DnsRequestOptions,
        legs: &[usize],
        history: &mut AttemptHistory,
    ) -> FanOutVerdict {
        // A single leg is the common router topology (one upstream IP).
        // Avoid JoinSet spawn, query clone, abort bookkeeping and the
        // negative-grace timer when there is nothing to race.
        if let [index] = legs {
            let result = self.query_endpoint(*index, query, options).await;
            return Self::single_leg_verdict(result, history);
        }

        let mut join_set = JoinSet::new();
        for &idx in legs {
            let pool = self.clone();
            let query = query.clone();
            let options = *options;
            join_set.spawn(async move { pool.query_endpoint(idx, &query, &options).await });
        }
        if join_set.is_empty() {
            return FanOutVerdict::Failed(UpstreamError::NoConnections);
        }

        let mut last_err: Option<UpstreamError> = None;
        let mut negative: Option<Message> = None;
        let mut truncated: Option<Message> = None;
        let grace = tokio::time::sleep(pool_config::NEGATIVE_GRACE);
        tokio::pin!(grace);

        loop {
            // `biased;` makes a ready leg result win over the grace timer
            // when both fire in the same poll cycle, so a positive that
            // settles exactly at the grace boundary is not discarded.
            tokio::select! {
                biased;
                joined = join_set.join_next() => {
                    let Some(joined) = joined else {
                        // Every leg settled without a positive answer. A
                        // truncated answer outranks an explicit negative
                        // (stream retry may recover the data), so it is
                        // returned before the negative.
                        if let Some(message) = truncated {
                            return FanOutVerdict::Truncated(message);
                        }
                        if let Some(message) = negative {
                            return FanOutVerdict::Negative(message);
                        }
                        return FanOutVerdict::Failed(
                            last_err.unwrap_or(UpstreamError::NoConnections),
                        );
                    };
                    if let Some(verdict) = Self::fold_leg_outcome(
                        &mut last_err,
                        &mut negative,
                        &mut truncated,
                        &mut grace,
                        joined,
                        history,
                    ) {
                        // Positive answer: win immediately.
                        // The other legs are aborted mid-flight. Their
                        // connection-level failures are deliberately not
                        // recorded: an aborted query proves nothing about
                        // the connection (it may simply have been slower
                        // than the winner). A genuinely dead connection
                        // is still retired eventually — its aborted legs
                        // never update `last_used_ms`, so it goes stale
                        // and the next query races it against a fresh
                        // dial, retiring it on failure.
                        join_set.abort_all();
                        return verdict;
                    }
                }
                _ = &mut grace, if negative.is_some() => {
                    // No positive answer arrived within the grace window. A
                    // truncated UDP answer is still preferred over the
                    // negative: the stream retry may recover the full answer,
                    // so surface the truncation instead of the negative.
                    // Before aborting, harvest any leg that settled in the
                    // same poll cycle: `biased;` already prefers a ready leg
                    // result over the timer, and this drain is the backstop
                    // for results enqueued right after the select fired — a
                    // positive at the grace boundary must not be discarded.
                    while let Some(joined) = join_set.try_join_next() {
                        if let Some(verdict) = Self::fold_leg_outcome(
                            &mut last_err,
                            &mut negative,
                            &mut truncated,
                            &mut grace,
                            joined,
                            history,
                        ) {
                            join_set.abort_all();
                            return verdict;
                        }
                    }
                    // Aborting the remaining legs skips their failure
                    // accounting (see the positive-answer abort above).
                    join_set.abort_all();
                    if let Some(message) = truncated {
                        return FanOutVerdict::Truncated(message);
                    }
                    let mut message = negative.unwrap();
                    for record in &mut message.authorities {
                        if matches!(record.data, RData::SOA(_)) {
                            record.ttl = record.ttl.min(pool_config::CONTESTED_NEGATIVE_TTL);
                        }
                    }
                    return FanOutVerdict::Negative(message);
                }
            }
        }
    }

    /// Maps the sole leg's result to the same verdict shape used by the
    /// concurrent selection path. There is no competing endpoint to grace or
    /// abort, so a negative keeps its original SOA TTL unchanged.
    fn single_leg_verdict(
        (index, result): LegResult,
        history: &mut AttemptHistory,
    ) -> FanOutVerdict {
        match result {
            Ok(message) if message.metadata.truncation => FanOutVerdict::Truncated(message),
            Ok(message) if DnsAnswer::is_negative_message(&message) => {
                FanOutVerdict::Negative(message)
            }
            Ok(message) => FanOutVerdict::Answer(message),
            Err(UpstreamError::Protocol(
                code @ (ResponseCode::NXDomain | ResponseCode::NoError),
                soa,
            )) => {
                let mut message = Message::response(0, hickory_proto::op::OpCode::Query);
                message.metadata.response_code = code;
                if let Some(soa) = soa {
                    message.authorities.push(*soa);
                }
                FanOutVerdict::Negative(message)
            }
            Err(e) => {
                history.record_failure(index, &e);
                FanOutVerdict::Failed(e)
            }
        }
    }

    /// Folds one leg's outcome into the fan-out selection state; returns a
    /// verdict when the leg's answer wins outright (a positive answer).
    fn fold_leg_outcome(
        last_err: &mut Option<UpstreamError>,
        negative: &mut Option<Message>,
        truncated: &mut Option<Message>,
        grace: &mut Pin<&mut tokio::time::Sleep>,
        joined: Result<LegResult, tokio::task::JoinError>,
        history: &mut AttemptHistory,
    ) -> Option<FanOutVerdict> {
        match Self::single_leg_verdict(joined.ok()?, history) {
            FanOutVerdict::Answer(message) => return Some(FanOutVerdict::Answer(message)),
            FanOutVerdict::Truncated(message) => {
                truncated.get_or_insert(message);
            }
            FanOutVerdict::Negative(message) => {
                if negative.is_none() {
                    *negative = Some(message);
                    grace.as_mut().reset(tokio::time::Instant::now() + pool_config::NEGATIVE_GRACE);
                }
            }
            FanOutVerdict::Failed(err) => select_better_error(last_err, err),
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::native::mocks::MockConnector;

    #[test]
    fn capped_fanout_prefers_fast_dns_answers_and_revisits_every_endpoint() {
        let connectors: Vec<Arc<dyn DnsConnector>> = (1..=4)
            .map(|i| MockConnector::new([10, 0, 0, i], DnsTransport::Udp) as Arc<dyn DnsConnector>)
            .collect();
        let scheduler = EndpointScheduler::new(&connectors);
        let group = scheduler.group(false);
        let negative = Err(UpstreamError::Protocol(ResponseCode::NXDomain, None));
        scheduler.observe(2, 1_000, &negative);
        scheduler.observe(0, 20_000, &negative);
        scheduler.observe(1, 0, &Err(UpstreamError::Timeout));
        scheduler.observe(3, 0, &Err(UpstreamError::NoConnections));
        assert_eq!(scheduler.srtt_us[2].load(Ordering::Relaxed), 8_875);
        assert_eq!(scheduler.srtt_us[3].load(Ordering::Relaxed), INITIAL_RTT_US);
        let mut history = AttemptHistory::default();
        assert_eq!(scheduler.select(group, 4, &history).as_ref(), &[0, 1, 2, 3]);
        assert!(scheduler.select(group, 0, &history).is_empty());
        assert!(scheduler.select(scheduler.group(true), 2, &history).is_empty());
        let mut explored = [false; 4];
        for turn in 0..4 * EXPLORE_INTERVAL {
            let selected = scheduler.select(group, 1, &history);
            assert_eq!(selected.len(), 1);
            if !turn.is_multiple_of(EXPLORE_INTERVAL) {
                assert_eq!(selected[0], 2);
            }
            explored[selected[0]] = true;
        }
        assert_eq!(explored, [true; 4]);
        // A busy winner has the same SRTT after the attempt; retries still cover all four.
        for _ in 0..2 {
            for &index in scheduler.select(group, 2, &history).iter() {
                history.record_failure(index, &UpstreamError::NoConnections);
            }
        }
        history.blocked.sort_unstable();
        assert_eq!(history.blocked, [0, 1, 2, 3]);
    }
}
