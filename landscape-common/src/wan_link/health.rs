//! Per-link health state computed by the health-check section.
//!
//! The section (in `landscape::wan_link_service`) probes and evaluates; the
//! route service (in `landscape-core`) aggregates the snapshots and is the
//! single source of truth for consumers (failover decisions, future status
//! views). This module is deliberately IO-free: the evaluator only sees
//! per-round probe results.

use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utils::time::get_f64_timestamp;

/// Debounced liveness of a link as judged by its health-check section.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum WanLinkHealthState {
    /// No verdict yet: the section just (re)started or has no session.
    #[default]
    Unknown,
    Healthy,
    Unhealthy,
}

/// One probe target's result, fed into [`HealthEvaluator::apply_round`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetProbe {
    pub target: Ipv4Addr,
    /// Round-trip time; `None` when the probe failed or timed out.
    pub rtt: Option<Duration>,
}

/// Per-target detail of the most recent probe round.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TargetHealthStat {
    pub target: Ipv4Addr,
    /// RTT of the latest probe; `None` when it failed.
    pub last_rtt_ms: Option<u64>,
    /// Smoothed RTT trend; `None` until the first successful probe. A
    /// failed probe keeps the previous trend.
    pub rtt_ewma_ms: Option<f64>,
}

/// Latest per-link health snapshot; refreshed on every probe round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WanLinkHealthInfo {
    pub link_id: Uuid,
    pub state: WanLinkHealthState,
    /// Consecutive failed rounds; reset by any successful round.
    pub consecutive_failures: u32,
    /// Per-target details from the most recent round.
    pub targets: Vec<TargetHealthStat>,
    /// Smoothed mean-RTT trend across the successful targets of a round;
    /// `None` until the first successful target.
    pub rtt_ewma_ms: Option<f64>,
    /// Smoothed failed-target fraction trend, `0.0..=1.0`; `None` until
    /// the first round.
    pub loss_ewma: Option<f64>,
    pub last_success_at: Option<f64>,
    pub last_failure_at: Option<f64>,
    pub updated_at: f64,
}

/// Debounced state transition reported by [`HealthEvaluator::apply_round`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthTransition {
    pub from: WanLinkHealthState,
    pub to: WanLinkHealthState,
}

/// Weight of the newest sample in the health EWMAs; history carries
/// `1 - ALPHA`. With the default 10s interval this tracks roughly the
/// last half minute of probing.
pub const HEALTH_EWMA_ALPHA: f64 = 0.3;

/// Probe rounds whose failures are tolerated right after a (re)start,
/// before routes and neighbor entries have converged.
pub const HEALTH_WARMUP_ROUNDS: u32 = 1;

fn update_ewma(current: Option<f64>, sample: f64) -> f64 {
    match current {
        Some(prev) => HEALTH_EWMA_ALPHA * sample + (1.0 - HEALTH_EWMA_ALPHA) * prev,
        None => sample,
    }
}

/// Pure per-link health state machine: debounced verdicts on probe rounds
/// plus EWMA trends. A round succeeds when at least `reliability` of its
/// targets answered; the threshold is capped at the round's target count
/// so targets that error locally (dropped by the caller before the round
/// reaches the evaluator) can never wedge the verdict. `Unhealthy` needs
/// `failure_threshold` consecutive failed rounds and `Healthy` is recovered
/// from `Unhealthy` only after `recovery_threshold` consecutive successful
/// rounds.
pub struct HealthEvaluator {
    failure_threshold: u32,
    recovery_threshold: u32,
    reliability: u32,
    info: WanLinkHealthInfo,
    consecutive_successes: u32,
    rounds_seen: u32,
}

impl HealthEvaluator {
    pub fn new(
        link_id: Uuid,
        failure_threshold: u32,
        recovery_threshold: u32,
        reliability: u32,
    ) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            recovery_threshold: recovery_threshold.max(1),
            reliability: reliability.max(1),
            info: WanLinkHealthInfo {
                link_id,
                state: WanLinkHealthState::Unknown,
                consecutive_failures: 0,
                targets: Vec::new(),
                rtt_ewma_ms: None,
                loss_ewma: None,
                last_success_at: None,
                last_failure_at: None,
                updated_at: get_f64_timestamp(),
            },
            consecutive_successes: 0,
            rounds_seen: 0,
        }
    }

    pub fn state(&self) -> WanLinkHealthState {
        self.info.state
    }

    pub fn info(&self) -> &WanLinkHealthInfo {
        &self.info
    }

    /// Apply one probe round and report the debounced state transition,
    /// if the verdict flipped. A round without probes is not a verdict:
    /// nothing is counted or updated.
    pub fn apply_round(&mut self, results: &[TargetProbe]) -> Option<HealthTransition> {
        if results.is_empty() {
            return None;
        }
        let now = get_f64_timestamp();
        let warmup = self.rounds_seen < HEALTH_WARMUP_ROUNDS;
        self.rounds_seen += 1;

        let mut targets = Vec::with_capacity(results.len());
        for probe in results {
            let prev = self.info.targets.iter().find(|stat| stat.target == probe.target);
            let last_rtt_ms = probe.rtt.map(|rtt| rtt.as_millis() as u64);
            let rtt_ewma_ms = match probe.rtt {
                Some(rtt) => Some(update_ewma(
                    prev.and_then(|stat| stat.rtt_ewma_ms),
                    rtt.as_millis() as f64,
                )),
                None => prev.and_then(|stat| stat.rtt_ewma_ms),
            };
            targets.push(TargetHealthStat { target: probe.target, last_rtt_ms, rtt_ewma_ms });
        }
        self.info.targets = targets;

        let total = results.len();
        let up = results.iter().filter(|probe| probe.rtt.is_some()).count();
        // Cap the requirement at what the round could actually probe:
        // locally errored targets are excluded upstream, and judging
        // against the configured count alone would wedge the link
        // Unhealthy whenever one of them stays locally broken.
        let required = self.reliability.min(total as u32);
        let round_ok = total > 0 && up as u32 >= required;
        let rtts: Vec<f64> = results
            .iter()
            .filter_map(|probe| probe.rtt)
            .map(|rtt| rtt.as_millis() as f64)
            .collect();
        if !rtts.is_empty() {
            let mean = rtts.iter().sum::<f64>() / rtts.len() as f64;
            self.info.rtt_ewma_ms = Some(update_ewma(self.info.rtt_ewma_ms, mean));
        }
        if total > 0 {
            let loss = 1.0 - up as f64 / total as f64;
            self.info.loss_ewma = Some(update_ewma(self.info.loss_ewma, loss));
        }

        let from = self.info.state;
        let to = if round_ok {
            self.info.last_success_at = Some(now);
            self.info.consecutive_failures = 0;
            self.consecutive_successes += 1;
            if from == WanLinkHealthState::Unhealthy
                && self.consecutive_successes < self.recovery_threshold
            {
                WanLinkHealthState::Unhealthy
            } else {
                WanLinkHealthState::Healthy
            }
        } else {
            self.info.last_failure_at = Some(now);
            self.consecutive_successes = 0;
            if warmup {
                from
            } else {
                self.info.consecutive_failures += 1;
                if self.info.consecutive_failures >= self.failure_threshold {
                    WanLinkHealthState::Unhealthy
                } else {
                    from
                }
            }
        };
        self.info.state = to;
        self.info.updated_at = now;

        (to != from).then_some(HealthTransition { from, to })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use WanLinkHealthState::{Healthy, Unhealthy, Unknown};

    const T1: Ipv4Addr = Ipv4Addr::new(223, 5, 5, 5);
    const T2: Ipv4Addr = Ipv4Addr::new(119, 29, 29, 29);

    fn evaluator(
        failure_threshold: u32,
        recovery_threshold: u32,
        reliability: u32,
    ) -> HealthEvaluator {
        HealthEvaluator::new(Uuid::nil(), failure_threshold, recovery_threshold, reliability)
    }

    fn ok(target: Ipv4Addr, ms: u64) -> TargetProbe {
        TargetProbe { target, rtt: Some(Duration::from_millis(ms)) }
    }

    fn fail(target: Ipv4Addr) -> TargetProbe {
        TargetProbe { target, rtt: None }
    }

    #[test]
    fn first_success_marks_healthy_and_seeds_trends() {
        let mut evaluator = evaluator(3, 3, 1);

        let transition = evaluator.apply_round(&[ok(T1, 40)]).unwrap();

        assert_eq!((transition.from, transition.to), (Unknown, Healthy));
        assert_eq!(evaluator.state(), Healthy);
        assert_eq!(evaluator.info().consecutive_failures, 0);
        assert_eq!(evaluator.info().rtt_ewma_ms, Some(40.0));
        assert_eq!(evaluator.info().loss_ewma, Some(0.0));
        assert_eq!(evaluator.info().targets.len(), 1);
        assert_eq!(evaluator.info().targets[0].last_rtt_ms, Some(40));
        assert_eq!(evaluator.info().targets[0].rtt_ewma_ms, Some(40.0));
        assert!(evaluator.info().last_success_at.is_some());
    }

    #[test]
    fn sub_threshold_failures_keep_healthy_and_rtt_trend() {
        let mut evaluator = evaluator(3, 3, 1);
        evaluator.apply_round(&[ok(T1, 40)]);

        assert!(evaluator.apply_round(&[fail(T1)]).is_none());
        assert!(evaluator.apply_round(&[fail(T1)]).is_none());

        assert_eq!(evaluator.state(), Healthy);
        assert_eq!(evaluator.info().consecutive_failures, 2);
        assert_eq!(evaluator.info().targets[0].last_rtt_ms, None);
        assert_eq!(evaluator.info().targets[0].rtt_ewma_ms, Some(40.0));
        assert!(evaluator.info().loss_ewma.unwrap() > 0.0);
    }

    #[test]
    fn threshold_failures_flip_to_unhealthy() {
        let mut evaluator = evaluator(3, 3, 1);
        evaluator.apply_round(&[ok(T1, 40)]);

        assert!(evaluator.apply_round(&[fail(T1)]).is_none());
        assert!(evaluator.apply_round(&[fail(T1)]).is_none());
        let transition = evaluator.apply_round(&[fail(T1)]).unwrap();

        assert_eq!((transition.from, transition.to), (Healthy, Unhealthy));
        assert_eq!(evaluator.info().consecutive_failures, 3);
    }

    #[test]
    fn warmup_tolerates_first_round_failure() {
        let mut evaluator = evaluator(1, 1, 1);

        assert!(evaluator.apply_round(&[fail(T1)]).is_none());
        assert_eq!(evaluator.state(), Unknown);
        assert_eq!(evaluator.info().consecutive_failures, 0);

        let transition = evaluator.apply_round(&[fail(T1)]).unwrap();
        assert_eq!((transition.from, transition.to), (Unknown, Unhealthy));
    }

    #[test]
    fn recovery_needs_consecutive_successful_rounds() {
        let mut evaluator = evaluator(1, 3, 1);
        evaluator.apply_round(&[fail(T1)]);
        evaluator.apply_round(&[fail(T1)]);
        assert_eq!(evaluator.state(), Unhealthy);

        assert!(evaluator.apply_round(&[ok(T1, 30)]).is_none());
        assert_eq!(evaluator.state(), Unhealthy);
        assert!(evaluator.apply_round(&[ok(T1, 30)]).is_none());
        assert_eq!(evaluator.state(), Unhealthy);

        assert!(evaluator.apply_round(&[fail(T1)]).is_none());
        assert_eq!(evaluator.state(), Unhealthy);

        assert!(evaluator.apply_round(&[ok(T1, 30)]).is_none());
        assert!(evaluator.apply_round(&[ok(T1, 30)]).is_none());
        let transition = evaluator.apply_round(&[ok(T1, 30)]).unwrap();
        assert_eq!((transition.from, transition.to), (Unhealthy, Healthy));
    }

    #[test]
    fn reliability_counts_up_targets() {
        let mut strict = evaluator(1, 1, 2);
        assert!(strict.apply_round(&[ok(T1, 20), fail(T2)]).is_none());
        assert_eq!(strict.info().loss_ewma, Some(0.5));

        let transition = strict.apply_round(&[ok(T1, 20), fail(T2)]).unwrap();
        assert_eq!((transition.from, transition.to), (Unknown, Unhealthy));

        let mut relaxed = evaluator(1, 1, 1);
        let transition = relaxed.apply_round(&[ok(T1, 20), fail(T2)]).unwrap();
        assert_eq!((transition.from, transition.to), (Unknown, Healthy));
        assert_eq!(relaxed.info().rtt_ewma_ms, Some(20.0));
    }

    #[test]
    fn reliability_is_capped_at_probeable_targets() {
        // reliability 3 but only 2 targets could be probed (the third
        // errored locally and was dropped by the caller): both answering
        // keeps the round successful instead of wedging the link.
        let mut evaluator = evaluator(1, 1, 3);
        let transition = evaluator.apply_round(&[ok(T1, 20), ok(T2, 30)]).unwrap();
        assert_eq!((transition.from, transition.to), (Unknown, Healthy));

        // Still strict within what could be probed: one of two down fails.
        let transition = evaluator.apply_round(&[ok(T1, 20), fail(T2)]).unwrap();
        assert_eq!((transition.from, transition.to), (Healthy, Unhealthy));
    }

    #[test]
    fn dropped_targets_are_pruned() {
        let mut evaluator = evaluator(3, 3, 1);
        evaluator.apply_round(&[ok(T1, 20), ok(T2, 30)]);
        assert_eq!(evaluator.info().targets.len(), 2);

        evaluator.apply_round(&[ok(T1, 25)]);

        assert_eq!(evaluator.info().targets.len(), 1);
        assert_eq!(evaluator.info().targets[0].target, T1);
        assert_eq!(evaluator.info().targets[0].rtt_ewma_ms, Some(21.5));
    }

    #[test]
    fn empty_round_is_not_a_verdict() {
        let mut evaluator = evaluator(3, 3, 1);
        evaluator.apply_round(&[ok(T1, 40)]);

        assert!(evaluator.apply_round(&[]).is_none());

        assert_eq!(evaluator.state(), Healthy);
        assert_eq!(evaluator.info().consecutive_failures, 0);
        assert_eq!(evaluator.info().targets.len(), 1);
    }
}
