//! 分钟聚合纯逻辑:1s 紧凑快照 → 每分钟每子系统一行(无 IO,两种构建可测)。

use std::collections::HashMap;

use landscape_common::memtrack::{subsystem_label, CompactSnapshot, SlotCounters};
use landscape_common::metric::memory::{MemMinuteRecord, PROCESS_SUBSYSTEM};

#[derive(Default)]
struct SubsystemMinuteAcc {
    live_sum: u128,
    live_max: u64,
    samples: u64,
    /// 分钟内首/末次快照的累计值,差值即分钟内增量。
    alloc_first: Option<u64>,
    alloc_last: u64,
    free_first: Option<u64>,
    free_last: u64,
}

impl SubsystemMinuteAcc {
    fn ingest_live(&mut self, live: u64) {
        self.live_sum += live as u128;
        self.live_max = self.live_max.max(live);
        self.samples += 1;
    }

    fn ingest_subsystem(&mut self, live: u64, allocated: u64, freed: u64) {
        self.ingest_live(live);
        self.alloc_first.get_or_insert(allocated);
        self.alloc_last = allocated;
        self.free_first.get_or_insert(freed);
        self.free_last = freed;
    }

    fn finish(&self, subsystem: String, minute_ts: u64) -> MemMinuteRecord {
        let samples = self.samples.max(1);
        MemMinuteRecord {
            minute_ts,
            subsystem,
            live_avg_bytes: (self.live_sum / samples as u128) as u64,
            live_max_bytes: self.live_max,
            alloc_delta_bytes: self.alloc_last.saturating_sub(self.alloc_first.unwrap_or(0)),
            free_delta_bytes: self.free_last.saturating_sub(self.free_first.unwrap_or(0)),
        }
    }
}

/// 跨分钟滚动聚合器:ingest 1s 紧凑快照,分钟翻转时吐出上一分钟的全部行。
#[derive(Default)]
pub struct MinuteAggregator {
    current_minute: Option<u64>,
    subsystems: HashMap<usize, SubsystemMinuteAcc>,
    process: SubsystemMinuteAcc,
}

impl MinuteAggregator {
    pub fn new() -> Self {
        MinuteAggregator::default()
    }

    /// 写入一个快照;若跨入新分钟,返回刚结束分钟的行(可能为空:同一分钟
    /// 内首次 ingest 不产生行)。跳过从未使用的全零槽位(累计计数器单调,
    /// 全零 = 进程启动以来无分配,过滤不丢信息且减少空行入库)。
    pub fn ingest(&mut self, snapshot: &CompactSnapshot) -> Vec<MemMinuteRecord> {
        let minute = snapshot.timestamp_ms / 60_000 * 60_000;
        let finished = match self.current_minute {
            None => {
                self.current_minute = Some(minute);
                None
            }
            Some(current) if current == minute => None,
            Some(current) => {
                self.current_minute = Some(minute);
                Some(current)
            }
        };
        let rows = finished.map(|minute_ts| self.take_rows(minute_ts)).unwrap_or_default();

        for (slot, counters) in snapshot.iter_slots() {
            if counters == SlotCounters::default() {
                continue;
            }
            self.subsystems.entry(slot).or_default().ingest_subsystem(
                counters.live_bytes,
                counters.allocated_bytes,
                counters.freed_bytes,
            );
        }
        if let Some(rss) = snapshot.meta.process_rss_bytes {
            self.process.ingest_live(rss);
        }

        rows
    }

    /// 显式强制吐出当前分钟。后台 recorder 停止时会丢弃未完成分钟。
    pub fn flush_current(&mut self) -> Vec<MemMinuteRecord> {
        self.current_minute.take().map(|minute_ts| self.take_rows(minute_ts)).unwrap_or_default()
    }

    /// 丢弃当前未完成分钟,用于 recorder 停止或重启。
    pub fn discard_current(&mut self) {
        self.current_minute = None;
        self.subsystems.clear();
        self.process = SubsystemMinuteAcc::default();
    }

    fn take_rows(&mut self, minute_ts: u64) -> Vec<MemMinuteRecord> {
        let mut rows: Vec<MemMinuteRecord> = std::mem::take(&mut self.subsystems)
            .into_iter()
            .map(|(slot, acc)| acc.finish(subsystem_label(slot).to_string(), minute_ts))
            .collect();
        if self.process.samples > 0 {
            rows.push(self.process.finish(PROCESS_SUBSYSTEM.to_string(), minute_ts));
        }
        self.process = SubsystemMinuteAcc::default();
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::memtrack::{CompactSnapshot, SnapshotMeta};

    /// 仅填充 dns 槽位(下标 0)的紧凑快照,其余槽位保持全零(会被聚合器过滤)。
    fn snap(
        timestamp_ms: u64,
        live: u64,
        allocated: u64,
        freed: u64,
        rss: Option<u64>,
    ) -> CompactSnapshot {
        let mut snapshot = CompactSnapshot::zeroed(timestamp_ms);
        snapshot.set_slot(
            0,
            SlotCounters {
                allocated_bytes: allocated,
                freed_bytes: freed,
                live_bytes: live,
                ..Default::default()
            },
        );
        snapshot.meta = SnapshotMeta {
            process_rss_bytes: rss,
            process_virtual_bytes: rss,
            total_live_bytes: live,
            untracked_bytes: None,
        };
        snapshot
    }

    #[test]
    fn aggregator_emits_rows_on_minute_rollover() {
        let mut agg = MinuteAggregator::new();
        let minute = 600_000u64;

        assert!(agg.ingest(&snap(minute + 1_000, 100, 300, 200, Some(1_000))).is_empty());
        assert!(agg.ingest(&snap(minute + 2_000, 120, 400, 280, Some(1_100))).is_empty());

        let rows = agg.ingest(&snap(minute + 61_000, 130, 500, 370, Some(1_200)));
        assert_eq!(rows.len(), 2);
        let dns = rows.iter().find(|r| r.subsystem == "dns").unwrap();
        assert_eq!(dns.minute_ts, minute);
        assert_eq!(dns.live_avg_bytes, 110);
        assert_eq!(dns.live_max_bytes, 120);
        assert_eq!(dns.alloc_delta_bytes, 100);
        assert_eq!(dns.free_delta_bytes, 80);
        let process = rows.iter().find(|r| r.subsystem == PROCESS_SUBSYSTEM).unwrap();
        assert_eq!(process.live_avg_bytes, 1_050);
        assert_eq!(process.live_max_bytes, 1_100);
        assert_eq!(process.alloc_delta_bytes, 0);
        assert_eq!(process.free_delta_bytes, 0);

        let tail = agg.flush_current();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].minute_ts, minute + 60_000);
        assert_eq!(tail.iter().find(|r| r.subsystem == "dns").unwrap().live_avg_bytes, 130);
        assert!(agg.flush_current().is_empty());
    }

    #[test]
    fn discard_current_drops_incomplete_minute() {
        let mut agg = MinuteAggregator::new();
        let minute = 600_000;
        assert!(agg.ingest(&snap(minute + 1_000, 100, 300, 200, Some(1_000))).is_empty());

        agg.discard_current();

        assert!(agg.ingest(&snap(minute + 61_000, 120, 400, 280, Some(1_100))).is_empty());
        let rows = agg.flush_current();
        let dns = rows.iter().find(|row| row.subsystem == "dns").unwrap();
        assert_eq!(dns.minute_ts, minute + 60_000);
        assert_eq!(dns.live_avg_bytes, 120);
        assert_eq!(dns.alloc_delta_bytes, 0);
    }
}
