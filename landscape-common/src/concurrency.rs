use std::collections::hash_map::DefaultHasher;
use std::fmt::Display;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use tokio::task::JoinHandle as TokioJoinHandle;
use tracing::Instrument;

pub const MAX_THREAD_NAME_LEN: usize = 15;

pub mod thread_name {
    pub mod fixed {
        /// Dedicated NTP/system clock synchronization thread.
        pub const TIME_SYNC: &str = "ld-time";
        /// Pingora gateway supervisor thread for the main HTTP proxy loop.
        pub const GATEWAY_MAIN: &str = "ld-gw-main";
        /// Driver thread that owns the secondary HTTPS gateway runtime.
        pub const GATEWAY_HTTPS_DRIVER: &str = "ld-gwh-drv";
        /// Single SQLite hot-store writer thread.
        pub const METRIC_DB_WRITER: &str = "ld-mdb";
        /// Background DuckDB cold-store sync thread.
        pub const METRIC_DB_COLD: &str = "ld-mdc";
        /// eBPF metric event reader thread that feeds userspace metric channels.
        pub const METRIC_EVENT_READER: &str = "ld-mevt";
        /// eBPF neighbor update listener thread.
        pub const EBPF_NEIGH_UPDATE: &str = "ld-neigh";
    }

    pub mod prefix {
        /// Primary webserver/control-plane Tokio runtime threads.
        pub const CORE_RUNTIME: &str = "ld-core";
        /// Secondary Tokio runtime for gateway HTTPS accept/IO work.
        pub const GATEWAY_HTTPS_RUNTIME: &str = "ld-gwh";
        /// Dedicated Tokio runtime for DuckDB query work.
        pub const METRIC_QUERY_RUNTIME: &str = "ld-mqry";
        /// Firewall eBPF worker threads keyed by interface.
        pub const FIREWALL: &str = "ld-fw";
        /// NAT eBPF worker threads keyed by interface.
        pub const NAT: &str = "ld-nat";
        /// WAN route eBPF worker threads keyed by interface.
        pub const ROUTE_WAN: &str = "ld-rw";
        /// LAN route eBPF worker threads keyed by interface.
        pub const ROUTE_LAN: &str = "ld-rl";
        /// MSS clamp eBPF worker threads keyed by interface.
        pub const MSS_CLAMP: &str = "ld-mss";
        /// hostapd watchdog threads keyed by interface.
        pub const WIFI: &str = "ld-wifi";
        /// PPPD watchdog threads keyed by PPP interface name.
        pub const PPPD: &str = "ld-ppp";
        /// PTY reader threads keyed by PTY session id.
        pub const PTY_READ: &str = "ld-ptyr";
        /// PTY writer threads keyed by PTY session id.
        pub const PTY_WRITE: &str = "ld-ptyw";
        /// PTY child-wait threads keyed by PTY session id.
        pub const PTY_WAIT: &str = "ld-ptyx";
        /// Packet dump receive threads keyed by interface.
        pub const DUMP_RX: &str = "ld-dmpr";
        /// Packet dump transmit threads keyed by interface.
        pub const DUMP_TX: &str = "ld-dmpt";
    }
}

pub mod task_label {
    pub mod task {
        /// Service manager task that supervises one restartable service instance.
        pub const SERVICE_MANAGER_SPAWN: &str = "service.manager.spawn";
        /// Service manager task that waits for and reports service shutdown.
        pub const SERVICE_MANAGER_STOP: &str = "service.manager.stop";
        /// Background redirect server that upgrades HTTP traffic to HTTPS.
        pub const WEB_REDIRECT_HTTPS: &str = "web.redirect_https";
        /// Long-lived PTY websocket session loop.
        pub const WS_PTY_SESSION: &str = "ws.pty.session";
        /// Long-lived Docker task websocket fan-out loop.
        pub const WS_DOCKER_TASKS: &str = "ws.docker.tasks";
        /// Long-lived packet dump websocket loop.
        pub const WS_DUMP_SESSION: &str = "ws.dump.session";
        /// Gateway copy task for downstream client to upstream target traffic.
        pub const GATEWAY_SNI_CLIENT_TO_UPSTREAM: &str = "gateway.sni.client_to_upstream";
        /// Gateway copy task for upstream target to downstream client traffic.
        pub const GATEWAY_SNI_UPSTREAM_TO_CLIENT: &str = "gateway.sni.upstream_to_client";
        /// Firewall service async launcher.
        pub const FIREWALL_RUN: &str = "firewall.service.run";
        /// Firewall service stop-signal bridge task.
        pub const FIREWALL_STOP: &str = "firewall.service.stop";
        /// Firewall observer task reacting to interface events.
        pub const FIREWALL_OBSERVER: &str = "firewall.service.observer";
        /// WAN route service async launcher.
        pub const ROUTE_WAN_RUN: &str = "route.wan.run";
        /// WAN route service stop-signal bridge task.
        pub const ROUTE_WAN_STOP: &str = "route.wan.stop";
        /// WAN route observer task reacting to interface events.
        pub const ROUTE_WAN_OBSERVER: &str = "route.wan.observer";
        /// LAN route service async launcher.
        pub const ROUTE_LAN_RUN: &str = "route.lan.run";
        /// LAN route service stop-signal bridge task.
        pub const ROUTE_LAN_STOP: &str = "route.lan.stop";
        /// LAN route observer task reacting to interface events.
        pub const ROUTE_LAN_OBSERVER: &str = "route.lan.observer";
        /// Metric service async launcher.
        pub const METRIC_SERVICE_RUN: &str = "metric.service.run";
        /// Metric service stop-signal bridge task.
        pub const METRIC_SERVICE_STOP: &str = "metric.service.stop";
        /// Background task that refreshes cached connect global stats.
        pub const METRIC_GLOBAL_STATS_REFRESH: &str = "metric.global_stats.refresh";
        /// Metric query executor task name used inside the dedicated query runtime.
        pub const METRIC_QUERY: &str = "metric.query";
        /// WiFi service async launcher.
        pub const WIFI_RUN: &str = "wifi.service.run";
        /// WiFi service stop-signal bridge task.
        pub const WIFI_STOP: &str = "wifi.service.stop";
        /// MSS clamp service async launcher.
        pub const MSS_CLAMP_RUN: &str = "mss_clamp.run";
        /// MSS clamp service stop-signal bridge task.
        pub const MSS_CLAMP_STOP: &str = "mss_clamp.stop";
        /// MSS clamp observer task reacting to interface events.
        pub const MSS_CLAMP_OBSERVER: &str = "mss_clamp.observer";
        /// PPPD service async launcher.
        pub const PPPD_RUN: &str = "pppd.service.run";
        /// PPPD service stop-signal bridge task.
        pub const PPPD_STOP: &str = "pppd.service.stop";
        /// PPPD watcher that polls acquired addresses and syncs routes.
        pub const PPPD_IP_WATCH: &str = "pppd.service.ip_watch";
        /// NAT service async launcher.
        pub const NAT_RUN: &str = "nat.service.run";
        /// NAT service stop-signal bridge task.
        pub const NAT_STOP: &str = "nat.service.stop";
        /// NAT observer task reacting to interface events.
        pub const NAT_OBSERVER: &str = "nat.service.observer";
        /// EventHub dispatcher task that receives events and dispatches to domain broadcast channels.
        pub const EVENT_HUB_DISPATCHER: &str = "event.hub.dispatcher";
        /// eBPF neighbor update async task that periodically syncs ARP/NDP tables.
        pub const EBPF_NEIGH_UPDATE: &str = "ebpf.neigh_update";
    }

    pub mod op {
        /// Query historical points for a single connection key.
        pub const METRIC_QUERY_BY_KEY: &str = "metric.query_by_key";
        /// Query connection history summary list.
        pub const METRIC_HISTORY_SUMMARIES: &str = "metric.history_summaries";
        /// Query aggregated source-IP connection history.
        pub const METRIC_HISTORY_SRC_IP: &str = "metric.history_src_ip";
        /// Query aggregated destination-IP connection history.
        pub const METRIC_HISTORY_DST_IP: &str = "metric.history_dst_ip";
        /// Query global traffic aggregates.
        pub const METRIC_GLOBAL_STATS: &str = "metric.global_stats";
        /// Query DNS history rows.
        pub const METRIC_DNS_HISTORY: &str = "metric.dns_history";
        /// Query DNS summary statistics.
        pub const METRIC_DNS_SUMMARY: &str = "metric.dns_summary";
        /// Query lightweight DNS summary statistics.
        pub const METRIC_DNS_LIGHTWEIGHT_SUMMARY: &str = "metric.dns_lightweight_summary";
    }
}

pub fn available_parallelism() -> usize {
    thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

pub fn short_thread_name(prefix: &str, key: impl AsRef<str>) -> String {
    let mut prefix = sanitize_token(prefix);
    if prefix.is_empty() {
        prefix = "ld".to_string();
    }

    if prefix.len() >= MAX_THREAD_NAME_LEN {
        prefix.truncate(MAX_THREAD_NAME_LEN);
        return prefix;
    }

    let key = sanitize_token(key.as_ref());
    if key.is_empty() {
        return prefix;
    }

    let direct = format!("{prefix}-{key}");
    if direct.len() <= MAX_THREAD_NAME_LEN {
        return direct;
    }

    let hash = short_hash(&key);
    let remaining = MAX_THREAD_NAME_LEN.saturating_sub(prefix.len() + 1 + hash.len());
    if remaining == 0 {
        return prefix;
    }

    let key_prefix = key.chars().take(remaining).collect::<String>();
    format!("{prefix}-{key_prefix}{hash}")
}

pub fn runtime_thread_name_fn(prefix: &'static str) -> impl Fn() -> String + Send + Sync + 'static {
    let seq = Arc::new(AtomicUsize::new(0));
    move || {
        let index = seq.fetch_add(1, Ordering::Relaxed);
        short_thread_name(prefix, format!("{index:02}"))
    }
}

pub fn spawn_named_thread<F, T>(name: impl Into<String>, f: F) -> io::Result<thread::JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new().name(name.into()).spawn(f)
}

pub fn spawn_thread_with_key<F, T>(
    prefix: &str,
    key: impl AsRef<str>,
    f: F,
) -> io::Result<thread::JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    spawn_named_thread(short_thread_name(prefix, key), f)
}

pub fn spawn_task<Fut>(label: &'static str, future: Fut) -> TokioJoinHandle<Fut::Output>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    tokio::spawn(future.instrument(tracing::info_span!("task", task = label)))
}

pub fn spawn_task_with_resource<Fut>(
    label: &'static str,
    resource: impl Display,
    future: Fut,
) -> TokioJoinHandle<Fut::Output>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    let resource = resource.to_string();
    tokio::spawn(future.instrument(tracing::info_span!("task", task = label, resource = %resource)))
}

fn sanitize_token(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev_dash = false;

    for ch in value.chars() {
        let mapped = match ch {
            'a'..='z' | '0'..='9' => Some(ch),
            'A'..='Z' => Some(ch.to_ascii_lowercase()),
            _ => Some('-'),
        };

        if let Some(mapped) = mapped {
            if mapped == '-' {
                if !prev_dash && !out.is_empty() {
                    out.push(mapped);
                }
                prev_dash = true;
            } else {
                out.push(mapped);
                prev_dash = false;
            }
        }
    }

    while out.ends_with('-') {
        out.pop();
    }

    out
}

fn short_hash(value: &str) -> String {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:02x}", hasher.finish() & 0xff)
}

#[cfg(test)]
mod tests {
    use super::{runtime_thread_name_fn, short_thread_name, thread_name, MAX_THREAD_NAME_LEN};

    #[test]
    fn thread_name_keeps_short_names() {
        assert_eq!(short_thread_name(thread_name::prefix::FIREWALL, "eth0"), "ld-fw-eth0");
    }

    #[test]
    fn thread_name_truncates_long_keys() {
        let name = short_thread_name(thread_name::prefix::FIREWALL, "very-long-interface-name");
        assert!(name.starts_with("ld-fw-"));
        assert!(name.len() <= MAX_THREAD_NAME_LEN);
    }

    #[test]
    fn runtime_thread_namer_is_stable_and_short() {
        let namer = runtime_thread_name_fn(thread_name::prefix::CORE_RUNTIME);
        let first = namer();
        let second = namer();
        assert_ne!(first, second);
        assert!(first.starts_with("ld-core-"));
        assert!(second.starts_with("ld-core-"));
        assert!(first.len() <= MAX_THREAD_NAME_LEN);
        assert!(second.len() <= MAX_THREAD_NAME_LEN);
    }
}
