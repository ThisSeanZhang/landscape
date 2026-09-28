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
        /// Single SQLite metric writer thread.
        pub const METRIC_DB_WRITER: &str = "ld-mdb";
        /// eBPF neighbor update listener thread.
        pub const EBPF_NEIGH_UPDATE: &str = "ld-neigh";
    }

    pub mod prefix {
        /// Primary webserver/control-plane Tokio runtime threads.
        pub const CORE_RUNTIME: &str = "ld-core";
        /// Secondary Tokio runtime for gateway HTTPS accept/IO work.
        pub const GATEWAY_HTTPS_RUNTIME: &str = "ld-gwh";
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
        /// eBPF connect metric event source task that feeds userspace connect metric channels.
        pub const METRIC_EBPF_CONNECT_EVENT_SOURCE: &str = "metric.ebpf.connect.event.source";
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
        /// NAT service async launcher.
        pub const NAT_RUN: &str = "nat.service.run";
        /// NAT service stop-signal bridge task.
        pub const NAT_STOP: &str = "nat.service.stop";
        /// NAT observer task reacting to interface events.
        pub const NAT_OBSERVER: &str = "nat.service.observer";
        /// NAT observer task reacting to WAN route events.
        pub const NAT_WAN_ROUTE_OBSERVER: &str = "nat.service.wan_route_observer";
        /// EventHub dispatcher task that receives events and dispatches to domain broadcast channels.
        pub const EVENT_HUB_DISPATCHER: &str = "event.hub.dispatcher";
        /// eBPF neighbor update async task that periodically syncs ARP/NDP tables.
        pub const EBPF_NEIGH_UPDATE: &str = "ebpf.neigh_update";
        /// eBPF DAD NS learning ringbuf event source feeding the LAN IPv6 service.
        pub const EBPF_IP6_DAO_EVENT_SOURCE: &str = "ebpf.ip6_dao.event.source";
        /// Supervised DAD event dispatcher forwarding ringbuf events to per-iface servers.
        pub const EBPF_IP6_DAO_DISPATCHER: &str = "ebpf.ip6_dao.dispatcher";
        /// Periodic in-process memory snapshot sampler feeding the RAM ring buffer.
        pub const MEM_SAMPLE: &str = "mem.sample";

        // ── netlink 连接驱动与事件转发 ──────────────────────────────
        /// rtnetlink route connection driver.
        pub const NETLINK_CONN_DRIVER: &str = "netlink.conn.driver";
        /// nl80211 (WiFi) connection driver.
        pub const NETLINK_CONN_WIFI: &str = "netlink.conn.wifi";
        /// rtnetlink connection driver for the ethtool channel.
        pub const NETLINK_CONN_ETHTOOL: &str = "netlink.conn.ethtool";
        /// rtnetlink connection driver bound to observer multicast groups.
        pub const NETLINK_CONN_OBSERVER: &str = "netlink.conn.observer";
        /// Netlink observer task forwarding link/address events into the event hub.
        pub const EVENT_NETLINK_DISPATCH: &str = "event.netlink.dispatch";

        // ── 构造器内长驻事件监听 ────────────────────────────────────
        /// Firewall blacklist listener reacting to GeoIP update events.
        pub const FIREWALL_BLACKLIST_OBSERVER: &str = "firewall.blacklist.observer";
        /// Static NAT v4 mapping listener reacting to device events.
        pub const NAT_STATIC_V4_OBSERVER: &str = "nat.static_v4.observer";
        /// Static NAT v6 mapping listeners reacting to device/IPv6 events.
        pub const NAT_STATIC_V6_OBSERVER: &str = "nat.static_v6.observer";
        /// Flow rule listener reacting to DNS service events.
        pub const FLOW_RULE_OBSERVER: &str = "flow.rule.observer";
        /// Destination IP rule listener reacting to geo/DNS events.
        pub const FLOW_DST_IP_OBSERVER: &str = "flow.dst_ip.observer";
        /// IP route service listener reacting to rule store changes.
        pub const ROUTE_SERVICE_OBSERVER: &str = "route.service.observer";
        /// DNS resolver conf listener reacting to DNS config changes.
        pub const DNS_SERVICE_OBSERVER: &str = "dns.service.observer";
        /// 1s host status sampling loop (CPU/memory/temperature).
        pub const SYS_STATUS_SAMPLER: &str = "sys.status.sampler";
        /// DDNS background job scheduler.
        pub const DNS_DDNS_JOB: &str = "dns.ddns.job";
        /// ACME certificate order refresh/renewal background task.
        pub const CERT_ORDER_REFRESH: &str = "cert.order.refresh";
        /// GeoIP service listener reacting to rule/config update events.
        pub const GEO_IP_OBSERVER: &str = "geo.ip.observer";
        /// GeoSite service listener reacting to rule update events.
        pub const GEO_SITE_OBSERVER: &str = "geo.site.observer";
        /// WAN interface IP config listener reacting to iface events.
        pub const WAN_IPCONFIG_OBSERVER: &str = "wan.ipconfig.observer";
        /// DHCPv6 PD client service listener reacting to iface events.
        pub const WAN_IPV6PD_OBSERVER: &str = "wan.ipv6pd.observer";
        /// DHCPv6 PD client session receive loop.
        pub const WAN_IPV6PD_CLIENT_RENEW: &str = "wan.ipv6pd_client.rx";
        /// LAN hostname registry listener for device/DHCP events.
        pub const DNS_HOSTNAME_OBSERVER: &str = "dns.hostname.observer";
        /// ARP learning listener for address events.
        pub const ARP_LEARN: &str = "arp.learn";
        /// Periodic ARP scan task.
        pub const ARP_SCAN: &str = "arp.scan";

        // ── 每连接/每请求任务 ───────────────────────────────────────
        /// DNS UDP/TCP socket serve loop.
        pub const DNS_LISTENER_SERVE: &str = "dns.listener.serve";
        /// DNS-over-HTTPS socket serve loop.
        pub const DNS_DOH_HANDLER: &str = "dns.doh.handler";
        /// DHCPv4 server per-socket packet loop.
        pub const DHCP_V4_SERVER_HANDLER: &str = "dhcp.server.handler";
        /// DHCPv4 service listener reacting to iface/config events.
        pub const DHCP_V4_SERVICE_OBSERVER: &str = "dhcp.v4_service.observer";
        /// DHCPv6 server per-connection handler.
        pub const LAN_DHCP_V6_CONNECTION: &str = "lan.dhcpv6.connection";
        /// LAN IPv6 service listener reacting to iface/prefix events.
        pub const LAN_IPV6_SERVICE_OBSERVER: &str = "lan.ipv6.observer";
        /// MAC-link map listener reacting to neighbor events.
        pub const LAN_MAC_LINK_OBSERVER: &str = "lan.mac_link.observer";
        /// Docker unix-socket API event listener.
        pub const DOCKER_EVENT_UNIX: &str = "docker.event.unix";
        /// Docker engine event stream listener.
        pub const DOCKER_EVENT_LISTENER: &str = "docker.event.listen";
        /// Docker image pull/inspect background operation.
        pub const DOCKER_IMAGE_OP: &str = "docker.image.op";

        // ── metric 引擎内部 ─────────────────────────────────────────
        /// Metric connect aggregation worker.
        pub const METRIC_CONNECT_WORKER: &str = "metric.connect.worker";
        /// Metric DNS aggregation worker.
        pub const METRIC_DNS_WORKER: &str = "metric.dns.worker";
        /// Metric connect batch writer.
        pub const METRIC_CONNECT_WRITER: &str = "metric.connect.writer";
        /// Metric DNS batch writer.
        pub const METRIC_DNS_WRITER: &str = "metric.dns.writer";
        /// Daily connect global-stats drift correction rebuild.
        pub const METRIC_STATS_REBUILD: &str = "metric.stats.rebuild";
        /// Memory-mode sink realtime aggregation worker.
        pub const METRIC_MEM_SINK_WORKER: &str = "metric.mem_sink.worker";
        /// Memory minute-level persistence recorder.
        pub const METRIC_MEM_RECORDER: &str = "metric.mem.recorder";

        // ── 其它 ───────────────────────────────────────────────────
        /// PPPoE client session task.
        pub const PPPOE_CLIENT_RUN: &str = "pppoe.client.run";
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
    let name = name.into();
    // 专用线程按线程名归属记账(如 ld-fw-* → firewall),标签线程生命周期有效。
    let tag = crate::memtrack::subsystem_from_thread_name(&name);
    thread::Builder::new().name(name).spawn(move || crate::memtrack::tag::with_tag(tag, f))
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
    // 每次 poll 期间将当前线程归属到该任务标签对应的子系统,任务迁移到
    // 其他 worker 线程后仍正确归属。
    let tag = crate::memtrack::subsystem_from_task_label(label);
    tokio::spawn(
        crate::memtrack::TaggedFuture::new(tag, future)
            .instrument(tracing::info_span!("task", task = label)),
    )
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
    let tag = crate::memtrack::subsystem_from_task_label(label);
    tokio::spawn(
        crate::memtrack::TaggedFuture::new(tag, future)
            .instrument(tracing::info_span!("task", task = label, resource = %resource)),
    )
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
