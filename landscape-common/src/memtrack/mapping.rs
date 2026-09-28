//! 归属映射:任务标签/线程名 → 子系统槽位 ID。
//!
//! 任务标签取第一个 `.` 前的段(如 `firewall.service.run` → `firewall`);
//! 线程名按 `landscape_common::concurrency::thread_name` 的 `ld-*` 规范匹配。
//! 未知值回落到 `unattributed`。

use super::registry::{SUBSYSTEMS, UNATTRIBUTED};

fn index_of(name: &str) -> usize {
    SUBSYSTEMS.iter().position(|s| *s == name).unwrap_or(UNATTRIBUTED)
}

/// task label 前缀 → 子系统。覆盖 `concurrency::task_label` 的现有标签,
/// 以及后续迁移裸 `tokio::spawn` 时会引入的前缀(dhcp/geo/dns/arp/...)。
pub fn subsystem_from_task_label(label: &str) -> usize {
    let head = label.split('.').next().unwrap_or("");
    let mapped = match head {
        "firewall" => "firewall",
        "nat" => "nat",
        "route" => "route",
        "metric" | "mem" => "metric",
        "gateway" => "gateway",
        "wifi" => "wifi",
        "mss_clamp" => "wan",
        "pppd" => "pppd",
        "pppoe" => "pppoe",
        "ebpf" => "ebpf",
        "event" => "event",
        "web" | "ws" => "webserver",
        "service" => "service",
        "time" => "time",
        "dns" => "dns",
        "cert" => "cert",
        "dhcp" => "lan",
        "lan" => "lan",
        "wan" => "wan",
        "geo" => "geo",
        "docker" => "docker",
        "dump" => "dump",
        "netlink" => "netlink",
        "flow" => "flow",
        "arp" => "arp",
        "sys" => "sys",
        _ => return UNATTRIBUTED,
    };
    index_of(mapped)
}

/// 线程名 → 子系统。`ld-core-*`(主 runtime 共享 worker)保持 unattributed:
/// 其上运行大量未打标任务,归属到任何单一子系统都会失真。
pub fn subsystem_from_thread_name(name: &str) -> usize {
    let mapped = if name.starts_with("ld-gw") {
        "gateway"
    } else if name.starts_with("ld-fw") {
        "firewall"
    } else if name.starts_with("ld-nat") {
        "nat"
    } else if name.starts_with("ld-rw") || name.starts_with("ld-mss") {
        "wan"
    } else if name.starts_with("ld-rl") {
        "lan"
    } else if name.starts_with("ld-wifi") {
        "wifi"
    } else if name.starts_with("ld-pty") {
        "pty"
    } else if name.starts_with("ld-dmp") {
        "dump"
    } else if name.starts_with("ld-mdb") {
        "metric"
    } else if name.starts_with("ld-neigh") {
        "ebpf"
    } else if name.starts_with("ld-time") {
        "time"
    } else {
        return UNATTRIBUTED;
    };
    index_of(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memtrack::registry::subsystem_label;

    #[test]
    fn task_labels_map_to_subsystems() {
        assert_eq!(subsystem_label(subsystem_from_task_label("firewall.service.run")), "firewall");
        assert_eq!(
            subsystem_label(subsystem_from_task_label("metric.ebpf.connect.event.source")),
            "metric"
        );
        assert_eq!(
            subsystem_label(subsystem_from_task_label("gateway.sni.client_to_upstream")),
            "gateway"
        );
        assert_eq!(subsystem_label(subsystem_from_task_label("mss_clamp.observer")), "wan");
        assert_eq!(subsystem_label(subsystem_from_task_label("pppd.service.run")), "pppd");
        assert_eq!(subsystem_label(subsystem_from_task_label("pppoe.client.run")), "pppoe");
        assert_eq!(subsystem_label(subsystem_from_task_label("service.manager.spawn")), "service");
        assert_eq!(subsystem_label(subsystem_from_task_label("mem.sample")), "metric");
        assert_eq!(subsystem_label(subsystem_from_task_label("netlink.conn.driver")), "netlink");
        assert_eq!(subsystem_label(subsystem_from_task_label("flow.rule.observer")), "flow");
        assert_eq!(subsystem_label(subsystem_from_task_label("arp.scan")), "arp");
        assert_eq!(subsystem_label(subsystem_from_task_label("sys.status.sampler")), "sys");
        assert_eq!(subsystem_label(subsystem_from_task_label("cert.order.refresh")), "cert");
        assert_eq!(subsystem_label(subsystem_from_task_label("unknown.label")), "unattributed");
        assert_eq!(subsystem_label(subsystem_from_task_label("")), "unattributed");
    }

    #[test]
    fn thread_names_map_to_subsystems() {
        assert_eq!(subsystem_label(subsystem_from_thread_name("ld-gw-main")), "gateway");
        assert_eq!(subsystem_label(subsystem_from_thread_name("ld-gwh-drv")), "gateway");
        assert_eq!(subsystem_label(subsystem_from_thread_name("ld-fw-eth0")), "firewall");
        assert_eq!(subsystem_label(subsystem_from_thread_name("ld-nat-eth0")), "nat");
        assert_eq!(subsystem_label(subsystem_from_thread_name("ld-rw-01")), "wan");
        assert_eq!(subsystem_label(subsystem_from_thread_name("ld-rl-01")), "lan");
        assert_eq!(subsystem_label(subsystem_from_thread_name("ld-mdb")), "metric");
        assert_eq!(subsystem_label(subsystem_from_thread_name("ld-ptyr-3")), "pty");
        assert_eq!(subsystem_label(subsystem_from_thread_name("ld-core-03")), "unattributed");
        assert_eq!(subsystem_label(subsystem_from_thread_name("main")), "unattributed");
    }
}
