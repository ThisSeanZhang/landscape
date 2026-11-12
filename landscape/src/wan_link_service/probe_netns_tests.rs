//! Privileged tests use disposable network namespaces and local responders.
//! Only WAN2 initially has a main default. Removing it must not break WAN1.
use super::application_probe::probe_target;
use landscape_common::{
    sys_service::route_service::{RouteTargetInfo, WanRouteTarget},
    wan_link::WanProbeTarget,
};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(out.status.success(), "ip {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}
struct Peer {
    name: String,
    server: Option<Child>,
}
impl Peer {
    fn start(&mut self) {
        use std::io::{BufRead, BufReader};
        let mut child = Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.name,
                "python3",
                "-u",
                "-c",
                include_str!("probe_test_server.py"),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready).unwrap();
        assert_eq!(ready.trim(), "ready");
        self.server = Some(child);
    }
    fn stop(&mut self) {
        if let Some(mut child) = self.server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop();
        let _ = Command::new("ip").args(["netns", "del", &self.name]).status();
    }
}

#[test]
#[ignore = "requires root, iproute2 and isolated network namespaces"]
fn health_probes_are_confined_and_recover_in_both_families() {
    // SAFETY: this dedicated test thread and all subsequently created runtime
    // threads/children inherit a new namespace; host routes are never modified.
    assert_eq!(
        unsafe { libc::unshare(libc::CLONE_NEWNET) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    ip(&["link", "set", "lo", "up"]);
    std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0\n").unwrap();
    let mut peers = Vec::new();
    for n in 1..=2 {
        let name = format!("fo-probe-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        ip(&["netns", "add", &name]);
        let mut peer = Peer { name, server: None };
        let dev = format!("w{n}");
        let remote = format!("p{n}");
        ip(&["link", "add", &dev, "type", "veth", "peer", "name", &remote]);
        ip(&["link", "set", &remote, "netns", &peer.name]);
        ip(&["link", "set", &dev, "up"]);
        // Native PPP interfaces can inherit loose RPF from the distribution.
        std::fs::write(format!("/proc/sys/net/ipv4/conf/{dev}/rp_filter"), "2\n").unwrap();
        ip(&["addr", "add", &format!("198.18.{n}.1/30"), "dev", &dev]);
        ip(&["-6", "addr", "add", &format!("fd00:{n}::1/64"), "dev", &dev, "nodad"]);
        for args in [vec!["link", "set", "lo", "up"], vec!["link", "set", &remote, "up"]] {
            let mut command = vec!["-n", &peer.name];
            command.extend(args);
            ip(&command);
        }
        ip(&["-n", &peer.name, "addr", "add", &format!("198.18.{n}.2/30"), "dev", &remote]);
        ip(&[
            "-n",
            &peer.name,
            "-6",
            "addr",
            "add",
            &format!("fd00:{n}::2/64"),
            "dev",
            &remote,
            "nodad",
        ]);
        ip(&["-n", &peer.name, "-6", "addr", "add", "fe80::53/64", "dev", &remote, "nodad"]);
        ip(&["-n", &peer.name, "addr", "add", "198.19.0.53/32", "dev", "lo"]);
        ip(&["-n", &peer.name, "-6", "addr", "add", "fd53::53/128", "dev", "lo", "nodad"]);
        // Reproduce a secondary native PPPoE WAN with no kernel default.
        if n == 2 {
            ip(&["route", "add", "default", "via", "198.18.2.2", "dev", &dev]);
            ip(&["-6", "route", "add", "default", "via", "fd00:2::2", "dev", &dev]);
        }
        peer.start();
        peers.push(peer);
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let mut bindings = Vec::new();
    for n in 1..=2 {
        let dev = format!("w{n}");
        for info in [
            RouteTargetInfo::new_gateway_v4(
                0,
                &dev,
                None,
                format!("198.18.{n}.1").parse().unwrap(),
                format!("198.18.{n}.2").parse().unwrap(),
                false,
            ),
            RouteTargetInfo::new_gateway_v6(
                0,
                &dev,
                None,
                format!("fd00:{n}::1").parse().unwrap(),
                format!("fd00:{n}::2").parse().unwrap(),
                false,
            ),
        ] {
            bindings.push(WanRouteTarget::link(n, info));
        }
    }
    rt.block_on(landscape_ebpf::maps::route::sync_bound_wan_routes(&bindings)).unwrap();
    let check = |n: u32, ipv6: bool, application_healthy: bool| {
        rt.block_on(async {
            let src = if ipv6 { format!("fd00:{n}::1") } else { format!("198.18.{n}.1") }
                .parse()
                .unwrap();
            let server = if ipv6 { "fd53::53" } else { "198.19.0.53" }.parse().unwrap();
            let targets = [
                WanProbeTarget::Icmp { address: server },
                WanProbeTarget::Dns { server, domain: "probe.test".into() },
                WanProbeTarget::Http {
                    dns_server: server,
                    url: "http://probe.test:18080/".into(),
                },
            ];
            for (i, target) in targets.iter().enumerate() {
                let result = probe_target(
                    &format!("w{n}"),
                    src,
                    target,
                    Duration::from_secs(2),
                    0x0200_0000 | n,
                )
                .await
                .unwrap();
                assert_eq!(
                    result.is_some(),
                    i == 0 || application_healthy,
                    "WAN{n}, ipv6={ipv6}, {target:?}"
                );
            }
        });
    };
    for ipv6 in [false, true] {
        check(1, ipv6, true);
        check(2, ipv6, true);
    }
    // The primary disconnect removes the only main default. A secondary WAN
    // with its own policy table must still receive ICMP/DNS/HTTP replies.
    ip(&["route", "del", "default"]);
    ip(&["-6", "route", "del", "default"]);
    for ipv6 in [false, true] {
        check(1, ipv6, true);
        check(2, ipv6, true);
    }
    // Recreating/reconfiguring a PPP interface can restore the inherited RPF.
    // The reconcile loop must repair it again without requiring a restart.
    std::fs::write("/proc/sys/net/ipv4/conf/w1/rp_filter", "2\n").unwrap();
    let dropped = rt
        .block_on(probe_target(
            "w1",
            "198.18.1.1".parse().unwrap(),
            &WanProbeTarget::Dns {
                server: "198.19.0.53".parse().unwrap(),
                domain: "probe.test".into(),
            },
            Duration::from_millis(250),
            0x0200_0001,
        ))
        .unwrap();
    assert!(dropped.is_none(), "loose RPF should reproduce the dropped reply");
    rt.block_on(landscape_ebpf::maps::route::sync_bound_wan_routes(&bindings)).unwrap();
    check(1, false, true);
    // Both WAN peers use the same link-local address. The scope must select
    // the intended interface rather than relying on the default route.
    for n in 1..=2 {
        let result = rt
            .block_on(probe_target(
                &format!("w{n}"),
                format!("fd00:{n}::1").parse().unwrap(),
                &WanProbeTarget::Icmp { address: "fe80::53".parse().unwrap() },
                Duration::from_secs(2),
                0x0200_0000 | n,
            ))
            .unwrap();
        assert!(result.is_some(), "link-local WAN{n} probe failed");
    }
    // Carrier and ICMP stay healthy; only WAN1's application responders stop.
    peers[0].stop();
    for ipv6 in [false, true] {
        check(1, ipv6, false);
        check(2, ipv6, true);
    }
    peers[0].start();
    for ipv6 in [false, true] {
        check(1, ipv6, true);
    }
}
