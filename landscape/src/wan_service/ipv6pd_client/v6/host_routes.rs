use std::{collections::HashMap, net::Ipv6Addr, time::Duration};

use landscape_common::{
    net::MacAddr,
    sys_service::route_service::{LanIPv6RouteKey, LanRouteInfo, LanRouteMode},
};
use tokio::time::Instant;

use crate::{
    netlink::ipv6::{del_iface_ip, set_iface_ip},
    sys_service::route::IpRouteService,
};

/// `/128` entries owned by this PD client, including deprecated addresses still
/// valid on the interface. One deadline per address: reacquiring A after A→B
/// replaces A's grace deadline rather than leaving a timer that can delete A.
pub(super) struct WanHostRoutes<'a> {
    routes: &'a IpRouteService,
    iface: &'a str,
    ifindex: u32,
    mac: Option<MacAddr>,
    valid_until: HashMap<Ipv6Addr, Instant>,
}

fn key(iface: &str, addr: Ipv6Addr) -> LanIPv6RouteKey {
    LanIPv6RouteKey {
        iface_name: iface.to_owned(),
        subnet: addr,
        prefix_len: 128,
    }
}

impl<'a> WanHostRoutes<'a> {
    pub(super) fn new(
        routes: &'a IpRouteService,
        iface: &'a str,
        ifindex: u32,
        mac: Option<MacAddr>,
    ) -> Self {
        Self {
            routes,
            iface,
            ifindex,
            mac,
            valid_until: HashMap::new(),
        }
    }

    pub(super) async fn install(&mut self, addr: Ipv6Addr, valid: u32, preferred: u32) {
        if valid != 0 && set_iface_ip(addr, 128, self.iface, Some(valid), Some(preferred)) {
            self.publish(addr, Instant::now() + Duration::from_secs(valid.into())).await;
        }
    }

    async fn publish(&mut self, addr: Ipv6Addr, until: Instant) {
        self.valid_until.insert(addr, until);
        self.routes
            .insert_ipv6_lan_route(
                key(self.iface, addr),
                LanRouteInfo {
                    ifindex: self.ifindex,
                    iface_name: self.iface.to_owned(),
                    iface_ip: addr.into(),
                    mac: self.mac,
                    prefix: 128,
                    mode: LanRouteMode::WanReachable,
                },
            )
            .await;
    }

    pub(super) fn deprecate_until(&mut self, addr: Ipv6Addr, until: Instant) {
        if let Some(deadline) = self.valid_until.get_mut(&addr) {
            *deadline = until;
        }
    }

    pub(super) async fn wait_for_expiry(&self) {
        match self.valid_until.values().min() {
            Some(&at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
    }

    pub(super) async fn expire(&mut self, now: Instant) {
        for (addr, _) in self.valid_until.extract_if(|_, until| *until <= now) {
            self.routes.remove_ipv6_lan_route_by_key(&key(self.iface, addr)).await;
        }
    }

    pub(super) async fn remove(&mut self, addr: Ipv6Addr) {
        if self.valid_until.remove(&addr).is_some() {
            self.routes.remove_ipv6_lan_route_by_key(&key(self.iface, addr)).await;
        }
    }

    /// On explicit teardown there will be no client left to service grace timers.
    pub(super) async fn clear_on_stop(&mut self) {
        for (addr, _) in self.valid_until.drain() {
            del_iface_ip(addr, 128, self.iface);
            self.routes.remove_ipv6_lan_route_by_key(&key(self.iface, addr)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::sys_service::route_service::dataplane::NoopRouteTableDataplane;
    use std::{sync::Arc, time::Duration};

    #[tokio::test]
    async fn grace_expiry_keeps_reacquired_host_and_covering_lan_route() {
        let routes = IpRouteService::new(Arc::new(NoopRouteTableDataplane));
        let iface = "wan0";
        let a: Ipv6Addr = "2001:db8:1::42".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:2::42".parse().unwrap();
        let lan_key = LanIPv6RouteKey {
            iface_name: "lan0".into(),
            subnet: "2001:db8:1::".parse().unwrap(),
            prefix_len: 64,
        };
        routes
            .insert_ipv6_lan_route(
                lan_key.clone(),
                LanRouteInfo {
                    iface_name: "lan0".into(),
                    ifindex: 8,
                    iface_ip: "2001:db8:1::1".parse().unwrap(),
                    prefix: 64,
                    mac: None,
                    mode: LanRouteMode::Reachable,
                },
            )
            .await;
        let mut hosts = WanHostRoutes::new(&routes, iface, 7, None);
        let now = Instant::now();
        let grace = now + Duration::from_secs(10);
        let end = now + Duration::from_secs(60);
        hosts.publish(a, end).await;
        hosts.publish(b, end).await;
        hosts.deprecate_until(a, grace);
        hosts.expire(grace - Duration::from_secs(1)).await;
        let entries = routes.get_all_ipv6_lan_routes().await;
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[&key(iface, a)],
            LanRouteInfo {
                iface_name: iface.into(),
                ifindex: 7,
                iface_ip: a.into(),
                prefix: 128,
                mac: None,
                mode: LanRouteMode::WanReachable,
            }
        );

        // A → B → A before A's grace expires: the old deadline must not remove A.
        hosts.publish(a, end).await;
        hosts.deprecate_until(b, grace);
        hosts.expire(grace).await;
        let entries = routes.get_all_ipv6_lan_routes().await;
        assert!(entries.contains_key(&key(iface, a)));
        assert!(!entries.contains_key(&key(iface, b)));
        hosts.remove(a).await;
        let entries = routes.get_all_ipv6_lan_routes().await;
        assert_eq!(entries.len(), 1);
        assert!(entries.contains_key(&lan_key));
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires CAP_NET_ADMIN, BPF and a private bpffs"]
    async fn installed_pd_hosts_reach_rt6_lan_map_and_retire_individually() {
        use landscape_ebpf::runtime::EbpfRuntime;
        use libbpf_rs::{MapCore, MapFlags, MapHandle};
        use std::process::Command;

        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNET) },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        assert!(Command::new("ip").args(["link", "set", "lo", "up"]).status().unwrap().success());
        let parent = "/sys/fs/bpf/landscape";
        std::fs::create_dir_all(parent).unwrap();
        let space = tempfile::Builder::new().prefix("pd-host-").tempdir_in(parent).unwrap();
        let rt = Arc::new(
            EbpfRuntime::init(space.path().file_name().unwrap().to_str().unwrap(), None).unwrap(),
        );
        let map = MapHandle::from_pinned_path(&rt.paths().rt6_lan_map).unwrap();
        let routes = IpRouteService::new(rt.route_table());
        let mut hosts = WanHostRoutes::new(&routes, "lo", 1, None);
        let a: Ipv6Addr = "2001:db8:1::42".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:2::42".parse().unwrap();
        let lookup = |ip: Ipv6Addr| {
            let mut k = 128u32.to_ne_bytes().to_vec();
            k.extend(ip.octets());
            map.lookup(&k, MapFlags::ANY).unwrap().is_some()
        };
        hosts.install(a, 60, 30).await;
        hosts.install(b, 60, 30).await;
        assert!(lookup(a) && lookup(b));
        assert!(!lookup("2001:db8:1::43".parse().unwrap()));
        super::super::deprecate_previous_pd_address(
            &mut hosts,
            Some(a),
            Some(b),
            Duration::from_secs(1),
            "lo",
        );
        assert!(lookup(a));
        tokio::time::timeout(Duration::from_secs(5), hosts.wait_for_expiry()).await.unwrap();
        hosts.expire(Instant::now()).await;
        assert!(!lookup(a) && lookup(b));

        // Two PD links with the same delegated prefix and IID share one LPM key.
        assert!(
            Command::new("ip")
                .args(["link", "add", "wan-b", "type", "dummy"])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("ip").args(["link", "set", "wan-b", "up"]).status().unwrap().success()
        );
        let ifindex = unsafe { libc::if_nametoindex(c"wan-b".as_ptr()) };
        assert_ne!(ifindex, 0);
        let mut other = WanHostRoutes::new(&routes, "wan-b", ifindex, None);
        other.install(b, 60, 30).await;
        assert_eq!(routes.get_all_ipv6_lan_routes().await.len(), 2);
        other.clear_on_stop().await;
        assert!(lookup(b));
        hosts.clear_on_stop().await;
        assert!(!lookup(b));
    }

    #[tokio::test]
    async fn unsuccessful_address_install_does_not_publish_a_host_route() {
        let routes = IpRouteService::new(Arc::new(NoopRouteTableDataplane));
        // Longer than IFNAMSIZ; cannot accidentally configure a real interface.
        let mut hosts = WanHostRoutes::new(&routes, "no-such-pd-test-interface", 7, None);
        hosts.install("2001:db8::42".parse().unwrap(), 60, 30).await;
        assert!(routes.get_all_ipv6_lan_routes().await.is_empty());
    }
}
