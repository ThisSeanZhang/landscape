//! Explicit eBPF runtime: the single owner of a map space and its chain
//! managers.
//!
//! A daemon creates exactly one [`EbpfRuntime`] early at startup via
//! [`EbpfRuntime::init`]; tests create one per run pointing at an isolated
//! bpffs directory. Everything that used to read the process-global
//! `MAP_PATHS` static now receives [`LandscapeMapPath`] (plain map I/O) or
//! [`Arc<EbpfRuntime>`] (attach/chain code) as an explicit parameter instead.
//!
//! A runtime exclusively owns its map space: two live runtimes must never
//! share the same `space`, otherwise per-boot maps (delete + recreate) would
//! fight each other.

use std::sync::Arc;

use crate::LandscapeMapPath;
use crate::bpf_error::LdEbpfResult;
use crate::maps;
use crate::maps::wan_trie::dispatcher::WanTrieDispatcher;
use crate::metric::EbpfMetricSourceFactory;
use crate::route_backbone::RouteBackbone;
use crate::xdp_attach::XdpAttach;
use crate::{dns_result_sink::EbpfDnsResultSink, flow_socket_registrar::EbpfFlowSocketRegistrar};

/// bpffs root directory for `space`.
fn root_for_space(space: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/sys/fs/bpf/landscape/{}", space))
}

/// Build the pin-path layout for `space` and create/reuse every shared map
/// under it, without constructing the chain managers.
///
/// This is the entry point for callers that only touch plain maps
/// (`maps::*` functions taking a `&LandscapeMapPath`); attaching stages or
/// chains requires the full [`EbpfRuntime::init`].
pub fn init_map_paths(space: &str) -> LdEbpfResult<Arc<LandscapeMapPath>> {
    let root = root_for_space(space);
    tracing::info!("ebpf map space is: {space}");
    if !root.exists() {
        std::fs::create_dir_all(&root).map_err(|e| {
            crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("can not create bpf map path {}", root.display()),
                source: e.into(),
            }
        })?;
    }
    let paths = Arc::new(LandscapeMapPath::from_root(&root));
    tracing::info!("ebpf map paths is: {paths:#?}");
    maps::init_path(&paths);
    Ok(paths)
}

/// The running eBPF subsystem: shared map pin paths plus the TC/XDP chain
/// managers, all created eagerly by [`EbpfRuntime::init`].
#[derive(Clone)]
pub struct EbpfRuntime {
    pub(crate) paths: Arc<LandscapeMapPath>,
    /// Shared route dispatch substrate (trie, intro seed, exits, root
    /// prog-array shells) consumed by the LAN/WAN route services and
    /// every WAN link chain.
    pub(crate) backbone: Arc<RouteBackbone>,
    /// Per-iface XDP slot arbitration (native vs SKB fallback).
    pub(crate) xdp_attach: Arc<XdpAttach>,
    pub(crate) try_native_xdp: Option<Vec<i32>>,
}

impl EbpfRuntime {
    /// Create the map space, seed every shared map and build the TC/XDP
    /// chain managers (which load their exit skeletons).
    ///
    /// `try_native_xdp` mirrors the CLI `--try-xdp` flag: `None` disables
    /// native XDP attach, `Some([])` enables it on every interface and
    /// `Some([ifindex..])` restricts it to the listed interfaces.
    ///
    /// The returned runtime exclusively owns `space`.
    pub fn init(space: &str, try_native_xdp: Option<Vec<i32>>) -> LdEbpfResult<Self> {
        // The WAN dispatch tries live in BPF arenas: the interpreter cannot
        // run arena programs, so a disabled JIT makes every intro load fail
        // with EOPNOTSUPP. Warn loudly instead of failing mysteriously.
        if let Ok(v) = std::fs::read_to_string("/proc/sys/net/core/bpf_jit_enable")
            && v.trim() == "0"
        {
            tracing::error!(
                "net.core.bpf_jit_enable is 0: BPF arena programs (WAN dispatch trie) \
                 cannot load on this kernel; enable the JIT sysctl"
            );
        }
        let paths = init_map_paths(space)?;
        let wan_trie = Arc::new(WanTrieDispatcher::new());
        let backbone = Arc::new(RouteBackbone::new(paths.clone(), wan_trie)?);
        let xdp_attach = Arc::new(XdpAttach::new(paths.clone(), try_native_xdp.clone()));
        Ok(Self { paths, backbone, xdp_attach, try_native_xdp })
    }

    /// The shared route dispatch substrate.
    pub fn backbone(&self) -> &Arc<RouteBackbone> {
        &self.backbone
    }

    /// The per-iface XDP slot coordinator.
    pub fn xdp_attach(&self) -> &Arc<XdpAttach> {
        &self.xdp_attach
    }

    /// Shared map pin paths.
    pub fn paths(&self) -> &Arc<LandscapeMapPath> {
        &self.paths
    }

    /// Native XDP attach configuration this runtime was built with.
    pub fn try_native_xdp(&self) -> Option<&Vec<i32>> {
        self.try_native_xdp.as_ref()
    }

    /// eBPF-backed [`DnsResultSink`](landscape_common::flow::DnsResultSink)
    /// bound to this runtime's map space.
    pub fn dns_result_sink(&self) -> EbpfDnsResultSink {
        EbpfDnsResultSink::new(self.paths.clone())
    }

    /// eBPF-backed
    /// [`FlowSocketRegistrar`](landscape_common::flow::FlowSocketRegistrar)
    /// bound to this runtime's map space.
    pub fn flow_socket_registrar(&self) -> EbpfFlowSocketRegistrar {
        EbpfFlowSocketRegistrar::new(self.paths.clone())
    }

    /// eBPF-backed [`crate::metric::MetricSourceFactory`] bound to this
    /// runtime's map space.
    pub fn metric_source_factory(&self) -> EbpfMetricSourceFactory {
        EbpfMetricSourceFactory::new(self.paths.clone())
    }

    // ─────────────────────────────────────────────────────────────────
    // Capability factories (usage-domain traits from landscape-common).
    //
    // These take `self: Arc<Self>` and are called as `rt.clone().xxx()`
    // because the returned capability keeps the runtime alive for its
    // lifetime (guards detach chain state on drop).
    // ─────────────────────────────────────────────────────────────────

    /// Firewall capability (blacklist sync).
    pub fn firewall(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::wan_service::firewall::dataplane::FirewallDataplane> {
        Arc::new(crate::runtime_impls::EbpfFirewallDataplane::new(self))
    }

    /// NAT capability (static mapping sync).
    pub fn nat(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::wan_service::nat::dataplane::NatDataplane> {
        Arc::new(crate::runtime_impls::EbpfNatDataplane::new(self))
    }

    /// LAN route chain capability.
    pub fn lan_route(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::lan_service::lan_route::dataplane::LanRouteDataplane> {
        Arc::new(crate::runtime_impls::EbpfLanRouteDataplane::new(self))
    }

    /// WAN route chain capability.
    pub fn wan_route(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::wan_service::wan_route::dataplane::WanRouteDataplane> {
        Arc::new(crate::runtime_impls::EbpfWanRouteDataplane::new(self))
    }

    /// System route table sync capability.
    pub fn route_table(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::sys_service::route_service::dataplane::RouteTableDataplane> {
        Arc::new(crate::runtime_impls::EbpfRouteTableDataplane::new(self))
    }

    /// Flow rule sync capability.
    pub fn flow_rules(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::flow::dataplane::FlowRuleDataplane> {
        Arc::new(crate::runtime_impls::EbpfFlowRuleDataplane::new(self))
    }

    /// Neighbor MAC learning capability.
    pub fn mac_binding(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::lan_service::mac_binding::MacBindingDataplane> {
        Arc::new(crate::runtime_impls::EbpfMacBindingDataplane::new(self))
    }

    /// LAN IPv6 DAD-NS observer capability (standalone `tc_lan_dao` filter).
    pub fn ipv6_dao_filter(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::lan_service::lan_ipv6::dataplane::Ip6DaoFilterDataplane> {
        Arc::new(crate::runtime_impls::EbpfIp6DaoFilterDataplane::new(self))
    }

    /// Spawn the periodic ARP / IPv6-neighbour → `ip_mac_*` map sync
    /// task for this runtime's map space.  Cancelling the returned token
    /// stops the task.
    pub fn start_neigh_update(&self) -> tokio_util::sync::CancellationToken {
        use landscape_common::concurrency::{spawn_task, task_label};
        let cancel = tokio_util::sync::CancellationToken::new();
        let paths = self.paths.clone();
        let task_cancel = cancel.clone();
        spawn_task(task_label::task::EBPF_NEIGH_UPDATE, async move {
            if let Err(e) = crate::maps::mac::neigh_update(paths, task_cancel).await {
                tracing::warn!("eBPF neigh_update service exited with error: {e}");
            }
        });
        cancel
    }
}
