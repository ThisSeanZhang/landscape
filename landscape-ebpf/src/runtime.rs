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

use crate::bpf_error::LdEbpfResult;
use crate::chain::tc_manager::TcChainManager;
use crate::chain::xdp_manager::XdpChainManager;
use crate::maps;
use crate::metric::EbpfMetricSourceFactory;
use crate::LandscapeMapPath;
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
    pub(crate) tc: Arc<TcChainManager>,
    pub(crate) xdp: Arc<XdpChainManager>,
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
        let paths = init_map_paths(space)?;
        let tc = Arc::new(TcChainManager::new(paths.clone())?);
        let xdp = Arc::new(XdpChainManager::new(paths.clone())?);
        Ok(Self { paths, tc, xdp, try_native_xdp })
    }

    /// Shared map pin paths.
    pub fn paths(&self) -> &Arc<LandscapeMapPath> {
        &self.paths
    }

    /// TC chain manager.
    pub fn tc(&self) -> &TcChainManager {
        &self.tc
    }

    /// XDP chain manager.
    pub fn xdp(&self) -> &XdpChainManager {
        &self.xdp
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

    /// PPPoE session capability (attach/teardown + WAN IPv4 binding).
    pub fn pppoe_dataplane(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::wan_service::pppoe::PppoeDataplane> {
        Arc::new(crate::runtime_impls::EbpfPppoeDataplane::new(self))
    }

    /// WAN address binding capability (`wan_ip_binding` map).
    pub fn wan_addr_binding(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::wan_service::addr_binding::WanAddrBinding> {
        Arc::new(crate::runtime_impls::EbpfWanAddrBinding::new(self))
    }

    /// Firewall capability (stage attach + blacklist sync).
    pub fn firewall(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::wan_service::firewall::dataplane::FirewallDataplane> {
        Arc::new(crate::runtime_impls::EbpfFirewallDataplane::new(self))
    }

    /// NAT capability (stage attach + static mapping sync).
    pub fn nat(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::wan_service::nat::dataplane::NatDataplane> {
        Arc::new(crate::runtime_impls::EbpfNatDataplane::new(self))
    }

    /// MSS clamp capability (stage attach).
    pub fn mss_clamp(
        self: Arc<Self>,
    ) -> Arc<dyn landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane> {
        Arc::new(crate::runtime_impls::EbpfMssClampDataplane::new(self))
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
