use std::sync::Arc;

use landscape_common::flow::FlowSocketRegistrar;

use crate::dns_dispatcher::attach_reuseport_ebpf;
use crate::maps::{dns, LandscapeMapPath};

/// eBPF-backed [`FlowSocketRegistrar`]: writes the DNS socket into the
/// flow->socket sockmap and attaches the reuseport dispatcher.
pub struct EbpfFlowSocketRegistrar {
    paths: Arc<LandscapeMapPath>,
}

impl EbpfFlowSocketRegistrar {
    pub fn new(paths: Arc<LandscapeMapPath>) -> Self {
        Self { paths }
    }
}

impl FlowSocketRegistrar for EbpfFlowSocketRegistrar {
    fn register_dns_socket(&self, flow_id: u32, sock_fd: i32, is_tcp: bool) {
        if is_tcp {
            dns::setting_dns_sock_map_tcp(&self.paths, sock_fd, flow_id);
        } else {
            dns::setting_dns_sock_map(&self.paths, sock_fd, flow_id);
        }
        if let Err(e) = attach_reuseport_ebpf(&self.paths, sock_fd) {
            tracing::error!("[flow: {flow_id}]: attach reuseport eBPF error: {e:?}");
        }
    }
}
