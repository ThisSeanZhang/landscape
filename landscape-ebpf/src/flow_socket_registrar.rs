use std::sync::Arc;

use landscape_common::flow::{
    DnsListenerRole, DnsSocketRegisterError, FlowSocketRegistrar, MAX_FLOW_ID,
};

use crate::dns_dispatcher::attach_reuseport_ebpf;
use crate::maps::{LandscapeMapPath, dns};

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
    fn register_dns_socket(
        &self,
        flow_id: u32,
        sock_fd: i32,
        role: DnsListenerRole,
    ) -> Result<(), DnsSocketRegisterError> {
        if flow_id > MAX_FLOW_ID {
            return Err(DnsSocketRegisterError::InvalidFlowId { flow_id, max: MAX_FLOW_ID });
        }

        dns::setting_dns_sock_map(&self.paths, sock_fd, flow_id, role)
            .map_err(|e| DnsSocketRegisterError::MapUpdate(e.to_string()))?;

        // Every listener of a role shares one reuseport group, and the kernel
        // accepts only a single dispatcher program per group. Attaching a
        // freshly loaded program to a later socket therefore fails with
        // EINVAL. The already-attached dispatcher serves the whole group
        // through the sockmap, so keep the listener running instead of
        // failing the flow.
        if let Err(e) = attach_reuseport_ebpf(&self.paths, sock_fd, role) {
            tracing::error!("[flow: {flow_id}]: attach reuseport eBPF error: {e:?}");
        }

        Ok(())
    }
}
