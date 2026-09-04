use landscape_common::flow::FlowSocketRegistrar;

use crate::dns_dispatcher::attach_reuseport_ebpf;
use crate::map_setting::dns;

/// eBPF-backed [`FlowSocketRegistrar`]: writes the DNS socket into the
/// flow->socket sockmap and attaches the reuseport dispatcher.
pub struct EbpfFlowSocketRegistrar;

impl FlowSocketRegistrar for EbpfFlowSocketRegistrar {
    fn register_dns_socket(&self, flow_id: u32, sock_fd: i32, is_tcp: bool) {
        if is_tcp {
            dns::setting_dns_sock_map_tcp(sock_fd, flow_id);
        } else {
            dns::setting_dns_sock_map(sock_fd, flow_id);
        }
        if let Err(e) = attach_reuseport_ebpf(sock_fd) {
            tracing::error!("[flow: {flow_id}]: attach reuseport eBPF error: {e:?}");
        }
    }
}
