/// Associates a DNS listener socket with a flow so the datapath can steer and
/// load-balance the incoming DNS queries for that flow.
///
/// Invoked during flow lifecycle (start/stop), not per query. The concrete
/// implementation decides how to register the socket: today that's the eBPF
/// DNS sockmap plus reuseport dispatch, another backend can replace it.
///
/// There is intentionally no deregister method: the datapath keeps these
/// sockets in a sockmap, and the kernel removes a sockmap entry automatically
/// once its socket is closed. Closing the listener socket is therefore the
/// deregistration, and re-registering a flow simply overwrites the previous
/// entry. An explicit delete would only add races with concurrent
/// re-registration under the same key.
pub trait FlowSocketRegistrar: Send + Sync {
    /// Bind a DNS listen socket to `flow_id`.
    fn register_dns_socket(&self, flow_id: u32, sock_fd: i32, is_tcp: bool);
}

/// No-op registrar used by tests and non-Linux builds.
pub struct NoopFlowSocketRegistrar;

impl FlowSocketRegistrar for NoopFlowSocketRegistrar {
    fn register_dns_socket(&self, _flow_id: u32, _sock_fd: i32, _is_tcp: bool) {}
}
