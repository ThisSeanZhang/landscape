use crate::flow::error::DnsSocketRegisterError;

/// Logical DNS listener role packed into the high byte of the DNS sockmap key.
///
/// UDP, DoH and plain DNS/TCP can all exist for one flow. The role keeps
/// their socket-map entries in separate key spaces even though all three
/// listeners are registered in the same `dns_flow_socks` map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum DnsListenerRole {
    Udp = 0,
    Doh = 1,
    Tcp = 2,
    /// Reserved sentinel mirroring `DNS_LISTENER_ROLE_INVALID` in the eBPF
    /// dispatcher. Never a real listener role; the eBPF program drops any
    /// query whose role is not one of `Udp`/`Doh`/`Tcp`.
    Invalid = 3,
}

impl DnsListenerRole {
    /// Highest value that maps to a real listener role.
    pub const MAX_VALID: u32 = Self::Tcp as u32;

    /// Number of bits reserved for `flow_id` in the packed socket-map key.
    pub const KEY_FLOW_BITS: u32 = 8;

    /// Pack this role and `flow_id` into the key consumed by the eBPF
    /// dispatcher. Must stay in sync with `DNS_FLOW_KEY_ROLE_SHIFT` and
    /// `DNS_LISTENER_ROLE_*` in
    /// `landscape-ebpf/src/bpf/dns/dns_dispatcher.h`.
    pub const fn socket_key(self, flow_id: u32) -> u32 {
        ((self as u32) << Self::KEY_FLOW_BITS) | flow_id
    }
}

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
    /// Bind a DNS listen socket to `flow_id` and `role`.
    ///
    /// Returns an error when the socket cannot be inserted into the datapath
    /// map. Reuseport dispatcher attach failures are logged by the
    /// implementation and are not fatal: listeners of a role share one
    /// reuseport group, and the already-attached dispatcher serves them
    /// through the sockmap. The caller must close the listener socket on
    /// error.
    fn register_dns_socket(
        &self,
        flow_id: u32,
        sock_fd: i32,
        role: DnsListenerRole,
    ) -> Result<(), DnsSocketRegisterError>;
}

/// No-op registrar used by tests and non-Linux builds.
pub struct NoopFlowSocketRegistrar;

impl FlowSocketRegistrar for NoopFlowSocketRegistrar {
    fn register_dns_socket(
        &self,
        _flow_id: u32,
        _sock_fd: i32,
        _role: DnsListenerRole,
    ) -> Result<(), DnsSocketRegisterError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::config::MAX_FLOW_ID;

    #[test]
    fn listener_roles_have_disjoint_key_ranges() {
        assert_eq!(DnsListenerRole::Udp.socket_key(MAX_FLOW_ID), MAX_FLOW_ID);
        assert_eq!(DnsListenerRole::Doh.socket_key(MAX_FLOW_ID), 511);
        assert_eq!(DnsListenerRole::Tcp.socket_key(MAX_FLOW_ID), 767);
        assert_eq!(DnsListenerRole::Udp.socket_key(5), 5);
        assert_eq!(DnsListenerRole::Doh.socket_key(5), 261);
        assert_eq!(DnsListenerRole::Tcp.socket_key(5), 517);
    }
}
