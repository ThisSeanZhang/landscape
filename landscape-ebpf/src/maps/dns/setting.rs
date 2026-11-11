use std::io;

use landscape_common::flow::{DnsListenerRole, MAX_FLOW_ID};
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use crate::bpf_error::{LandscapeEbpfError, LdEbpfResult};
use crate::maps::LandscapeMapPath;

/// Pack a DNS listener role and flow id into the `dns_flow_socks` key.
///
/// The map key is:
///
/// ```text
/// bits 31..8: role (UDP/DoH/TCP)
/// bits  7..0: flow_id
/// ```
///
/// This mirrors the key construction in `sk_dns_dispatcher.bpf.c`.
pub fn dns_flow_key(flow_id: u32, role: DnsListenerRole) -> LdEbpfResult<u32> {
    if flow_id > MAX_FLOW_ID {
        return Err(LandscapeEbpfError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("DNS flow id {flow_id} exceeds supported maximum {MAX_FLOW_ID}"),
        )));
    }
    Ok(role.socket_key(flow_id))
}

fn setting_dns_sock_map_inner<T: MapCore>(
    dns_flow_socks: &T,
    sock_fd: i32,
    flow_id: u32,
    role: DnsListenerRole,
) -> LdEbpfResult<()> {
    let key = dns_flow_key(flow_id, role)?.to_le_bytes();
    let value = (sock_fd as u64).to_le_bytes();
    dns_flow_socks.update(&key, &value, MapFlags::ANY).map_err(|source| {
        LandscapeEbpfError::Context {
            context: format!("update dns_flow_socks for flow_id={flow_id} role={role:?}"),
            source,
        }
    })?;
    Ok(())
}

/// Register a DNS listener socket for one flow and listener role.
///
/// A missing map is an error rather than a silent no-op: leaving a listener
/// out of the reuseport map would let the kernel distribute traffic to the
/// wrong per-flow socket.
pub fn setting_dns_sock_map(
    paths: &LandscapeMapPath,
    sock_fd: i32,
    flow_id: u32,
    role: DnsListenerRole,
) -> LdEbpfResult<()> {
    let dns_flow_socks = MapHandle::from_pinned_path(&paths.dns_flow_socks).map_err(|source| {
        LandscapeEbpfError::Context {
            context: format!("open dns_flow_socks at {}", paths.dns_flow_socks.display()),
            source,
        }
    })?;

    setting_dns_sock_map_inner(&dns_flow_socks, sock_fd, flow_id, role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libbpf_rs::MapType;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    /// Creates an unnamed temporary SOCKMAP mirroring the `dns_flow_socks`
    /// layout (key u32, value u64, 1024 entries). Returns `None` (skip) when
    /// the environment cannot create BPF maps, e.g. no CAP_BPF.
    fn create_test_sockmap() -> Option<MapHandle> {
        #[allow(clippy::needless_update)]
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        match MapHandle::create(MapType::Sockmap, None::<String>, 4, 8, 1024, &opts) {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("skipping sockmap test: cannot create BPF sockmap: {e:?}");
                None
            }
        }
    }

    fn bound_udp_socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").expect("bind udp socket")
    }

    fn sockmap_value(map: &MapHandle, key: [u8; 4]) -> Option<u64> {
        map.lookup(&key, MapFlags::ANY)
            .expect("sockmap lookup")
            .map(|value| u64::from_le_bytes(value[..8].try_into().unwrap()))
    }

    #[test]
    fn dns_flow_key_packs_role_and_flow_id() {
        assert_eq!(dns_flow_key(5, DnsListenerRole::Udp).unwrap(), 5);
        assert_eq!(dns_flow_key(5, DnsListenerRole::Doh).unwrap(), 261);
        assert_eq!(dns_flow_key(5, DnsListenerRole::Tcp).unwrap(), 517);
        assert_eq!(dns_flow_key(255, DnsListenerRole::Udp).unwrap(), 255);
        assert_eq!(dns_flow_key(255, DnsListenerRole::Doh).unwrap(), 511);
        assert_eq!(dns_flow_key(255, DnsListenerRole::Tcp).unwrap(), 767);
    }

    #[test]
    fn dns_flow_key_rejects_out_of_range_flow_ids() {
        assert!(dns_flow_key(MAX_FLOW_ID + 1, DnsListenerRole::Udp).is_err());
    }

    /// Guards the kernel behavior the no-deregistration design relies on:
    /// a sockmap entry is removed automatically once its socket is closed
    /// (socket teardown unlinks it from the sockmap, via deferred RCU work),
    /// so closing the listener socket cleans up `dns_flow_socks` on its own.
    #[test]
    fn sockmap_entry_auto_removed_on_socket_close() {
        let Some(map) = create_test_sockmap() else { return };
        let sock = bound_udp_socket();
        let flow_id = 21;
        let role = DnsListenerRole::Udp;
        let key = dns_flow_key(flow_id, role).unwrap().to_le_bytes();

        setting_dns_sock_map_inner(&map, sock.as_raw_fd(), flow_id, role)
            .expect("register listener in test sockmap");
        // guard against a vacuous pass: the registration must have taken effect
        assert!(sockmap_value(&map, key).is_some());

        drop(sock); // close the only fd owning this socket

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match sockmap_value(&map, key) {
                None => break, // auto-removed by the kernel
                Some(_) if Instant::now() >= deadline => {
                    panic!("sockmap entry still present 5s after socket close")
                }
                Some(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
}
