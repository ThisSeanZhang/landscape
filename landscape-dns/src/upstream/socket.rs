use std::io;
use std::os::fd::RawFd;

/// Sets the SO_MARK option on a socket (the flow's routing identity).
pub(crate) fn set_socket_mark(fd: RawFd, mark_value: u32) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark_value as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };

    if result == -1 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

/// Enforce the selected WAN even when the OS default route points elsewhere.
/// A missing family is an error, never an unbound fallback through another WAN.
pub(crate) fn bind_wan_device(
    fd: RawFd,
    server: std::net::SocketAddr,
    config: &landscape_common::dns::bind::DnsBindConfig,
) -> io::Result<()> {
    if config.follow_flow.is_none() {
        return Ok(());
    }
    let iface = config.interface(server.is_ipv6()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "DNS flow has no selected WAN for this address family",
        )
    })?;
    let iface = std::ffi::CString::new(iface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid WAN device"))?;
    // SAFETY: fd belongs to a live socket, and CString includes the required NUL.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface.as_ptr().cast(),
            iface.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
