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
