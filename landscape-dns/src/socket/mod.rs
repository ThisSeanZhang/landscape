use std::net::SocketAddr;

#[derive(Debug)]
pub struct RecvDnsMessage {
    pub message: Vec<u8>,
    pub addr: SocketAddr,
    pub mark: u32,
    pub tos: u8,
}

pub struct SendDnsMessage {
    pub message: Vec<u8>,
    pub addr: SocketAddr,
}

pub fn set_socket_rcvmark(fd: i32) -> std::io::Result<()> {
    let enable_mark: libc::c_int = 1;
    unsafe {
        let res = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVMARK,
            &enable_mark as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable_mark) as libc::socklen_t,
        );
        if res == -1 {
            return Err(std::io::Error::last_os_error());
        } else {
            Ok(())
        }
    }
}

pub fn get_socket_rcvmark(fd: i32) -> std::io::Result<bool> {
    let mut mark: u32 = 1;
    let mut mark_size = std::mem::size_of::<u32>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVMARK,
            &mut mark as *mut _ as *mut _,
            &mut mark_size,
        )
    };
    if ret >= 0 {
        Ok(mark > 0)
    } else {
        Err(std::io::Error::last_os_error())
    }
}
