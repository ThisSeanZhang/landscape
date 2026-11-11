use std::{io, mem::MaybeUninit, os::raw::c_void};

use landscape_common::flow::DnsListenerRole;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libc::SO_ATTACH_REUSEPORT_EBPF;
use libc::{SOL_SOCKET, setsockopt, socklen_t};
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

use crate::bpf_error::{LandscapeEbpfError, LdEbpfResult};
use crate::landscape::pin_and_reuse_map;
use crate::maps::LandscapeMapPath;
use crate::skel::sk_dns_dispatcher::*;

pub fn attach_reuseport_ebpf(
    paths: &LandscapeMapPath,
    sock_fd: i32,
    role: DnsListenerRole,
) -> LdEbpfResult<()> {
    let mut open_object = MaybeUninit::zeroed();
    let builder = SkDnsDispatcherSkelBuilder::default();
    let mut open_skel =
        crate::bpf_ctx!(builder.open(&mut open_object), "dns_dispatcher open skeleton failed")?;

    let rodata = open_skel.maps.rodata_data.as_deref_mut().ok_or_else(|| {
        LandscapeEbpfError::Io(io::Error::other("dns_dispatcher skeleton has no writable rodata"))
    })?;
    rodata.dns_listener_role_id = role as u32;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.dns_flow_socks, &paths.dns_flow_socks),
        "dns_dispatcher prepare dns_flow_socks failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &paths.flow_match_map),
        "dns_dispatcher prepare flow_match_map failed"
    )?;

    let skel = crate::bpf_ctx!(open_skel.load(), "dns_dispatcher load skeleton failed")?;

    let reuseport_dns_dispatcher = skel.progs.reuseport_dns_dispatcher;
    let prog_fd: i32 = reuseport_dns_dispatcher.as_fd().as_raw_fd();

    unsafe {
        let ret = setsockopt(
            sock_fd,
            SOL_SOCKET,
            SO_ATTACH_REUSEPORT_EBPF,
            &prog_fd as *const _ as *const c_void,
            std::mem::size_of::<i32>() as socklen_t,
        );
        if ret != 0 {
            let err = io::Error::last_os_error();
            return Err(LandscapeEbpfError::Io(io::Error::new(
                err.kind(),
                format!("setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed for role {role:?}: {err}"),
            )));
        }
    }

    tracing::info!("attach DNS eBPF success for role {role:?}");
    Ok(())
}
