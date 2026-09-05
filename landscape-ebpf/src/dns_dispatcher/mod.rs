use std::{mem::MaybeUninit, os::raw::c_void};

pub(crate) mod land_dns_dispatcher {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/land_dns_dispatcher.skel.rs"));
}
use crate::bpf_error::LdEbpfResult;
use crate::landscape::pin_and_reuse_map;
use crate::maps::LandscapeMapPath;
use land_dns_dispatcher::*;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libc::SO_ATTACH_REUSEPORT_EBPF;
use libc::{setsockopt, socklen_t, SOL_SOCKET};
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

pub fn attach_reuseport_ebpf(paths: &LandscapeMapPath, sock_fd: i32) -> LdEbpfResult<()> {
    let mut open_object = MaybeUninit::zeroed();
    let builder = LandDnsDispatcherSkelBuilder::default();
    let mut open_skel =
        crate::bpf_ctx!(builder.open(&mut open_object), "dns_dispatcher open skeleton failed")?;

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

    // tracing::info!("is_supported {:?}", reuseport_dns_dispatcher.prog_type().is_supported());
    // tracing::info!("{:?}", reuseport_dns_dispatcher.attach_type());

    unsafe {
        let ret = setsockopt(
            sock_fd,
            SOL_SOCKET,
            SO_ATTACH_REUSEPORT_EBPF,
            &prog_fd as *const _ as *const c_void,
            std::mem::size_of::<i32>() as socklen_t,
        );
        if ret != 0 {
            tracing::error!("{:?}", std::io::Error::last_os_error());
        } else {
            tracing::info!("attach DNS eBPF success");
        }
    }

    Ok(())
}
