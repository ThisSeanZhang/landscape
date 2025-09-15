use std::{mem::MaybeUninit, os::raw::c_void};

pub(crate) mod land_dns_dispatcher {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/land_dns_dispatcher.skel.rs"));
}
use crate::bpf_error::LdEbpfResult;
use crate::MAP_PATHS;
use land_dns_dispatcher::*;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libc::SO_ATTACH_REUSEPORT_EBPF;
use libc::{setsockopt, socklen_t, SOL_SOCKET};
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

pub fn attach_reuseport_ebpf(sock_fd: i32) -> LdEbpfResult<()> {
    let mut open_object = MaybeUninit::zeroed();
    let builder = LandDnsDispatcherSkelBuilder::default();
    let mut open_skel = builder.open(&mut open_object)?;

    open_skel.maps.dns_flow_socks.set_pin_path(&MAP_PATHS.dns_flow_socks)?;
    open_skel.maps.dns_flow_socks.reuse_pinned_map(&MAP_PATHS.dns_flow_socks)?;

    open_skel.maps.flow_match_map.set_pin_path(&MAP_PATHS.flow_match_map)?;
    open_skel.maps.flow_match_map.reuse_pinned_map(&MAP_PATHS.flow_match_map)?;

    let skel = open_skel.load()?;

    let reuseport_dns_dispatcher = skel.progs.reuseport_dns_dispatcher;
    let prog_fd: i32 = reuseport_dns_dispatcher.as_fd().as_raw_fd();

    // println!("is_supported {:?}", reuseport_dns_dispatcher.prog_type().is_supported());
    // println!("{:?}", reuseport_dns_dispatcher.attach_type());

    unsafe {
        let ret = setsockopt(
            sock_fd,
            SOL_SOCKET,
            SO_ATTACH_REUSEPORT_EBPF,
            &prog_fd as *const _ as *const c_void,
            std::mem::size_of::<i32>() as socklen_t,
        );
        if ret != 0 {
            println!("{:?}", std::io::Error::last_os_error());
        } else {
            println!("success");
        }
    }

    Ok(())
}
