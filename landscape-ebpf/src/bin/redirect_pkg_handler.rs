use clap::Parser;

use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use landscape_ebpf::landscape::TcHookProxy;
use landscape_ebpf::tproxy::landscape_tproxy::*;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::TC_INGRESS;

use libc::{if_freenameindex, if_nameindex, if_nametoindex};
use std::ffi::CStr;
use std::io;

#[derive(Debug, Parser)]
pub struct CmdParams {
    #[arg(short = 's', long = "saddr", default_value = "0.0.0.0", env = "LAND_PROXY_SERVER_ADDR")]
    tproxy_server_address: Ipv4Addr,
    #[arg(short = 'p', long = "sport", default_value_t = 12345, env = "LAND_PROXY_SERVER_PORT")]
    tproxy_server_port: u16,
}

// fn bump_memlock_rlimit() {
//     let rlimit = libc::rlimit { rlim_cur: 128 << 20, rlim_max: 128 << 20 };

//     if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
//         panic!("Failed to increase rlimit");
//     }
// }

fn main() {
    // bump_memlock_rlimit();
    let params = CmdParams::parse();

    let ifindex = match get_non_loopback_interface_index() {
        Ok(index) => index,
        Err(err) => {
            eprintln!("Error: {:?}", err);
            return;
        }
    };

    // Install Ctrl-C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let proxy_addr: u32 = params.tproxy_server_address.into();

    let skel_builder = TproxySkelBuilder::default();
    // skel_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).unwrap();

    // Set constants
    open_skel.maps.rodata_data.proxy_addr = proxy_addr.to_be();
    open_skel.maps.rodata_data.proxy_port = params.tproxy_server_port.to_be();

    // Load into kernel
    let skel = open_skel.load().unwrap();

    let tproxy_ingress = skel.progs.tproxy_ingress;
    // let tproxy_egress = skel.progs.tproxy_egress;
    let mut tproxy_ingress_hook = TcHookProxy::new(&tproxy_ingress, ifindex, TC_INGRESS, 1);
    // let mut tproxy_egress_hook = TcHookProxy::new(&tproxy_egress, ifindex, TC_EGRESS, 1);

    tproxy_ingress_hook.attach();
    // tproxy_egress_hook.attach();

    // Block until SIGINT
    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0));
    }

    drop(tproxy_ingress_hook);
    // drop(tproxy_egress_hook);
}

fn get_non_loopback_interface_index() -> Result<i32, io::Error> {
    unsafe {
        // 获取所有网卡的名称和索引
        let interfaces = if_nameindex();
        if interfaces.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get interfaces"));
        }

        // 遍历网卡，查找非 "lo"
        let mut ptr = interfaces;
        while !(*ptr).if_name.is_null() {
            let name = CStr::from_ptr((*ptr).if_name).to_string_lossy();

            if name != "lo" {
                // 获取索引
                let index = if_nametoindex((*ptr).if_name);
                if index == 0 {
                    if_freenameindex(interfaces);
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Failed to get interface index",
                    ));
                }

                if_freenameindex(interfaces);
                return Ok(index as i32);
            }

            ptr = ptr.add(1);
        }

        // 释放资源
        if_freenameindex(interfaces);

        // 如果未找到非 "lo" 网卡
        Err(io::Error::new(io::ErrorKind::NotFound, "No non-loopback interface found"))
    }
}
