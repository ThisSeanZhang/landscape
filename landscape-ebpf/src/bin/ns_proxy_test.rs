use clap::Parser;
use std::{
    fs::File,
    mem::MaybeUninit,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::sleep,
    time::Duration,
};

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS, TC_INGRESS,
};
use nix::sched;

use landscape_ebpf::landscape::TcHookProxy;
fn bump_memlock_rlimit() {
    let rlimit = libc::rlimit { rlim_cur: 128 << 20, rlim_max: 128 << 20 };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        panic!("Failed to increase rlimit");
    }
}

use landscape_ebpf::ns_proxy::ns_proxy::*;

#[derive(Debug, Parser)]
pub struct Params {
    #[clap(long, short = 'm', default_value_t = false)]
    has_mac: bool,

    #[clap(long, short)]
    wan_index: i32,

    #[clap(long, short)]
    ns_index: i32,

    #[clap(long, short)]
    target_addr: Ipv4Addr,

    #[clap(long = "ld", default_value = "0.0.0.0")]
    listen_addr: Ipv4Addr,

    #[clap(long = "lp", default_value_t = 12345)]
    listen_port: u16,
}

fn main() {
    // ip netns add tpns
    // ip link add veth0 type veth peer name veth1
    // ip link set veth1 netns tpns
    // ip link set veth0 up
    // ip netns exec tpns ip link set veth1 up
    // ip netns exec tpns ip link set lo up
    // ip netns exec tpns ip neigh replace 169.254.0.1 lladdr be:25:85:83:00:0d dev veth1
    // ip netns exec tpns  ip addr add 169.254.0.11/32 dev veth1
    // ip netns exec tpns  ip route add 169.254.0.1 dev veth1 scope link
    // ip netns exec tpns  ip route add default via 169.254.0.1 dev veth1

    // ip netns exec tpns ip rule add fwmark 0x1/0x1 lookup 100
    // ip netns exec tpns ip route add local default dev lo table 100
    // ip netns exec tpns sysctl -w net.ipv4.conf.lo.accept_local=1
    // ip netns exec tpns ip route add 169.254.0.1 dev veth1

    // sysctl net.ipv4.conf.veth0.proxy_arp=1
    //  sysctl net.ipv4.conf.veth0.rp_filter=2

    // curl -vvv 223.5.5.5.5:2234
    // docker run --rm -p 2234:80 --name temp-nginx nginx
    //
    // nc -lu 2235
    // nc -u 223.5.5.5.5 2235

    let params = Params::parse();

    println!("parmas: {:?}", params);
    bump_memlock_rlimit();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let mut landscape_builder = NsProxySkelBuilder::default();
    landscape_builder.obj_builder.debug(true);

    let target_addr: u32 = params.target_addr.into();
    let proxy_addr: u32 = params.listen_addr.into();

    let mut open_object = MaybeUninit::uninit();
    let landscape_open = landscape_builder.open(&mut open_object).unwrap();
    landscape_open.maps.rodata_data.outer_ifindex = params.ns_index as u32;
    landscape_open.maps.rodata_data.target_addr = target_addr.to_be();

    landscape_open.maps.rodata_data.proxy_addr = proxy_addr.to_be();
    landscape_open.maps.rodata_data.proxy_port = params.listen_port.to_be();

    if !params.has_mac {
        landscape_open.maps.rodata_data.current_eth_net_offset = 0;
    }

    let landscape_skel = landscape_open.load().unwrap();

    let inner_xdp = landscape_skel.progs.inner_xdp;
    let ns_ingress = landscape_skel.progs.ns_ingress;
    let handle_setsockopt_enter = landscape_skel.progs.handle_setsockopt_enter;
    // let handle__ksyscall = landscape_skel.progs.handle__ksyscall;
    // let cgroup_socket = landscape_skel.progs.sock_create;
    // let ns_peer_ingress = landscape_skel.progs.ns_peer_ingress;
    let wan_egress = landscape_skel.progs.wan_egress;

    let current_ns = File::open("/proc/self/ns/net").unwrap();

    let mut ns_inner_ingress_hook =
        TcHookProxy::new(&ns_ingress, params.ns_index - 1, TC_INGRESS, 1);
    // let mut ns_outer_ingress_hook = TcHookProxy::new(&ns_peer_ingress, 9, TC_INGRESS, 2);
    let mut wan_egress_hook = TcHookProxy::new(&wan_egress, params.wan_index, TC_EGRESS, 1);

    wan_egress_hook.attach();
    // ns_outer_ingress_hook.attach();
    enter_namespace("/var/run/netns/tpns").unwrap();
    let handle_setsockopt_enter_point =
        handle_setsockopt_enter.attach_tracepoint("syscalls", "sys_enter_setsockopt").unwrap();
    // let handle__ksyscall_link =
    //     handle__ksyscall.attach_ksyscall(false, "__sys_setsockopt").unwrap();
    // let cgroup_fd = std::fs::OpenOptions::new()
    //     .read(true)
    //     .custom_flags(libc::O_DIRECTORY)
    //     .open("/sys/fs/cgroup")
    //     .unwrap()
    //     .into_raw_fd();
    // let cgroup_socket_attach = cgroup_socket.attach_cgroup(cgroup_fd).unwrap();
    ns_inner_ingress_hook.attach();
    let xdp = inner_xdp.attach_xdp(params.ns_index - 1).unwrap();

    sched::setns(&current_ns, sched::CloneFlags::CLONE_NEWNET).unwrap();
    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0));
    }

    enter_namespace("/var/run/netns/tpns").unwrap();
    drop(ns_inner_ingress_hook);
    let _ = handle_setsockopt_enter_point.detach();
    // let _ = cgroup_socket_attach.detach();
    // handle__ksyscall_link.detach().unwrap();
    sched::setns(&current_ns, sched::CloneFlags::CLONE_NEWNET).unwrap();
    // drop(ns_outer_ingress_hook);
    drop(wan_egress_hook);
    let _ = xdp.detach();
}

fn enter_namespace(ns_path: &str) -> nix::Result<()> {
    let ns_file = File::open(ns_path).unwrap();
    sched::setns(ns_file, sched::CloneFlags::CLONE_NEWNET)?;
    Ok(())
}
