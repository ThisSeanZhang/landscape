mod landscape_bpf {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/landscape.skel.rs"));
}
use std::{mem::MaybeUninit, os::fd::AsFd, time::Duration};

use landscape_bpf::*;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Program, TcAttachPoint, TcHook, TcHookBuilder, TC_EGRESS, TC_INGRESS,
};
use tracing::debug;

fn bump_memlock_rlimit() {
    let rlimit = libc::rlimit { rlim_cur: 128 << 20, rlim_max: 128 << 20 };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        panic!("Failed to increase rlimit");
    }
}

pub fn test() {
    bump_memlock_rlimit();

    // let running = Arc::new(AtomicBool::new(true));
    // let r = running.clone();
    // ctrlc::set_handler(move || {
    //     r.store(false, Ordering::SeqCst);
    // })
    // .unwrap();

    let landscape_builder = LandscapeSkelBuilder::default();
    // landscape_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let landscape_open = landscape_builder.open(&mut open_object).unwrap();
    // landscape_open.maps.wan_ipv4_binding.set_pin_path(PathBuf::from(WAN_IP_MAP_PING_PATH));
    let landscape_skel = landscape_open.load().unwrap();

    let mark_ingress = landscape_skel.progs.mark_ingress;
    let mark_egress = landscape_skel.progs.mark_egress;
    // let nat_ingress = landscape_skel.progs.ingress_nat;
    // let nat_egress = landscape_skel.progs.egress_nat;
    // let modify_egress = landscape_skel.progs.modify_egress;

    // println!("pt: {:?}", modify_egress.prog_type());
    let ifindex = 15;
    // let mut tc_builder = TcHookBuilder::new(nat_ingress.as_fd());
    // tc_builder.ifindex(ifindex).replace(true).handle(1).priority(1);

    let mut mark_ingress_hook = TcHookProxy::new(&mark_ingress, ifindex, TC_INGRESS, 1);
    let mut mark_egress_hook = TcHookProxy::new(&mark_egress, ifindex, TC_EGRESS, 2);
    mark_ingress_hook.attach();
    mark_egress_hook.attach();
    // let mut nat_proxy = TcHookProxy::new(&nat_egress, 7, TC_EGRESS, 1);
    // let mut pppoe_proxy = TcHookProxy::new(&modify_egress, 2, TC_EGRESS, 2);
    // let mut tc_egress_builder = TcHookBuilder::new(nat_egress.as_fd());
    // tc_egress_builder.ifindex(7).replace(true).handle(1).priority(1);

    // let mut tc_modify_egress_builder = TcHookBuilder::new(modify_egress.as_fd());
    // tc_modify_egress_builder.ifindex(7).replace(true).handle(1).priority(2);

    // let mut ingress = tc_builder.hook(TC_INGRESS);
    // let mut egress = tc_egress_builder.hook(TC_EGRESS);
    // let mut modify = tc_modify_egress_builder.hook(TC_EGRESS);
    // match ingress.query() {
    //     Ok(_prog_id) => {
    //         ingress.detach().unwrap();

    //         ingress.create().unwrap();
    //         ingress.attach().unwrap();
    //     }
    //     Err(_) => {
    //         ingress.create().unwrap();
    //         ingress.attach().unwrap();
    //     }
    // }

    // match modify.query() {
    //     Ok(_prog_id) => {
    //         modify.detach().unwrap();
    //         println!("modify detach");
    //         return;
    //         // modify.create().unwrap();
    //         // modify.attach().unwrap();
    //     }
    //     Err(_) => {
    //         modify = modify.create().unwrap();
    //         modify.attach().unwrap();
    //     }
    // }
    // println!("modify success");
    // match egress.query() {
    //     Ok(_prog_id) => {
    //         egress.detach().unwrap();
    //         println!("egress detach");
    //         return;

    //         // egress.create().unwrap();
    //         // egress.attach().unwrap();
    //     }
    //     Err(_) => {
    //         egress = egress.create().unwrap();
    //         egress.attach().unwrap();
    //     }
    // }
    // nat_proxy.attach();
    // pppoe_proxy.attach();
    println!("egress success");

    // while running.load(Ordering::SeqCst) {
    //     thread::sleep(Duration::new(1, 0));
    // }
    std::thread::sleep(Duration::from_secs(10));
    drop(mark_egress_hook);
    drop(mark_ingress_hook);
    // ingress.detach().unwrap();
    // egress.detach().unwrap();
    // modify.detach().unwrap();
}

pub async fn xdp_test() {
    let landscape_builder = LandscapeSkelBuilder::default();
    // landscape_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let landscape_open = landscape_builder.open(&mut open_object).unwrap();
    let landscape_skel = landscape_open.load().unwrap();

    let _link = landscape_skel.progs.xdp_pass.attach_xdp(6).unwrap();

    std::thread::sleep(Duration::from_secs(120));
}

pub struct TcHookProxy {
    hook: Option<TcHook>,
}

impl TcHookProxy {
    pub fn new(prog: &Program, ifindex: i32, attach: TcAttachPoint, priority: u32) -> TcHookProxy {
        let mut tc_builder = TcHookBuilder::new(prog.as_fd());
        tc_builder.ifindex(ifindex).replace(true).handle(1).priority(priority);
        let ingress = tc_builder.hook(attach);
        Self { hook: Some(ingress) }
    }

    pub fn attach(&mut self) {
        if let Some(hook) = self.hook.as_mut() {
            let result = hook.query();
            debug!("1 - the hook is exist? {:?}", result);
            hook.create().unwrap();

            let result = hook.query();
            debug!("2 - the hook is exist? {:?}", result);
            hook.attach().unwrap();

            let result = hook.query();
            debug!("3 - the hook is exist? {:?}", result);
        }
    }
}

impl Drop for TcHookProxy {
    fn drop(&mut self) {
        if let Some(mut hook) = self.hook {
            debug!("detach hook");
            if let Ok(_) = hook.query() {
                debug!("start detach success");
                if let Err(e) = hook.detach() {
                    debug!("detach error: {:?}", e);
                } else {
                    debug!("detach success");
                }
            }
            if let Err(e) = hook.destroy() {
                debug!("destroy error: {:?}", e);
            }
        }
        // if let Ok(_) = self.query() {
        //     self.detach().unwrap();
        // }
    }
}
