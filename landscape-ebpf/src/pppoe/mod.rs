use std::{
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd},
        raw::c_void,
    },
};

use landscape_pppoe_client::*;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libc::{
    socket, socklen_t, AF_PACKET, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_RAW, SOL_SOCKET, SO_ATTACH_BPF,
};
use pnet::datalink::Channel::Ethernet;
use tokio::sync::mpsc;

mod landscape_pppoe_client {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/pppoe_client.skel.rs"));
}

pub mod pppoe_tc;
fn open_raw_socket(prog_fd: i32) -> Result<i32, ()> {
    const ETH_P_ALL: u16 = 0x0003;
    unsafe {
        let target_socket =
            socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, ETH_P_ALL.to_be() as i32);
        if target_socket == -1 {
            return Err(());
        }

        libc::setsockopt(
            target_socket,
            SOL_SOCKET,
            SO_ATTACH_BPF,
            &prog_fd as *const _ as *const c_void,
            std::mem::size_of_val(&target_socket) as socklen_t,
        );
        Ok(target_socket)
    }
}
pub async fn start(
    index: u32,
) -> Result<(mpsc::Sender<Box<Vec<u8>>>, mpsc::Receiver<Box<Vec<u8>>>), ()> {
    let pppoe_builder = PppoeClientSkelBuilder::default();

    // pppoe_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let pppoe_open = pppoe_builder.open(&mut open_object).unwrap();
    let pppoe_skel = pppoe_open.load().unwrap();

    let pppoe_pnet_progs = pppoe_skel.progs;

    let pppoe_pnet_filter_fd = pppoe_pnet_progs.pppoe_pnet_filter.as_fd().as_raw_fd();

    let pnet_socket = open_raw_socket(pppoe_pnet_filter_fd).unwrap();

    let all_interfaces = pnet::datalink::interfaces();
    let target_interface = all_interfaces.iter().find(|e| e.index == index);
    let Some(interface) = target_interface else {
        return Err(());
    };

    let mut pnet_config = pnet::datalink::Config::default();
    pnet_config.socket_fd = Some(pnet_socket);

    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, pnet_config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Box<Vec<u8>>>(1024);
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Box<Vec<u8>>>(1024);
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let _handler = std::thread::Builder::new()
        .name("landscape_pppoe_thread".into())
        .spawn(move || {
            //
            loop {
                match rx.next() {
                    Ok(packet) => {
                        tracing::info!("{:?}", packet);
                        out_tx.try_send(Box::new(packet.to_vec())).unwrap();
                    }
                    Err(e) => {
                        panic!("An error occurred while reading: {}", e);
                    }
                }
                if let Err(tokio::sync::oneshot::error::TryRecvError::Empty) = stop_rx.try_recv() {
                    continue;
                }
            }
        })
        .unwrap();
    tokio::spawn(async move {
        while let Some(data) = in_rx.recv().await {
            tx.send_to(&data, None);
        }
        stop_tx.send(()).unwrap();
    });
    Ok((in_tx, out_rx))
}
