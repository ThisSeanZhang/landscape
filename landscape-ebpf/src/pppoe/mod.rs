use std::{
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        raw::c_void,
    },
};

use landscape_pppoe_client::*;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libc::{
    socket, socklen_t, AF_PACKET, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_RAW, SOL_SOCKET, SO_ATTACH_BPF,
};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

mod landscape_pppoe_client {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/pppoe_client.skel.rs"));
}

pub mod pppoe_handle;
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

fn bind_raw_socket(socket: &Socket, ifindex: u32) -> Result<(), ()> {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = AF_PACKET as u16;
    addr.sll_ifindex = ifindex as i32;
    addr.sll_protocol = 0x0003_u16.to_be();

    let storage = unsafe {
        let mut s = std::mem::zeroed::<socket2::SockAddrStorage>();
        std::ptr::copy_nonoverlapping(&addr, &mut s as *mut _ as *mut libc::sockaddr_ll, 1);
        s
    };
    let sockaddr =
        unsafe { socket2::SockAddr::new(storage, std::mem::size_of::<libc::sockaddr_ll>() as u32) };

    socket.bind(&sockaddr).map_err(|e| {
        tracing::error!("pppoe socket bind failed: {e:?}");
    })
}

pub async fn start(
    index: u32,
) -> Result<(mpsc::Sender<Box<Vec<u8>>>, mpsc::Receiver<Box<Vec<u8>>>), ()> {
    let pppoe_builder = PppoeClientSkelBuilder::default();

    // pppoe_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let pppoe_open =
        crate::bpf_ctx!(pppoe_builder.open(&mut open_object), "pppoe_client open skeleton failed")
            .unwrap();
    let pppoe_skel =
        crate::bpf_ctx!(pppoe_open.load(), "pppoe_client load skeleton failed").unwrap();

    let pppoe_pnet_progs = pppoe_skel.progs;

    let pppoe_pnet_filter_fd = pppoe_pnet_progs.pppoe_pnet_filter.as_fd().as_raw_fd();

    let raw_socket_fd = open_raw_socket(pppoe_pnet_filter_fd)?;
    let socket = unsafe { Socket::from_raw_fd(raw_socket_fd) };
    bind_raw_socket(&socket, index)?;
    let async_fd = AsyncFd::new(socket).map_err(|e| {
        tracing::error!("pppoe async fd init failed: {e:?}");
    })?;

    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Box<Vec<u8>>>(1024);
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Box<Vec<u8>>>(1024);

    tokio::spawn(async move {
        let mut recv_buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];

        loop {
            tokio::select! {
                maybe_data = in_rx.recv() => {
                    let Some(data) = maybe_data else {
                        break;
                    };

                    loop {
                        let Ok(mut guard) = async_fd.writable().await else {
                            return;
                        };
                        match guard.try_io(|inner| inner.get_ref().send(&data)) {
                            Ok(Ok(_)) => break,
                            Ok(Err(e)) => {
                                tracing::error!("pppoe socket send failed: {e:?}");
                                return;
                            }
                            Err(_) => continue,
                        }
                    }
                }
                recv_ready = async_fd.readable() => {
                    let Ok(mut guard) = recv_ready else {
                        return;
                    };

                    match guard.try_io(|inner| inner.get_ref().recv(&mut recv_buf)) {
                        Ok(Ok(len)) => {
                            let packet = unsafe {
                                std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len)
                            };
                            if out_tx.send(Box::new(packet.to_vec())).await.is_err() {
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::error!("pppoe socket recv failed: {e:?}");
                            return;
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    });

    Ok((in_tx, out_rx))
}
