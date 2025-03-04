use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use landscape_common::util::compute_checksum;
use landscape_pppoe::*;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    OpenObject, TC_EGRESS, TC_INGRESS,
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::sync::oneshot::error::TryRecvError;

use crate::{landscape::TcHookProxy, PPPOE_EGRESS_PRIORITY, PPPOE_INGRESS_PRIORITY};

mod landscape_pppoe {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/pppoe.skel.rs"));
}
pub async fn create_pppoe_tc_ebpf<'a>(
    ifindex: u32,
    session_id: u16,
    obj: &'a mut MaybeUninit<OpenObject>,
) -> (tokio::sync::broadcast::Sender<()>, PppoeSkel<'a>) {
    let pppoe_builder = PppoeSkelBuilder::default();

    // pppoe_builder.obj_builder.debug(true);

    let pppoe_open: OpenPppoeSkel<'a> = pppoe_builder.open(obj).unwrap();
    pppoe_open.maps.rodata_data.session_id = session_id;
    let pppoe_skel: PppoeSkel<'a> = pppoe_open.load().unwrap();

    // let pppoe_pnet_progs = pppoe_skel.progs;

    // let mut pppoe_ingress_builder =
    //     TcHookProxy::new(&pppoe_skel.progs.pppoe_ingress, ifindex as i32, TC_INGRESS, PPPOE_INGRESS_PRIORITY);
    let mut pppoe_egress_builder = TcHookProxy::new(
        &pppoe_skel.progs.pppoe_egress,
        ifindex as i32,
        TC_EGRESS,
        PPPOE_EGRESS_PRIORITY,
    );

    // let mut pppoe_xdp_ingress = pppoe_skel.progs.pppoe_xdp_ingress;
    // let _link = pppoe_xdp_ingress.attach_xdp(ifindex as i32).unwrap();
    let (notice_tx, mut notice_rx) = tokio::sync::broadcast::channel::<()>(1);

    tokio::spawn(async move {
        // pppoe_ingress_builder.attach();
        pppoe_egress_builder.attach();

        let _ = notice_rx.recv().await;
    });
    (notice_tx, pppoe_skel)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PPPoEBpfTcAction {
    Stop,
}
// pub async fn create_pppoe_tc_ebpf2(
//     ifindex: u32,
//     session_id: u16,
// ) -> tokio::sync::mpsc::Sender<PPPoEBpfTcAction> {
//     let (action_tx, mut action_rx) = tokio::sync::mpsc::channel::<PPPoEBpfTcAction>(128);

//     tokio::spawn(async move {
//         let mut pppoe_builder = PppoeSkelBuilder::default();
//         pppoe_builder.obj_builder.debug(true);
//         let mut open_object = MaybeUninit::uninit();
//         tokio::pin!(open_object);
//         let pppoe_open: OpenPppoeSkel<'static> = pppoe_builder.open(&mut open_object).unwrap();
//         pppoe_open.maps.rodata_data.session_id = session_id;
//         let pppoe_skel: PppoeSkel<'static> = pppoe_open.load().unwrap();

//         let pppoe_ingress_builder =
//             TcHookProxy::new(&pppoe_skel.progs.pppoe_ingress, ifindex as i32, TC_INGRESS, 1);
//         let pppoe_egress_builder =
//             TcHookProxy::new(&pppoe_skel.progs.pppoe_egress, ifindex as i32, TC_EGRESS, 1);
//         while let Some(action) = action_rx.recv().await {
//             match action {
//                 PPPoEBpfTcAction::Stop => {
//                     break;
//                 }
//             }
//         }
//     });

//     action_tx
// }

#[derive(Debug)]
pub struct IcmpV4Hdr<'a> {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    __unused: u16,
    mtu: u16,
    data: &'a [u8],
}

impl<'a> IcmpV4Hdr<'a> {
    pub fn new(data: &'a [u8], mtu: u16) -> Self {
        let mut checksum: u32 = 0x03040000;
        checksum = checksum.wrapping_add(mtu as u32);
        let checksum = compute_checksum(checksum, data);
        IcmpV4Hdr {
            icmp_type: 3,
            code: 4,
            checksum,
            __unused: 0,
            mtu,
            data,
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(8 + self.data.len());
        result.push(self.icmp_type);
        result.push(self.code);
        result.extend_from_slice(&self.checksum.to_be_bytes());
        result.extend_from_slice(&self.__unused.to_be_bytes());
        result.extend_from_slice(&self.mtu.to_be_bytes());
        result.extend_from_slice(&self.data);
        result
    }
}

pub fn handle_icmp(ipv4_sockt: &Socket, data: Box<Vec<u8>>, mtu: u16) {
    if data.len() < 2 {
        return;
    }

    let eth_proto = data[0];

    // 1 IPV4
    if eth_proto == 1 {
        if data.len() < 29 {
            return;
        }
        let size = (data[1] & 0xf) * 4;
        tracing::info!("size is : {size:?}");
        let ipv4 = Ipv4Addr::new(data[13], data[14], data[15], data[16]);
        tracing::info!("ip is : {ipv4:?}");
        let packet_start = 1;
        // let packet_end = packet_start + (size as usize) + 8;
        let icmp_packet = IcmpV4Hdr::new(&data[packet_start..], mtu);
        tracing::info!("icmp packet: {:?}", icmp_packet);
        if let Err(e) = ipv4_sockt
            .send_to(&icmp_packet.get_bytes(), &SockAddr::from(SocketAddrV4::new(ipv4, 0)))
        {
            tracing::error!("e: {e:?}");
        }
    } else {
        tracing::info!("data.len() is : {:?}", data.len());
    }
}
pub async fn create_pppoe_tc_ebpf_3(
    ifindex: u32,
    session_id: u16,
    mtu: u16,
) -> tokio::sync::oneshot::Sender<tokio::sync::oneshot::Sender<()>> {
    // let pppoe_pnet_progs = pppoe_skel.progs;

    // let mut pppoe_ingress_builder =
    //     TcHookProxy::new(&pppoe_skel.progs.pppoe_ingress, ifindex as i32, TC_INGRESS, 1);

    let (icmp_msg_tx, mut icmp_msg_rx) = tokio::sync::mpsc::unbounded_channel::<Box<Vec<u8>>>();
    let socket_v4 =
        socket2::Socket::new(Domain::IPV4, Type::RAW, Some(libc::IPPROTO_ICMP.into())).unwrap();
    // let socket_v6 =
    //     socket2::Socket::new(Domain::IPV6, Type::RAW, Some(libc::IPPROTO_ICMPV6.into())).unwrap();

    // socket_v4.send_to(buf, addr)
    tokio::spawn(async move {
        while let Some(data) = icmp_msg_rx.recv().await {
            // println!("receive data len: {:?}", data.len());
            handle_icmp(&socket_v4, data, mtu);
        }

        tracing::info!("exit icmp too large loop");
    });
    let (notice_tx, mut notice_rx) =
        tokio::sync::oneshot::channel::<tokio::sync::oneshot::Sender<()>>();

    std::thread::spawn(move || {
        let builder = PppoeSkelBuilder::default(); // 假设你可以直接使用它
                                                   // 在新线程中执行逻辑
        let mut open_object = MaybeUninit::uninit();
        let pppoe_open = builder.open(&mut open_object).unwrap();
        pppoe_open.maps.rodata_data.session_id = session_id;
        pppoe_open.maps.rodata_data.pppoe_mtu = mtu;

        let pppoe_skel = pppoe_open.load().unwrap();

        let callback = |data: &[u8]| -> i32 {
            let _ = icmp_msg_tx.send(Box::new(data.to_vec()));
            0
        };
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder.add(&pppoe_skel.maps.icmp_notice_events, callback).expect("failed to add ringbuf");
        let mgr = builder.build().expect("failed to build");

        // mgr.consume().expect("failed to consume ringbuf");
        // let pppoe_pnet_progs = pppoe_skel.progs;

        // let mut pppoe_ingress_builder =
        //     TcHookProxy::new(&pppoe_skel.progs.pppoe_ingress, ifindex as i32, TC_INGRESS, 1);
        // let mut pppoe_egress_pkt_size_filter = TcHookProxy::new(
        //     &pppoe_skel.progs.pppoe_egress_pkt_size_filter,
        //     ifindex as i32,
        //     TC_EGRESS,
        //     PPPOE_MTU_FILTER_EGRESS_PRIORITY,
        // );

        let mut pppoe_egress_builder = TcHookProxy::new(
            &pppoe_skel.progs.pppoe_egress,
            ifindex as i32,
            TC_EGRESS,
            PPPOE_EGRESS_PRIORITY,
        );

        let mut pppoe_ingress_builder = TcHookProxy::new(
            &pppoe_skel.progs.pppoe_ingress_mss_filter,
            ifindex as i32,
            TC_INGRESS,
            PPPOE_INGRESS_PRIORITY,
        );

        let pppoe_xdp_ingress = pppoe_skel.progs.pppoe_xdp_ingress;
        let pppoe_xdp_link = pppoe_xdp_ingress.attach_xdp(ifindex as i32).unwrap();

        // pppoe_egress_pkt_size_filter.attach();
        pppoe_egress_builder.attach();
        pppoe_ingress_builder.attach();

        let call_back = 'wait_stoop: loop {
            let _ = mgr.poll(Duration::from_millis(100));
            match notice_rx.try_recv() {
                Ok(call_back) => break 'wait_stoop Some(call_back),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Closed) => break 'wait_stoop None,
            }
        };
        tracing::info!("退出 pppoe");
        // drop(pppoe_egress_pkt_size_filter);
        drop(pppoe_egress_builder);
        drop(pppoe_ingress_builder);
        let _ = pppoe_xdp_link.detach();
        if let Some(call_back) = call_back {
            let _ = call_back.send(());
        }
    });

    notice_tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_checksum1() {
        let data: &[u8] = &[
            0x45, 0x20, 0x05, 0xd4, 0x40, 0x8d, 0x40, 0x00, 0x3e, 0x06, 0x18, 0xb3, 0x0a, 0x03,
            0xcd, 0x24, 0x0a, 0x40, 0xfc, 0x5c, 0xcc, 0xf9, 0xd7, 0x48, 0x8e, 0x30, 0x5e, 0x03,
        ];
        let a = IcmpV4Hdr::new(data, 1468);
        assert_eq!(a.checksum, 0x66c9);
    }
}
