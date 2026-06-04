use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS,
};
use tokio::sync::oneshot::error::TryRecvError;

use crate::{
    landscape::TcHookProxy,
    map_setting::reuse_pinned_map_or_recreate,
    pipeline::wan_tc::{self, WanTcPipelineHandle},
    PPPOE_EGRESS_PRIORITY,
};

mod landscape_pppoe {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/pppoe.skel.rs"));
}

pub async fn create_pppoe_tc_ebpf_3(
    ifindex: u32,
    session_id: u16,
    _mtu: u16,
) -> tokio::sync::oneshot::Sender<tokio::sync::oneshot::Sender<()>> {
    let (notice_tx, mut notice_rx) =
        tokio::sync::oneshot::channel::<tokio::sync::oneshot::Sender<()>>();

    std::thread::spawn(move || {
        let chain_handle = match crate::stages::pppoe::attach_tc_pppoe(ifindex, session_id, true) {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::error!("pppoe tc chain register failed for ifindex={}: {e}", ifindex);
                None
            }
        };

        let pipeline = match WanTcPipelineHandle::acquire(ifindex) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("pppoe tc acquire pipeline failed for ifindex={}: {e}", ifindex);
                return;
            }
        };

        let builder = landscape_pppoe::PppoeSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let mut pppoe_open =
            crate::bpf_ctx!(builder.open(&mut open_object), "pppoe tc open skeleton failed")
                .expect("pppoe tc open skeleton");
        let ingress_path = wan_tc::wan_tc_pipeline_ingress_path(ifindex);
        let egress_path = wan_tc::wan_tc_pipeline_egress_path(ifindex);
        reuse_pinned_map_or_recreate(&mut pppoe_open.maps.ingress_stage_progs, &ingress_path);
        reuse_pinned_map_or_recreate(&mut pppoe_open.maps.egress_stage_progs, &egress_path);

        let rodata_data =
            pppoe_open.maps.rodata_data.as_deref_mut().expect("rodata is not memory mapped");
        rodata_data.session_id = session_id;

        let pppoe_skel = crate::bpf_ctx!(pppoe_open.load(), "pppoe tc load skeleton failed")
            .expect("pppoe tc load skeleton");

        if let Err(e) =
            pipeline.register_pppoe(&pppoe_skel.progs.pppoe_ingress, &pppoe_skel.progs.pppoe_egress)
        {
            tracing::error!("pppoe tc register in pipeline failed for ifindex={}: {e}", ifindex);
            return;
        }

        tracing::info!(
            "pppoe tc pipeline registered for ifindex={} session_id={}",
            ifindex,
            session_id
        );

        let call_back = loop {
            match notice_rx.try_recv() {
                Ok(call_back) => break Some(call_back),
                Err(TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(TryRecvError::Closed) => break None,
            }
        };

        pipeline.unregister_pppoe();
        tracing::info!("pppoe tc pipeline unregistered for ifindex={}", ifindex);

        drop(chain_handle);

        if let Some(call_back) = call_back {
            let _ = call_back.send(());
        }
        drop(pppoe_skel);
    });

    notice_tx
}

pub async fn create_pppoe_tc_ebpf<'a>(
    ifindex: u32,
    session_id: u16,
    obj: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
) -> (tokio::sync::broadcast::Sender<()>, landscape_pppoe::PppoeSkel<'a>) {
    let pppoe_builder = landscape_pppoe::PppoeSkelBuilder::default();

    let mut pppoe_open: landscape_pppoe::OpenPppoeSkel<'a> =
        crate::bpf_ctx!(pppoe_builder.open(obj), "pppoe_tc open skeleton failed").unwrap();
    let rodata_data =
        pppoe_open.maps.rodata_data.as_deref_mut().expect("rodata is not memory mapped");

    rodata_data.session_id = session_id;
    let pppoe_skel: landscape_pppoe::PppoeSkel<'a> =
        crate::bpf_ctx!(pppoe_open.load(), "pppoe_tc load skeleton failed").unwrap();

    let mut pppoe_egress_builder = TcHookProxy::new(
        &pppoe_skel.progs.pppoe_egress,
        ifindex as i32,
        TC_EGRESS,
        PPPOE_EGRESS_PRIORITY,
    );

    pppoe_egress_builder.attach();

    let (notice_tx, mut notice_rx) = tokio::sync::broadcast::channel::<()>(1);

    std::thread::spawn(move || {
        let _ = notice_rx.blocking_recv();
        drop(pppoe_egress_builder);
    });
    (notice_tx, pppoe_skel)
}
