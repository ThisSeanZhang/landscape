use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS,
};
use tokio::sync::oneshot::error::TryRecvError;

use crate::{
    bpf_error::LdEbpfResult,
    bpf_rs_shared::xdp_skb_pppoe_skel,
    chain::xdp_manager::{SkbXdpBundle, SkbXdpLink, XdpChainManager},
    landscape::TcHookProxy,
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

        let _skb_bundle_stored = match try_attach_pppoe_skb_xdp(ifindex, session_id) {
            Ok(bundle) => {
                tracing::info!("SKB-mode XDP attached for PPPoE decap on ifindex={ifindex}");
                XdpChainManager::instance().set_skb_bundle(ifindex, bundle);
                true
            }
            Err(e) => {
                tracing::debug!("SKB-mode XDP for PPPoE decap skipped: {e}");
                false
            }
        };

        let call_back = loop {
            match notice_rx.try_recv() {
                Ok(call_back) => break Some(call_back),
                Err(TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(TryRecvError::Closed) => break None,
            }
        };

        // If native XDP hasn't already taken the SKB bundle, we take it
        // here as a fallback.  Dropping the bundle detaches the SKB XDP.
        let _ = XdpChainManager::instance().take_skb_bundle(ifindex);
        drop(chain_handle);

        if let Some(call_back) = call_back {
            let _ = call_back.send(());
        }
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

    rodata_data.session_id = session_id.to_be();
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

fn try_attach_pppoe_skb_xdp(ifindex: u32, session_id: u16) -> LdEbpfResult<SkbXdpBundle> {
    let builder = xdp_skb_pppoe_skel::XdpSkbPppoeSkelBuilder::default();
    let (backing, obj) = crate::landscape::OwnedOpenObject::new();
    let mut open_skel = crate::bpf_ctx!(builder.open(obj), "open xdp_skb_pppoe skeleton")?;
    if let Some(rodata) = open_skel.maps.rodata_data.as_deref_mut() {
        rodata.session_id = session_id.to_be();
    }
    let skel = crate::bpf_ctx!(open_skel.load(), "load xdp_skb_pppoe skeleton")?;

    if crate::map_setting::redirect_able::is_xdp_redirect_able(ifindex) {
        return Err(crate::bpf_error::LandscapeEbpfError::Context {
            context: format!("native XDP already serving ifindex={ifindex} (redirect_able=true)"),
            source: libbpf_rs::Error::from_raw_os_error(17),
        });
    }

    let link = SkbXdpLink::attach(&skel.progs.xdp_skb_pppoe, ifindex)?;
    Ok(SkbXdpBundle::new(backing, skel, link))
}
