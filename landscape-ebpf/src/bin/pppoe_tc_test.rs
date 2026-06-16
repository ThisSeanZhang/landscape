use std::time::Duration;

use landscape_ebpf::pppoe;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    // ping -4 -I ens6 -M do -s 1472 DESKTOP-D4MDN4E.lan
    // ping -6 -I ens6 -M do -s 1444 DESKTOP-D4MDN4E.lan
    let (notice_tx, notice_rx) = tokio::sync::oneshot::channel::<()>();
    let tmpl = pppoe::pppoe_tc::PppoeEgressTmpl {
        dmac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        smac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        eth_proto: (0x8864u16).to_be(),
        ver_type: 0x11,
        code: 0x00,
        session_id: 0x2233u16.to_be(),
        ..Default::default()
    };
    let notise = pppoe::pppoe_tc::create_pppoe_tc_ebpf_3(5, tmpl, 1490).await;
    println!("结束 ebpf pppoe 创建");
    sleep(Duration::from_secs(20)).await;
    println!("应该结束了");
    notise.send(notice_tx).unwrap();
    println!("发送结束请求");
    let _ = notice_rx.await;
    println!("结束");
}
