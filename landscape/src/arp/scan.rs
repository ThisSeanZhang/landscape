use std::{net::Ipv4Addr, time::Duration};

use cidr::Ipv4Inet;
use landscape_common::{lan_service::lan_dhcpv4::status::ArpScanInfoItem, net::MacAddr};
use tokio_util::sync::CancellationToken;

pub async fn scan_ip_info(
    ifindex: u32,
    mac: MacAddr,
    server_addr: Ipv4Addr,
    mask: u8,
) -> Vec<ArpScanInfoItem> {
    let (arp_tx, mut arp_rx) = crate::arp::create_arp_listen(ifindex).await.unwrap();

    let ip_cidr = Ipv4Inet::new(server_addr, mask).unwrap();
    let mut cidr = ip_cidr.first();

    let scan_done = CancellationToken::new();
    let child_token = scan_done.child_token();
    tokio::spawn(async move {
        let mut send_num = 0_u16;

        while let Some(ip) = cidr.next() {
            cidr = ip;
            if ip.address() == cidr.last_address() {
                continue;
            }

            if ip.address() == server_addr {
                continue;
            }
            // println!("request ip: {:?}", ip.address());
            if let Err(e) = arp_tx.send(handle_arp_request(&mac, &server_addr, &ip.address())).await
            {
                tracing::error!("sand arp packet error: {e:?}");
            }

            send_num += 1;
            if send_num == 255 {
                send_num = 0;
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
        tracing::info!("[ifindex: {ifindex}] arp scan finish");
        tokio::time::sleep(Duration::from_secs(5)).await;

        scan_done.cancel();
    });

    let mut result = vec![];
    loop {
        tokio::select! {
            _ = child_token.cancelled() => break,
            msg = arp_rx.recv() => {
                let Some(packet) = msg else {
                    break;
                };
                if let Some(item) = handle_arp_response(packet) {
                    result.push(item);
                }
            }
        }
    }
    result
}

fn handle_arp_response(packet: Vec<u8>) -> Option<ArpScanInfoItem> {
    if packet.len() < 42 {
        return None;
    }

    // EtherType
    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    if ethertype != 0x0806 {
        return None;
    }

    // ARP 操作
    let oper = u16::from_be_bytes([packet[20], packet[21]]);
    if oper != 2 {
        return None; // 不是 ARP reply
    }

    // 发送者 MAC 和 IP
    let sha = &packet[22..28];
    let spa = &packet[28..32];

    let mac = MacAddr::new(sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
    let ip = Ipv4Addr::new(spa[0], spa[1], spa[2], spa[3]);

    Some(ArpScanInfoItem { ip, mac })
}

fn handle_arp_request(my_mac: &MacAddr, my_ip: &Ipv4Addr, target_ip: &Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 42]; // 14 (Ethernet) + 28 (ARP)

    let mac_slice = my_mac.octets();
    // --- Ethernet header ---
    // 目的 MAC: 广播
    buf[0..6].copy_from_slice(&[0xff; 6]);
    // 源 MAC
    buf[6..12].copy_from_slice(&mac_slice);
    // EtherType: ARP
    buf[12..14].copy_from_slice(&0x0806u16.to_be_bytes());

    // --- ARP payload ---
    // HTYPE: Ethernet = 1
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    // PTYPE: IPv4 = 0x0800
    buf[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    // HLEN, PLEN
    buf[18] = 6;
    buf[19] = 4;
    // OPER: request = 1
    buf[20..22].copy_from_slice(&1u16.to_be_bytes());
    // SHA
    buf[22..28].copy_from_slice(&mac_slice);
    // SPA
    buf[28..32].copy_from_slice(&my_ip.octets());
    // THA: 0
    buf[32..38].copy_from_slice(&[0u8; 6]);
    // TPA: ip (目标 IP)
    buf[38..42].copy_from_slice(&target_ip.octets());

    buf
}
