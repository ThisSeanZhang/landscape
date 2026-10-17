use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{NetHeaders, PacketHeaders, TransportHeader};

pub fn analyze(packet_out: &[u8]) {
    let pkt = match PacketHeaders::from_ethernet_slice(packet_out) {
        Ok(p) => p,
        Err(e) => {
            println!("parse failed: {:?}", e);
            return;
        }
    };

    if let Some(NetHeaders::Ipv4(ipv4, _exts)) = &pkt.net {
        let source: Ipv4Addr = ipv4.source.into();
        let destination: Ipv4Addr = ipv4.destination.into();
        println!("IPv4 src = {:?}, dst = {:?}", source, destination);

        if let Some(transport) = &pkt.transport {
            match transport {
                TransportHeader::Tcp(tcp) => {
                    println!(
                        "TCP src_port = {}, dst_port = {}",
                        tcp.source_port, tcp.destination_port
                    );
                    match tcp.calc_checksum_ipv4(ipv4, pkt.payload.slice()) {
                        Ok(calc) => {
                            println!(
                                "TCP checksum on packet = {:#x}, calculated = {:#x}, match = {}",
                                tcp.checksum,
                                calc,
                                tcp.checksum == calc
                            );
                        }
                        Err(err) => {
                            println!("TCP checksum calc error: {:?}", err);
                        }
                    }
                }
                TransportHeader::Udp(udp) => {
                    println!(
                        "UDP src_port = {}, dst_port = {}",
                        udp.source_port, udp.destination_port
                    );
                    match udp.calc_checksum_ipv4(ipv4, pkt.payload.slice()) {
                        Ok(calc) => {
                            println!(
                                "UDP checksum on packet = {:#x}, calculated = {:#x}, match = {}",
                                udp.checksum,
                                calc,
                                udp.checksum == calc
                            );
                        }
                        Err(err) => {
                            println!("UDP checksum calc error: {:?}", err);
                        }
                    }
                }
                _ => {
                    println!("other transport: {:?}", transport);
                }
            }
        }
    } else if let Some(NetHeaders::Ipv6(ipv6, _exts)) = pkt.net {
        let source: Ipv6Addr = ipv6.source.into();
        let destination: Ipv6Addr = ipv6.destination.into();
        println!("IPv6 src = {:?}, dst = {:?}", source, destination);
        println!("pkt.transport = {:?}", pkt.transport);

        // 传输层
        if let Some(transport) = pkt.transport {
            match transport {
                TransportHeader::Tcp(tcp) => {
                    println!(
                        "TCP src_port = {}, dst_port = {}",
                        tcp.source_port, tcp.destination_port
                    );
                    match tcp.calc_checksum_ipv6(&ipv6, pkt.payload.slice()) {
                        Ok(calc) => {
                            println!(
                                "TCP checksum on packet = {:#x}, calculated = {:#x}, match = {}",
                                tcp.checksum,
                                calc,
                                tcp.checksum == calc
                            );
                        }
                        Err(err) => {
                            println!("计算 TCP checksum 错误: {:?}", err);
                        }
                    }
                }
                TransportHeader::Udp(udp) => {
                    println!(
                        "UDP src_port = {}, dst_port = {}",
                        udp.source_port, udp.destination_port
                    );
                    match udp.calc_checksum_ipv6(&ipv6, pkt.payload.slice()) {
                        Ok(calc) => {
                            println!(
                                "UDP checksum on packet = {:#x}, calculated = {:#x}, match = {}",
                                udp.checksum,
                                calc,
                                udp.checksum == calc
                            );
                        }
                        Err(err) => {
                            println!("计算 UDP checksum 错误: {:?}", err);
                        }
                    }
                }
                TransportHeader::Icmpv6(icmp6) => {
                    println!(
                        "ICMPv6 type = {:?}, checksum = {:#x}",
                        icmp6.icmp_type, icmp6.checksum
                    );

                    // 对 ICMPv6 校验，要用 Icmpv6Header 提供的方法
                    // 注意：ethparse 里 Icmpv6Header 有 update_checksum / with_checksum 方法来生成正确 checksum
                    // 但它没有直接的 “calc_checksum_ipv6(&self, ipv6, payload)” 方法
                    // 所以你可以这样做：
                    let mut icmp_hdr = icmp6.clone();
                    if icmp_hdr
                        .update_checksum(ipv6.source, ipv6.destination, pkt.payload.slice())
                        .is_ok()
                    {
                        println!(
                            "ICMPv6 calculated checksum = {:#x}, matches? = {}",
                            icmp_hdr.checksum,
                            icmp_hdr.checksum == icmp6.checksum
                        );
                    } else {
                        println!("无法更新 ICMPv6 checksum");
                    }

                    println!("继续分析 payload len: {}", pkt.payload.slice().len());
                    // handle_icmpv6_payload(pkt.payload.slice());

                    // 如果是包含内部报文（如 ICMPv6 错误消息），你还可以手动解析 pkt.payload 的一部分作为 inner IPv6 + inner transport
                    // 这里就省略了
                }
                _ => {
                    println!("其他 transport: {:?}", transport);
                }
            }
        }
    }
}
