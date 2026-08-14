use landscape::dump::eth::EthFram;
use landscape::dump::ipv4::EthIpType;
use landscape::dump::udp_packet::EthUdpType;
use pnet::datalink::{self, Channel, NetworkInterface};

use landscape_common::net::MacAddr;

#[tokio::main]
async fn main() {
    // 要绑定的网桥名
    let iface_name = "br0-test".to_string();

    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(interface_names_match)
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    println!("interface name: {:?}", interface);
    // Create a channel to receive on
    let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };
    let mac = interface.mac.map(|mac| mac.octets()).map(MacAddr::from);

    loop {
        match rx.next() {
            Ok(packet) => {
                let result = EthFram::new(packet, mac);
                match result.eth_type {
                    landscape::dump::eth::EthL3Type::Raw(_, _) => {}
                    landscape::dump::eth::EthL3Type::Ipv4(ip_frame) => {
                        println!("ip_frame data: {}", serde_json::json!(&ip_frame));
                        if let EthIpType::Udp(udp_frame) = ip_frame.protocol {
                            println!("udp checksum: {}", udp_frame.checksum);
                            match udp_frame.playload {
                                EthUdpType::Dhcp(dhcp) => {
                                    println!(
                                        "dhcp: {}",
                                        serde_json::to_string_pretty(&*dhcp).unwrap()
                                    );
                                }
                                EthUdpType::Raw(data) => {
                                    println!("udp raw payload: {:?}", data);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}
