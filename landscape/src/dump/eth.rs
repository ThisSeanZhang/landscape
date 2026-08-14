use landscape_common::net::MacAddr;
use serde::{Deserialize, Serialize};

use super::ipv4::Ipv4EthFrame;

#[derive(Debug, Serialize, Deserialize)]
pub struct EthFram {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub vlans: Option<Vec<VlanInfo>>,
    pub eth_type: EthL3Type,
    pub eth_len: Option<u16>,
    // payload: Vec<u8>,
    pub direction: PacketDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketDirection {
    UnKnow,
    IN,
    OUT,
    LOOP,
}

/// In order to allow Ethernet II and IEEE 802.3 framing to be used on the same Ethernet segment,
/// a unifying standard, IEEE 802.3x-1997,
/// was introduced that required that EtherType values be greater than or equal to 1536.
/// That value was chosen because the maximum length (MTU) of the data field of
/// an Ethernet 802.3 frame is 1500 bytes and 1536 is equivalent to the number 600 in the hexadecimal numeral system.
/// Thus, values of 1500 and below for this field indicate that the field
/// is used as the size of the payload of the Ethernet frame while values of 1536
/// and above indicate that the field is used to represent an EtherType.
/// The interpretation of values 1501–1535, inclusive, is undefined.[1]
#[derive(Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum EthL3Type {
    Raw(u16, Vec<u8>) = 0x0000,
    Ipv4(Box<Ipv4EthFrame>) = 0x0800,
}

impl EthL3Type {
    pub fn from_u16(value: u16, data: &[u8]) -> Self {
        let end = match value {
            0x0800 => Ipv4EthFrame::new(data).map(|result| EthL3Type::Ipv4(Box::new(result))),
            _ => None,
        };
        if let Some(result) = end {
            result
        } else {
            EthL3Type::Raw(value, data.to_vec())
        }
    }
}

impl EthFram {
    pub fn new(data: &[u8], mac: Option<MacAddr>) -> EthFram {
        let length = data.len();

        let mut cursor: usize = 0;
        let (mac, is_tunl) = if let Some(mac) = mac {
            (mac, false)
        } else {
            (MacAddr::new(0, 0, 0, 0, 0, 0), false)
        };
        // let data = value.data;

        let (src_mac, dst_mac, direction, eth_type) = if is_tunl {
            (
                MacAddr::new(0, 0, 0, 0, 0, 0),
                MacAddr::new(0, 0, 0, 0, 0, 0),
                PacketDirection::UnKnow,
                0,
            )
        } else {
            // 以太网帧 目标MAC在前,IP协议中目标地址在后,两者相反
            // MAC 目标地址	 MAC 源地址
            let mut dst_mac = [0u8; 6];
            dst_mac.copy_from_slice(&data[cursor..6]);
            let dst_mac = MacAddr::from(dst_mac);
            cursor += 6;

            let mut src_mac = [0u8; 6];
            src_mac.copy_from_slice(&data[cursor..12]);
            let src_mac = MacAddr::from(src_mac);
            cursor += 6;

            let direction = if src_mac == mac {
                if dst_mac == mac {
                    PacketDirection::LOOP
                } else {
                    PacketDirection::OUT
                }
            } else {
                if dst_mac == mac {
                    PacketDirection::IN
                } else {
                    PacketDirection::UnKnow
                }
            };

            let eth_type = (data[cursor] as u16) << 8;
            let eth_type = eth_type | (data[cursor + 1] as u16);

            cursor += 2;
            (src_mac, dst_mac, direction, eth_type)
        };
        let eth_len = Some((length - cursor) as u16);
        let eth_type = EthL3Type::from_u16(eth_type, &data[cursor..]);
        // let payload = data[cursor..].to_vec();
        // let mut frames = vec![];
        // TODO
        EthFram {
            dst_mac,
            src_mac,
            vlans: None,
            eth_type,
            eth_len,
            // payload,
            direction,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlanInfo {
    tpid: u16, // Tag Protocol Identifier，一般为0x8100
    tci: u16,  // Tag Control Information，包括优先级和VLAN ID
}
