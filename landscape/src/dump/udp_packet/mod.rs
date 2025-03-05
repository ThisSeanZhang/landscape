use dhcp::DhcpEthFrame;
use pnet::util::Octets;
use serde::{Deserialize, Serialize};

pub mod dhcp;
pub mod dhcp_v6;

#[derive(Debug, Serialize, Deserialize)]
pub struct UdpEthFrame {
    pub source_port: u16,
    pub denst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub playload: EthUdpType,
}

impl UdpEthFrame {
    pub fn new(data: &[u8]) -> Option<UdpEthFrame> {
        let source_port = ((data[0] as u16) << 8) | (data[1] as u16);
        let denst_port = ((data[2] as u16) << 8) | (data[3] as u16);
        let length = ((data[4] as u16) << 8) | (data[5] as u16);
        let checksum = ((data[6] as u16) << 8) | (data[7] as u16);
        let playload = identifier_type(&data[8..]);

        Some(UdpEthFrame {
            source_port,
            denst_port,
            length,
            checksum,
            playload,
        })
    }

    pub fn get_payload_contain_checksum(&self, is_contain: bool) -> Vec<u8> {
        let mut pseudo_header: Vec<u8> = vec![];

        let payload = self.playload.convert_to_payload();
        let payload_length = (payload.len() + 8) as u16;

        pseudo_header.extend(self.source_port.octets());
        pseudo_header.extend(self.denst_port.octets());
        pseudo_header.extend(payload_length.octets());
        if is_contain {
            pseudo_header.push((self.checksum >> 8) as u8);
            pseudo_header.push((self.checksum & 0xFF) as u8);
        } else {
            pseudo_header.extend(&[0; 2]); // checksum
        }
        pseudo_header.extend(payload);

        pseudo_header
    }

    pub fn get_check_sum_part(&self) -> Vec<u8> {
        self.get_payload_contain_checksum(false)
    }

    /// ⚠ Remember to call the update_checksum function first
    pub fn as_payload(&self) -> Vec<u8> {
        self.get_payload_contain_checksum(true)
    }

    pub fn update_checksum(&mut self, checksum: u16) {
        if self.checksum == 0 {
            self.checksum = checksum;
        } else {
            if self.checksum != checksum {
                println!(
                    "Are you double-checking the checksum?: old: {:?} new: {:?}",
                    self.checksum, checksum
                );
            }
        }
    }

    pub fn get_response_empty(&self) -> UdpEthFrame {
        UdpEthFrame {
            source_port: self.denst_port,
            denst_port: self.source_port,
            length: 8,
            checksum: 0,
            playload: EthUdpType::Raw(vec![]),
        }
    }

    pub fn set_payload(&mut self, payload: EthUdpType) {
        let len = payload.convert_to_payload().len() as u16;
        self.length += len;
        self.playload = payload;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EthUdpType {
    Dhcp(Box<DhcpEthFrame>),
    Raw(Vec<u8>),
}

impl EthUdpType {
    pub fn convert_to_payload(&self) -> Vec<u8> {
        match self {
            EthUdpType::Dhcp(dhcp) => dhcp.convert_to_payload(),
            EthUdpType::Raw(data) => data.clone(),
        }
    }
}

fn identifier_type(data: &[u8]) -> EthUdpType {
    if let Some(dhcp) = DhcpEthFrame::new(data) {
        return EthUdpType::Dhcp(Box::new(dhcp));
    }

    EthUdpType::Raw(data.to_vec())
}
