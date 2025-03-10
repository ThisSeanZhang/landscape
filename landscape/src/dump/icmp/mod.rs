use serde::{Deserialize, Serialize};

pub mod v6;

#[derive(Debug, Serialize, Deserialize)]
pub struct IcmpEthFrame {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u32,
    pub rest: Vec<u8>,
}

impl IcmpEthFrame {
    pub fn new(data: &[u8]) -> Option<IcmpEthFrame> {
        if data.len() < 6 {
            return None;
        }
        let icmp_type = data[0];
        let code = data[1];
        let checksum = ((data[2] as u32) << 8)
            | ((data[3] as u32) << 8)
            | ((data[4] as u32) << 8)
            | (data[5] as u32);
        let rest = data[6..].to_vec();
        Some(IcmpEthFrame { icmp_type, code, checksum, rest })
    }
}
