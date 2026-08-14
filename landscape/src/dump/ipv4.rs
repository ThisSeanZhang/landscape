use core::panic;
use std::net::Ipv4Addr;

use pnet::util::Octets;
use serde::{Deserialize, Serialize};

use super::{icmp::IcmpEthFrame, udp_packet::UdpEthFrame};

pub fn split_u8_by_index(byte: u8, index: usize) -> (u8, u8) {
    if index > 7 {
        panic!("index out of range");
    }
    (byte >> index, byte & ((1 << index) - 1))
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Ipv4EthFrame {
    // 4 bit
    pub version: u8,
    // 4 bit
    pub head_len: u8,
    // 6 bit
    pub dscp: u8,
    // 2 bit
    pub ecn: u8,

    pub total_length: usize,

    pub ident: u16,

    // 3 bit
    pub flags: u8,
    // 13 bit
    pub fragment_offset: u16,
    pub ttl: u8,
    // u8
    pub protocol: EthIpType,
    pub checksum: u16,
    pub source_addr: Ipv4Addr,
    pub denst_addr: Ipv4Addr,
    pub options: Option<Vec<u8>>,
}

impl Ipv4EthFrame {
    pub fn new(data: &[u8]) -> Option<Ipv4EthFrame> {
        // println!("{data:?}");
        if data.len() < 20 {
            return None;
        }
        let (version, head_len) = split_u8_by_index(data[0], 4);
        let real_head_length = head_len * 4;
        if data.len() < real_head_length as usize {
            return None;
        }
        let (dscp, ecn) = split_u8_by_index(data[1], 2);
        let total_length = (((data[2] as u16) << 8) | (data[3] as u16)) as usize;
        let ident = ((data[4] as u16) << 8) | (data[5] as u16);
        let (flags, fragment_offset) = split_u8_by_index(data[6], 5);
        let fragment_offset = ((fragment_offset as u16) << 8) | (data[7] as u16);
        let ttl = data[8];
        let protocol = EthIpType::from_u8(data[9], &data[(real_head_length as usize)..]);
        let checksum = ((data[10] as u16) << 8) | (data[11] as u16);
        let source_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let denst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let options = None;
        Some(Ipv4EthFrame {
            version,
            head_len,
            dscp,
            ecn,
            total_length,
            ident,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            source_addr,
            denst_addr,
            options,
        })
    }

    pub fn get_header_contain_checksum(&self, is_contain: bool) -> Vec<u8> {
        let checksum = if is_contain { self.checksum } else { 0 };
        let mut header = vec![
            (self.version << 4) | (self.head_len & 0x0F),
            (self.dscp << 2) | (self.ecn & 0x03),
            (self.total_length >> 8) as u8,
            (self.total_length & 0xFF) as u8,
            (self.ident >> 8) as u8,
            (self.ident & 0xFF) as u8,
            (self.flags << 5) | ((self.fragment_offset >> 8) & 0x1F) as u8,
            (self.fragment_offset & 0xFF) as u8,
            self.ttl,
            self.protocol.get_val(),
            (checksum >> 8) as u8,
            (checksum & 0xFF) as u8,
        ];
        header.extend(self.source_addr.octets());
        header.extend(self.denst_addr.octets());
        header
    }
    /// 内部协议的 checksum
    pub fn caculate_protocol_checksum(&mut self) -> u16 {
        self.protocol.caculate_checksum(&self.source_addr, &self.denst_addr)
    }

    pub fn as_payload(&self) -> Vec<u8> {
        let mut header = self.get_header_contain_checksum(true);
        header.extend(self.protocol.as_payload());
        header
    }

    pub fn caculate_checksum(&mut self) -> u16 {
        // Create a byte array to hold the header fields
        let mut header = self.get_header_contain_checksum(false);

        // If options are present, add them to the header
        if let Some(ref opts) = self.options {
            header.extend(opts);
        }

        println!("self ip check: {header:?}");
        // Ensure header length is even by padding with a zero byte if necessary
        if !header.len().is_multiple_of(2) {
            header.push(0);
        }
        checksum(&header)
    }

    pub fn update_checksum(&mut self, checksum: u16) {
        if self.checksum == 0 {
            self.protocol.caculate_checksum(&self.source_addr, &self.denst_addr);
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

    pub fn get_response(&self) -> Ipv4EthFrame {
        Ipv4EthFrame {
            version: self.version,
            head_len: self.head_len,
            dscp: self.dscp,
            ecn: self.ecn,
            total_length: 20,
            ident: 0x1234,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: EthIpType::Raw(0, vec![]),
            checksum: 0,
            source_addr: self.denst_addr,
            denst_addr: self.source_addr,
            options: None,
        }
    }

    pub fn set_payload(&mut self, protocol: EthIpType) {
        self.total_length += protocol.as_payload().len();
        self.protocol = protocol;
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum EthIpType {
    Icmp(Box<IcmpEthFrame>) = 0x1,
    Ipv4(Box<Ipv4EthFrame>) = 0x4,
    Tcp(Vec<u8>) = 0x6,
    Udp(Box<UdpEthFrame>) = 0x11,
    Ipv6(Box<EthIpType>) = 0x29,
    Raw(u8, Vec<u8>) = 0xff,
}
impl EthIpType {
    pub fn from_u8(value: u8, data: &[u8]) -> Self {
        let end = match value {
            0x01 => IcmpEthFrame::new(data).map(|ic| EthIpType::Icmp(Box::new(ic))),
            0x04 => Ipv4EthFrame::new(data).map(|result| EthIpType::Ipv4(Box::new(result))),
            0x11 => UdpEthFrame::new(data).map(|result| EthIpType::Udp(Box::new(result))),
            _ => None,
        };

        if let Some(result) = end {
            result
        } else {
            EthIpType::Raw(value, data.to_vec())
        }
    }

    pub fn caculate_checksum(&mut self, source_addr: &Ipv4Addr, denst_addr: &Ipv4Addr) -> u16 {
        match self {
            EthIpType::Icmp(_) => todo!(),
            EthIpType::Ipv4(_) => todo!(),
            EthIpType::Tcp(_) => todo!(),
            EthIpType::Udp(udp) => {
                let mut checksum_vec = vec![];
                checksum_vec.extend(source_addr.octets());
                checksum_vec.extend(denst_addr.octets());

                checksum_vec.push(0);
                checksum_vec.push(17);
                checksum_vec.extend(udp.length.octets());

                checksum_vec.extend(udp.get_check_sum_part());

                println!("print pseudo_header: {checksum_vec:?}");
                let check = checksum(&checksum_vec);
                udp.checksum = check;
                check
            }
            EthIpType::Ipv6(_) => todo!(),
            EthIpType::Raw(_, _) => todo!(),
        }
    }

    pub fn as_payload(&self) -> Vec<u8> {
        match self {
            EthIpType::Icmp(_) => todo!(),
            EthIpType::Ipv4(_) => todo!(),
            EthIpType::Tcp(_) => todo!(),
            EthIpType::Udp(udp) => udp.as_payload(),
            EthIpType::Ipv6(_) => todo!(),
            EthIpType::Raw(_, _) => todo!(),
        }
    }

    pub fn get_val(&self) -> u8 {
        match self {
            EthIpType::Icmp(_) => 0x1,
            EthIpType::Ipv4(_) => 0x4,
            EthIpType::Tcp(_) => 0x6,
            EthIpType::Udp(_) => 0x11,
            EthIpType::Ipv6(_) => 0x29,
            EthIpType::Raw(val, _) => *val,
        }
    }
}

fn checksum(mut data: &[u8]) -> u16 {
    let mut sum = 0u32;

    // Sum all 16-bit words
    while data.len() >= 2 {
        let word = u16::from_be_bytes([data[0], data[1]]) as u32;
        sum = sum.wrapping_add(word);
        data = &data[2..];
    }

    // If there's a leftover byte, pad with zero and add
    if let Some(&byte) = data.first() {
        let word = (byte as u32) << 8;
        sum = sum.wrapping_add(word);
    }

    // Fold 32-bit sum to 16 bits and add carry
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test1() {
        let a = crate::dump::ipv4::split_u8_by_index(16, 2);
        println!("{a:?}")
    }
}
