use std::net::Ipv4Addr;

use options::{DhcpOptionMessageType, DhcpOptions};
use pnet::util::Octets;
use serde::{Deserialize, Serialize};

pub mod options;

use landscape_common::net::MacAddr;

const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

#[derive(Debug, Serialize, Deserialize)]
pub struct DhcpEthFrame {
    /// 操作码 (op): 1字节，1表示请求，2表示回复。
    pub op: u8,
    /// 硬件类型 (htype): 1字节，表示网络类型（1表示以太网）
    pub htype: u8,
    /// 硬件地址长度 (hlen): 1字节，通常为6（MAC地址长度）
    pub hlen: u8,
    /// 跳数 (hops): 1字节，初始为0。
    pub hops: u8,
    /// 事务ID (xid): 4字节，唯一标识请求和响应的ID。
    pub xid: u32,
    /// 客户端 到目前的等待时间 可以设置为 0
    pub secs: u16,
    /// 是否以广播的方式进行回应
    /// 高位设置为 1 表示使用组播的方式进行回应
    /// 只有第一位, 其他为保留
    pub flags: u16,
    /// Client IP address
    /// 客户端的当前地址 如果已经分配了 填写目前分配的地址 (续期的时候将使用这个)
    pub ciaddr: Ipv4Addr,
    /// Your IP address
    /// 服务端分配给客户端的 IP 地址, 客户端请求的时候设置为空
    pub yiaddr: Ipv4Addr,
    /// Server IP address
    /// 服务端响应时候填充自己的 ip 地址, 客户端请求设置为空
    pub siaddr: Ipv4Addr,
    /// Gateway IP address
    /// DHCP 中继的时候使用
    pub giaddr: Ipv4Addr,
    /// Client hardware address
    pub chaddr: MacAddr,
    #[serde(skip_serializing)]
    /// size 64
    pub sname: Vec<u8>,
    #[serde(skip_serializing)]
    /// size 128
    pub file: Vec<u8>,
    pub magic_cookie: u32,
    pub options: DhcpOptionFrame,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpOptionFrame {
    pub message_type: DhcpOptionMessageType,
    pub options: Vec<DhcpOptions>,
    pub end: Vec<u8>,
}

impl DhcpOptionFrame {
    pub fn new(data: &[u8]) -> Option<Self> {
        let mut options = DhcpOptions::from_data(data);
        // 从 Options 中提取 MessageType (Option 53)，并移除它
        let message_type_position =
            options.iter().position(|opt| matches!(opt, DhcpOptions::MessageType(_)))?;

        // 提取 MessageType 选项
        let message_type =
            if let DhcpOptions::MessageType(mt) = options.remove(message_type_position) {
                mt
            } else {
                return None;
            };

        // 从 Options 中提取 MessageType (Option 53)，并移除它
        let end_position = options.iter().position(|opt| matches!(opt, DhcpOptions::End(_)))?;

        // 提取 MessageType 选项
        let end = if let DhcpOptions::End(data) = options.remove(end_position) {
            data
        } else {
            return None;
        };

        // 返回填充好的 DhcpOptionFrame，其中 options 已经不包含 MessageType
        Some(DhcpOptionFrame { message_type, options, end })
    }

    pub fn convert_to_payload(&self) -> Vec<u8> {
        let mut options = DhcpOptions::MessageType(self.message_type.clone()).decode_option();
        for op in self.options.iter() {
            let u8_data = op.decode_option();
            options.extend(u8_data);
        }
        let pad_len = options.len() % 8;
        if pad_len != 0 {
            let target_length = (options.len() + 7) / 8 * 8;
            options.resize(target_length, 0);
        }
        options.extend(self.end.clone());
        options
    }

    pub fn set_message_type(&mut self, new_message_type: DhcpOptionMessageType) {
        self.message_type = new_message_type;
    }

    pub fn has_option(&self, index: u8) -> Option<DhcpOptions> {
        for opt in self.options.iter() {
            if opt.get_index() == index {
                return Some(opt.clone());
            }
        }
        None
    }

    pub fn update_or_create_option(&mut self, new_option: DhcpOptions) {
        let new_index = new_option.get_index();
        if let Some(pos) = self.options.iter().position(|opt| opt.get_index() == new_index) {
            self.options[pos] = new_option;
        } else {
            self.options.push(new_option);
        }
    }

    pub fn get_renew_time(&self) -> Option<(u64, u64, u64)> {
        let Some(DhcpOptions::AddressLeaseTime(lease_time)) = self.has_option(51) else {
            return None;
        };
        let renew_time = if let Some(DhcpOptions::Renewal(time)) = self.has_option(58) {
            time
        } else {
            lease_time / 2
        };
        let rebinding_time = if let Some(DhcpOptions::Rebinding(time)) = self.has_option(59) {
            time
        } else {
            lease_time * 7 / 8
        };
        return Some((renew_time as u64, rebinding_time as u64, lease_time as u64));
    }
}

impl DhcpEthFrame {
    pub fn new(data: &[u8]) -> Option<Self> {
        if data.len() < 240 {
            return None;
        }

        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];

        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let secs = u16::from_be_bytes([data[8], data[9]]);
        let flags = u16::from_be_bytes([data[10], data[11]]);

        let ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        let giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        let chaddr = MacAddr::new(data[28], data[29], data[30], data[31], data[32], data[33]);

        let sname = data[44..108].to_vec();
        let file = data[108..236].to_vec();

        let magic_cookie = u32::from_be_bytes([data[236], data[237], data[238], data[239]]);

        if magic_cookie != DHCP_MAGIC_COOKIE {
            return None;
        }

        let Some(options) = DhcpOptionFrame::new(&data[240..]) else { return None };
        Some(DhcpEthFrame {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            magic_cookie,
            options,
        })
    }

    pub fn is_broaddcast(&self) -> bool {
        self.flags == 0x8000
    }

    pub fn convert_to_payload(&self) -> Vec<u8> {
        let mut result = vec![];
        result.push(self.op);
        result.push(self.htype);
        result.push(self.hlen);
        result.push(self.hops);

        result.extend_from_slice(&self.xid.octets());
        result.extend_from_slice(&self.secs.octets());
        result.extend_from_slice(&self.flags.octets());

        result.extend_from_slice(&self.ciaddr.octets());
        result.extend_from_slice(&self.yiaddr.octets());
        result.extend_from_slice(&self.siaddr.octets());
        result.extend_from_slice(&self.giaddr.octets());

        result.extend_from_slice(&self.chaddr.octets());
        result.extend_from_slice(&[0; 202]); // 64 + 128 + 10

        result.extend_from_slice(&self.magic_cookie.octets());

        result.extend(self.options.convert_to_payload());
        result
    }
}

pub fn offer_options() -> DhcpOptionFrame {
    let mut options = vec![];
    options.push(DhcpOptions::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));

    options.push(DhcpOptions::Router(Ipv4Addr::new(10, 255, 255, 1)));
    options.push(DhcpOptions::AddressLeaseTime(40));
    options.push(DhcpOptions::ServerIdentifier(Ipv4Addr::new(10, 255, 255, 1)));

    options.push(DhcpOptions::DomainNameServer(vec![Ipv4Addr::new(10, 255, 255, 1)]));
    return DhcpOptionFrame {
        message_type: options::DhcpOptionMessageType::Offer,
        options,
        end: vec![255],
    };
}

pub fn ack_options() -> DhcpOptionFrame {
    //1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42
    let mut options = vec![];
    // 1
    options.push(DhcpOptions::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));
    //28
    // options.push(DhcpOptions::BroadcastAddr(Ipv4Addr::new(255, 255, 255, 0)));
    // 2
    // options.push(DhcpOptions::TimeOffset(100));

    // 3
    options.push(DhcpOptions::Router(Ipv4Addr::new(10, 255, 255, 1)));
    // 15
    // options.push(DhcpOptions::DomainName("lan".to_string()));

    // 6
    options.push(DhcpOptions::DomainNameServer(vec![Ipv4Addr::new(10, 255, 255, 1)]));
    // 12
    // options.push(DhcpOptions::Hostname("pc2".to_string()));

    options.push(DhcpOptions::AddressLeaseTime(40));
    options.push(DhcpOptions::ServerIdentifier(Ipv4Addr::new(10, 255, 255, 1)));

    return DhcpOptionFrame {
        message_type: options::DhcpOptionMessageType::Ack,
        options,
        end: vec![255],
    };
}

/// 客户端发起的 DHCP 请求 option 值, 现在默认这些
/// TODO: 加入设置的 80 或者其他的 option 用于 ipoe 的申请
pub fn discover_options(ciaddr: Option<Ipv4Addr>, hostname: String) -> DhcpOptionFrame {
    let mut options = vec![];
    // DHCP Message Type: Discover (Option 53)
    // options.push(DhcpOptions::MessageType(options::DhcpOptionMessageType::Discover));

    // Client Identifier (optional, 可以是 MAC 地址，或者可以不加)
    // options.push(DhcpOptions::ClientIdentifier(frame.chaddr.clone()));

    // 用于 重新续期已有的 ip 地址
    if let Some(ciaddr) = ciaddr {
        options.push(DhcpOptions::RequestedIpAddress(ciaddr));
    }
    options.push(DhcpOptions::Hostname(hostname));

    options.push(get_default_request_list());

    return DhcpOptionFrame {
        message_type: options::DhcpOptionMessageType::Discover,
        options,
        end: vec![255],
    };
}

pub fn gen_discover(
    xid: u32,
    mac_addr: MacAddr,
    ciaddr: Option<Ipv4Addr>,
    hostname: String,
) -> DhcpEthFrame {
    // Flags: Broadcast
    let flags = if ciaddr.is_none() { 0x8000 } else { 0 };
    let discover = DhcpEthFrame {
        op: 1,    // Boot Request
        htype: 1, // Hardware type: Ethernet
        hlen: 6,  // Hardware address length
        hops: 0,  // Hops
        xid,      // Transaction ID (随机数)
        secs: 0,  // Elapsed time
        flags,
        ciaddr: ciaddr.clone().unwrap_or(Ipv4Addr::UNSPECIFIED), // Client IP address (initially 0)
        yiaddr: Ipv4Addr::new(0, 0, 0, 0),                       // 'Your' IP address (from server)
        siaddr: Ipv4Addr::new(0, 0, 0, 0),                       // Server IP address
        giaddr: Ipv4Addr::new(0, 0, 0, 0),                       // Gateway IP address
        chaddr: mac_addr,                                        // Client hardware address
        sname: vec![0; 64],                                      // Server host name (optional)
        file: vec![0; 128],                                      // Boot file name (optional)
        magic_cookie: DHCP_MAGIC_COOKIE,                         // DHCP magic cookie
        options: discover_options(ciaddr, hostname),             // 使用上面定义的 discover options
    };
    discover
}

/// 获得 offer
pub fn gen_offer(frame: DhcpEthFrame) -> DhcpEthFrame {
    let offer = DhcpEthFrame {
        op: 2,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: frame.xid,
        secs: 0,
        flags: 0,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0),
        yiaddr: Ipv4Addr::new(10, 255, 255, 10),
        siaddr: Ipv4Addr::new(10, 255, 255, 1),
        giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: frame.chaddr,
        sname: [0; 64].to_vec(),
        file: [0; 128].to_vec(),
        magic_cookie: frame.magic_cookie,
        options: offer_options(),
    };
    offer
}

/// Requested Parameters (Option 55) - 常见的请求参数
pub fn get_default_request_list() -> DhcpOptions {
    DhcpOptions::ParameterRequestList(vec![
        1,   // Subnet Mask
        3,   // Router
        6,   // Domain Name Server
        15,  // Domain Name
        26,  // Interface MTU
        28,  // Broadcast Address
        12,  // Host Name
        42,  // NTP Servers
        51,  // Address Lease Time
        119, // Domain Search
    ])
}

pub fn gen_request(
    xid: u32,
    mac_addr: MacAddr,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    mut options: DhcpOptionFrame,
) -> DhcpEthFrame {
    // 增加 所要使用的 ip 地址 option
    options.options.push(DhcpOptions::ClassIdentifier("MSFT 5.0".as_bytes().to_vec()));
    let mut client_identifier = mac_addr.octets().to_vec();
    client_identifier.insert(0, 1);
    options.options.push(DhcpOptions::ClientIdentifier(client_identifier));
    options.options.push(get_default_request_list());

    options.message_type = DhcpOptionMessageType::Request;

    // Flags: Broadcast
    let flags = if ciaddr.is_unspecified() {
        // CI addr 为空 那就设置 Option
        options.options.push(DhcpOptions::RequestedIpAddress(yiaddr));
        0x8000
    } else {
        0
    };
    let offer = DhcpEthFrame {
        op: 1,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags,
        ciaddr,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: mac_addr,
        sname: [0; 64].to_vec(),
        file: [0; 128].to_vec(),
        magic_cookie: DHCP_MAGIC_COOKIE,
        options,
    };
    offer
}
