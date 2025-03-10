use super::option_codes::IcmpV6Options;

#[derive(Debug)]
pub struct RouterSolicitation {
    /// 8 位消息类型（RS 的类型值通常为 133）
    pub msg_type: u8,
    /// 8 位消息代码（RS 的代码值为 0）
    pub msg_code: u8,
    /// 16 位校验和
    pub checksum: u16,
    /// 32 位保留字段，必须置 0
    pub reserved: u32,
    /// 可变长度的选项
    pub opts: IcmpV6Options,
}

// impl dhcproto::Decodable for RouterSolicitation {
//     fn decode(decoder: &mut dhcproto::Decoder<'_>) -> dhcproto::error::DecodeResult<Self> {
//         Ok(Self {
//             msg_type: decoder.read_u8()?.into(),
//             msg_code: decoder.read_u8()?,
//             checksum: decoder.read::<16>()?.into(),
//             reserved: decoder.read::<32>()?.into(),
//             opts: IcmpV6Options::decode(decoder)?,
//         })
//     }
// }

// impl dhcproto::Encodable for RouterSolicitation {
//     fn encode(&self, e: &mut dhcproto::Encoder<'_>) -> dhcproto::error::EncodeResult<()> {
//         e.write_u8(self.msg_type.into())?;
//         e.write_u8(self.hop_count)?;
//         e.write_slice(&self.link_addr.octets())?;
//         e.write_slice(&self.peer_addr.octets())?;
//         self.opts.encode(e)?;
//         Ok(())
//     }
// }

#[derive(Debug)]
pub struct RouterAdvertisement {
    /// 8 位消息类型（RA 的类型值通常为 134）
    pub msg_type: u8,
    /// 8 位消息代码（RA 的代码值为 0）
    pub msg_code: u8,
    /// 16 位校验和
    pub checksum: u16,
    /// 8 位当前跳数限制（Cur Hop Limit）
    pub cur_hop_limit: u8,
    /// 8 位标志字段：
    /// - Bit0: Managed Address Configuration Flag (M)
    /// - Bit1: Other Configuration Flag (O)
    /// - Bit2-7: 保留，必须置 0
    pub flags: u8,
    /// 16 位路由器寿命
    pub router_lifetime: u16,
    /// 32 位可达时间
    pub reachable_time: u32,
    /// 32 位重传定时器
    pub retrans_timer: u32,
    /// 可变长度的选项
    pub opts: IcmpV6Options,
}
