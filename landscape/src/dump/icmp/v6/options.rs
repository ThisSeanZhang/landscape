use super::option_codes::IcmpV6Options;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6Type {
    // 已分配值
    Reserved,               // 0
    DestinationUnreachable, // 1 [RFC4443]
    PacketTooBig,           // 2 [RFC4443]
    TimeExceeded,           // 3 [RFC4443]
    ParameterProblem,       // 4 [RFC4443]
    // 5-99 未分配（通过 Unassigned 捕获）
    PrivateExperimentation100, // 100 [RFC4443]
    PrivateExperimentation101, // 101 [RFC4443]
    // 102-126 未分配（通过 Unassigned 捕获）
    ReservedForExpansionError, // 127 [RFC4443] Reserved for expansion of ICMPv6 error messages
    EchoRequest,               // 128 [RFC4443]
    EchoReply,                 // 129 [RFC4443]
    MulticastListenerQuery,    // 130 [RFC2710]
    MulticastListenerReport,   // 131 [RFC2710]
    MulticastListenerDone,     // 132 [RFC2710]
    RouterSolicitation,        // 133 [RFC4861]
    RouterAdvertisement,       // 134 [RFC4861]
    NeighborSolicitation,      // 135 [RFC4861]
    NeighborAdvertisement,     // 136 [RFC4861]
    RedirectMessage,           // 137 [RFC4861]
    RouterRenumbering,         // 138 [RFC2894]
    IcmpNodeInformationQuery,  // 139 [RFC4620]
    IcmpNodeInformationResponse, // 140 [RFC4620]
    InverseNeighborDiscoverySolicitation, // 141 [RFC3122]
    InverseNeighborDiscoveryAdvertisement, // 142 [RFC3122]
    Version2MulticastListenerReport, // 143 [RFC-ietf-pim-3810bis-12]
    HomeAgentAddressDiscoveryRequest, // 144 [RFC6275]
    HomeAgentAddressDiscoveryReply, // 145 [RFC6275]
    MobilePrefixSolicitation,  // 146 [RFC6275]
    MobilePrefixAdvertisement, // 147 [RFC6275]
    CertificationPathSolicitation, // 148 [RFC3971]
    CertificationPathAdvertisement, // 149 [RFC3971]
    IcmpExperimentalMobility, // 150 [RFC4065] ICMP messages utilized by experimental mobility protocols such as Seamoby
    MulticastRouterAdvertisement, // 151 [RFC4286]
    MulticastRouterSolicitation, // 152 [RFC4286]
    MulticastRouterTermination, // 153 [RFC4286]
    Fmipv6Messages,           // 154 [RFC5568]
    RplControlMessage,        // 155 [RFC6550]
    Ilnpv6LocatorUpdateMessage, // 156 [RFC6743]
    DuplicateAddressRequest,  // 157 [RFC6775]
    DuplicateAddressConfirmation, // 158 [RFC6775]
    MplControlMessage,        // 159 [RFC7731]
    ExtendedEchoRequest,      // 160 [RFC8335]
    ExtendedEchoReply,        // 161 [RFC8335]
    // 162-199 未分配（通过 Unassigned 捕获）
    PrivateExperimentation200, // 200 [RFC4443]
    PrivateExperimentation201, // 201 [RFC4443]
    // 202-254 未分配（通过 Unassigned 捕获）
    ReservedForExpansionInformational, // 255 [RFC4443] Reserved for expansion of ICMPv6 informational messages

    /// 对于未专门定义的数值（未分配的值），使用该变体携带原始 u8 数值
    Unassigned(u8),
}

impl From<u8> for Icmpv6Type {
    fn from(value: u8) -> Self {
        match value {
            0 => Icmpv6Type::Reserved,
            1 => Icmpv6Type::DestinationUnreachable,
            2 => Icmpv6Type::PacketTooBig,
            3 => Icmpv6Type::TimeExceeded,
            4 => Icmpv6Type::ParameterProblem,
            100 => Icmpv6Type::PrivateExperimentation100,
            101 => Icmpv6Type::PrivateExperimentation101,
            127 => Icmpv6Type::ReservedForExpansionError,
            128 => Icmpv6Type::EchoRequest,
            129 => Icmpv6Type::EchoReply,
            130 => Icmpv6Type::MulticastListenerQuery,
            131 => Icmpv6Type::MulticastListenerReport,
            132 => Icmpv6Type::MulticastListenerDone,
            133 => Icmpv6Type::RouterSolicitation,
            134 => Icmpv6Type::RouterAdvertisement,
            135 => Icmpv6Type::NeighborSolicitation,
            136 => Icmpv6Type::NeighborAdvertisement,
            137 => Icmpv6Type::RedirectMessage,
            138 => Icmpv6Type::RouterRenumbering,
            139 => Icmpv6Type::IcmpNodeInformationQuery,
            140 => Icmpv6Type::IcmpNodeInformationResponse,
            141 => Icmpv6Type::InverseNeighborDiscoverySolicitation,
            142 => Icmpv6Type::InverseNeighborDiscoveryAdvertisement,
            143 => Icmpv6Type::Version2MulticastListenerReport,
            144 => Icmpv6Type::HomeAgentAddressDiscoveryRequest,
            145 => Icmpv6Type::HomeAgentAddressDiscoveryReply,
            146 => Icmpv6Type::MobilePrefixSolicitation,
            147 => Icmpv6Type::MobilePrefixAdvertisement,
            148 => Icmpv6Type::CertificationPathSolicitation,
            149 => Icmpv6Type::CertificationPathAdvertisement,
            150 => Icmpv6Type::IcmpExperimentalMobility,
            151 => Icmpv6Type::MulticastRouterAdvertisement,
            152 => Icmpv6Type::MulticastRouterSolicitation,
            153 => Icmpv6Type::MulticastRouterTermination,
            154 => Icmpv6Type::Fmipv6Messages,
            155 => Icmpv6Type::RplControlMessage,
            156 => Icmpv6Type::Ilnpv6LocatorUpdateMessage,
            157 => Icmpv6Type::DuplicateAddressRequest,
            158 => Icmpv6Type::DuplicateAddressConfirmation,
            159 => Icmpv6Type::MplControlMessage,
            160 => Icmpv6Type::ExtendedEchoRequest,
            161 => Icmpv6Type::ExtendedEchoReply,
            200 => Icmpv6Type::PrivateExperimentation200,
            201 => Icmpv6Type::PrivateExperimentation201,
            255 => Icmpv6Type::ReservedForExpansionInformational,
            // 对于未匹配到上述已定义的数值，均使用 Unassigned 捕获
            other => Icmpv6Type::Unassigned(other),
        }
    }
}

impl From<Icmpv6Type> for u8 {
    fn from(icmp: Icmpv6Type) -> Self {
        match icmp {
            Icmpv6Type::Reserved => 0,
            Icmpv6Type::DestinationUnreachable => 1,
            Icmpv6Type::PacketTooBig => 2,
            Icmpv6Type::TimeExceeded => 3,
            Icmpv6Type::ParameterProblem => 4,
            Icmpv6Type::PrivateExperimentation100 => 100,
            Icmpv6Type::PrivateExperimentation101 => 101,
            Icmpv6Type::ReservedForExpansionError => 127,
            Icmpv6Type::EchoRequest => 128,
            Icmpv6Type::EchoReply => 129,
            Icmpv6Type::MulticastListenerQuery => 130,
            Icmpv6Type::MulticastListenerReport => 131,
            Icmpv6Type::MulticastListenerDone => 132,
            Icmpv6Type::RouterSolicitation => 133,
            Icmpv6Type::RouterAdvertisement => 134,
            Icmpv6Type::NeighborSolicitation => 135,
            Icmpv6Type::NeighborAdvertisement => 136,
            Icmpv6Type::RedirectMessage => 137,
            Icmpv6Type::RouterRenumbering => 138,
            Icmpv6Type::IcmpNodeInformationQuery => 139,
            Icmpv6Type::IcmpNodeInformationResponse => 140,
            Icmpv6Type::InverseNeighborDiscoverySolicitation => 141,
            Icmpv6Type::InverseNeighborDiscoveryAdvertisement => 142,
            Icmpv6Type::Version2MulticastListenerReport => 143,
            Icmpv6Type::HomeAgentAddressDiscoveryRequest => 144,
            Icmpv6Type::HomeAgentAddressDiscoveryReply => 145,
            Icmpv6Type::MobilePrefixSolicitation => 146,
            Icmpv6Type::MobilePrefixAdvertisement => 147,
            Icmpv6Type::CertificationPathSolicitation => 148,
            Icmpv6Type::CertificationPathAdvertisement => 149,
            Icmpv6Type::IcmpExperimentalMobility => 150,
            Icmpv6Type::MulticastRouterAdvertisement => 151,
            Icmpv6Type::MulticastRouterSolicitation => 152,
            Icmpv6Type::MulticastRouterTermination => 153,
            Icmpv6Type::Fmipv6Messages => 154,
            Icmpv6Type::RplControlMessage => 155,
            Icmpv6Type::Ilnpv6LocatorUpdateMessage => 156,
            Icmpv6Type::DuplicateAddressRequest => 157,
            Icmpv6Type::DuplicateAddressConfirmation => 158,
            Icmpv6Type::MplControlMessage => 159,
            Icmpv6Type::ExtendedEchoRequest => 160,
            Icmpv6Type::ExtendedEchoReply => 161,
            Icmpv6Type::PrivateExperimentation200 => 200,
            Icmpv6Type::PrivateExperimentation201 => 201,
            Icmpv6Type::ReservedForExpansionInformational => 255,
            Icmpv6Type::Unassigned(n) => n,
        }
    }
}

pub enum Icmpv6Message {
    RouterSolicitation(RouterSolicitation),
    RouterAdvertisement(RouterAdvertisement),
    Unassigned(u8, Vec<u8>),
}

impl dhcproto::Decodable for Icmpv6Message {
    fn decode(decoder: &mut dhcproto::Decoder<'_>) -> dhcproto::error::DecodeResult<Self> {
        let msg_type = decoder.peek_u8()?.into();

        Ok(match msg_type {
            Icmpv6Type::RouterSolicitation => {
                Icmpv6Message::RouterSolicitation(RouterSolicitation::decode(decoder)?)
            }
            // Icmpv6Type::RouterAdvertisement => RouterAdvertisement::decode(decoder)?,
            msg_type => Icmpv6Message::Unassigned(msg_type.into(), decoder.buffer().to_vec()),
        })
    }
}

#[derive(Debug)]
pub struct RouterSolicitation {
    /// 8 位消息类型（RS 的类型值通常为 133）
    pub msg_type: Icmpv6Type,
    /// 8 位消息代码（RS 的代码值为 0）
    pub msg_code: u8,
    /// 16 位校验和
    pub checksum: u16,
    /// 32 位保留字段，必须置 0
    pub reserved: u32,
    /// 可变长度的选项
    pub opts: IcmpV6Options,
}

impl dhcproto::Decodable for RouterSolicitation {
    fn decode(decoder: &mut dhcproto::Decoder<'_>) -> dhcproto::error::DecodeResult<Self> {
        Ok(Self {
            msg_type: decoder.read_u8()?.into(),
            msg_code: decoder.read_u8()?,
            checksum: decoder.read_u16()?,
            reserved: decoder.read_u32()?,
            opts: IcmpV6Options::decode(decoder)?,
        })
    }
}
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

impl dhcproto::Decodable for RouterAdvertisement {
    fn decode(decoder: &mut dhcproto::Decoder<'_>) -> dhcproto::error::DecodeResult<Self> {
        Ok(Self {
            msg_type: decoder.read_u8()?.into(),
            msg_code: decoder.read_u8()?,
            checksum: decoder.read_u16()?,
            cur_hop_limit: decoder.read_u8()?,
            flags: decoder.read_u8()?,
            router_lifetime: decoder.read_u16()?,
            reachable_time: decoder.read_u32()?,
            retrans_timer: decoder.read_u32()?,
            opts: IcmpV6Options::decode(decoder)?,
        })
    }
}
