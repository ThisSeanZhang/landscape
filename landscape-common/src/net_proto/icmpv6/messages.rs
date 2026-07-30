use std::net::Ipv6Addr;

use bytes::{Buf, BytesMut};
use deku::{DekuContainerRead, DekuContainerWrite, DekuRead, DekuReader, DekuWrite, DekuWriter};

use super::options::{IcmpV6Option, IcmpV6Options};
use crate::net_proto::error::NetProtoError;
use crate::net_proto::{LandscapeCodec, NetProtoCodec};

// ─── Icmpv6Type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6Type {
    Reserved,                              // 0
    DestinationUnreachable,                // 1
    PacketTooBig,                          // 2
    TimeExceeded,                          // 3
    ParameterProblem,                      // 4
    PrivateExperimentation100,             // 100
    PrivateExperimentation101,             // 101
    ReservedForExpansionError,             // 127
    EchoRequest,                           // 128
    EchoReply,                             // 129
    MulticastListenerQuery,                // 130
    MulticastListenerReport,               // 131
    MulticastListenerDone,                 // 132
    RouterSolicitation,                    // 133
    RouterAdvertisement,                   // 134
    NeighborSolicitation,                  // 135
    NeighborAdvertisement,                 // 136
    RedirectMessage,                       // 137
    RouterRenumbering,                     // 138
    IcmpNodeInformationQuery,              // 139
    IcmpNodeInformationResponse,           // 140
    InverseNeighborDiscoverySolicitation,  // 141
    InverseNeighborDiscoveryAdvertisement, // 142
    Version2MulticastListenerReport,       // 143
    HomeAgentAddressDiscoveryRequest,      // 144
    HomeAgentAddressDiscoveryReply,        // 145
    MobilePrefixSolicitation,              // 146
    MobilePrefixAdvertisement,             // 147
    CertificationPathSolicitation,         // 148
    CertificationPathAdvertisement,        // 149
    IcmpExperimentalMobility,              // 150
    MulticastRouterAdvertisement,          // 151
    MulticastRouterSolicitation,           // 152
    MulticastRouterTermination,            // 153
    Fmipv6Messages,                        // 154
    RplControlMessage,                     // 155
    Ilnpv6LocatorUpdateMessage,            // 156
    DuplicateAddressRequest,               // 157
    DuplicateAddressConfirmation,          // 158
    MplControlMessage,                     // 159
    ExtendedEchoRequest,                   // 160
    ExtendedEchoReply,                     // 161
    PrivateExperimentation200,             // 200
    PrivateExperimentation201,             // 201
    ReservedForExpansionInformational,     // 255
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

// ─── Helper functions for deku custom reader / writer ───────────────────────

fn read_icmpv6_options<R: std::io::Read + std::io::Seek>(
    reader: &mut deku::reader::Reader<R>,
) -> Result<IcmpV6Options, deku::DekuError> {
    let mut opts = IcmpV6Options::new();
    while !reader.end() {
        match IcmpV6Option::from_reader_with_ctx(reader, ()) {
            Ok(opt) => opts.insert(opt),
            Err(_) => break,
        }
    }
    Ok(opts)
}

fn write_icmpv6_options<W: std::io::Write + std::io::Seek>(
    writer: &mut deku::writer::Writer<W>,
    opts: &IcmpV6Options,
) -> Result<(), deku::DekuError> {
    for opt in opts.iter() {
        opt.to_writer(writer, ())?;
    }
    Ok(())
}

// ─── Message structs ────────────────────────────────────────────────────────

#[derive(Debug, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct RouterSolicitation {
    pub msg_type: u8,
    pub msg_code: u8,
    pub checksum: u16,
    pub reserved: u32,
    #[deku(
        reader = "read_icmpv6_options(deku::reader)",
        writer = "write_icmpv6_options(deku::writer, &self.opts)"
    )]
    pub opts: IcmpV6Options,
}

#[derive(Debug, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct RouterAdvertisement {
    pub msg_type: u8,
    pub msg_code: u8,
    pub checksum: u16,
    pub cur_hop_limit: u8,
    pub flags: u8,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    #[deku(
        reader = "read_icmpv6_options(deku::reader)",
        writer = "write_icmpv6_options(deku::writer, &self.opts)"
    )]
    pub opts: IcmpV6Options,
}

impl RouterAdvertisement {
    pub fn new(flags: u8, opts: IcmpV6Options) -> Self {
        Self {
            msg_type: 134, // RouterAdvertisement
            msg_code: 0,
            checksum: 0,
            cur_hop_limit: 64,
            flags,
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            opts,
        }
    }
}

#[derive(Debug, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct NeighborSolicitation {
    pub msg_type: u8,
    pub msg_code: u8,
    pub checksum: u16,
    pub reserved: u32,
    pub target_address: [u8; 16],
    #[deku(
        reader = "read_icmpv6_options(deku::reader)",
        writer = "write_icmpv6_options(deku::writer, &self.opts)"
    )]
    pub opts: IcmpV6Options,
}

impl NeighborSolicitation {
    pub fn new(target_address: Ipv6Addr, opts: IcmpV6Options) -> Self {
        Self {
            msg_type: 135, // NeighborSolicitation
            msg_code: 0,
            checksum: 0,
            reserved: 0,
            target_address: target_address.octets(),
            opts,
        }
    }

    pub fn target_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.target_address)
    }
}

#[derive(Debug, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct NeighborAdvertisement {
    pub msg_type: u8,
    pub msg_code: u8,
    pub checksum: u16,
    pub flags: u32,
    pub target_address: [u8; 16],
    #[deku(
        reader = "read_icmpv6_options(deku::reader)",
        writer = "write_icmpv6_options(deku::writer, &self.opts)"
    )]
    pub opts: IcmpV6Options,
}

impl NeighborAdvertisement {
    pub fn new(flags: u32, target_address: Ipv6Addr, opts: IcmpV6Options) -> Self {
        Self {
            msg_type: 136, // NeighborAdvertisement
            msg_code: 0,
            checksum: 0,
            flags,
            target_address: target_address.octets(),
            opts,
        }
    }

    pub fn solicited(target_address: Ipv6Addr, override_flag: bool, opts: IcmpV6Options) -> Self {
        let mut flags = 0u32;
        flags |= 1 << 30; // S (Solicited)
        if override_flag {
            flags |= 1 << 29; // O (Override)
        }
        Self::new(flags, target_address, opts)
    }

    pub fn target_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.target_address)
    }
}

// ─── Icmpv6Message ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Icmpv6Message {
    RouterSolicitation(RouterSolicitation),
    RouterAdvertisement(RouterAdvertisement),
    /// 135
    NeighborSolicitation(NeighborSolicitation),
    /// 136
    NeighborAdvertisement(NeighborAdvertisement),
    Unassigned(u8, Vec<u8>),
}

impl NetProtoCodec for Icmpv6Message {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>, NetProtoError> {
        if src.is_empty() {
            return Ok(None);
        }
        let msg_type: Icmpv6Type = src[0].into();
        let data = &src[..];
        let result = match msg_type {
            Icmpv6Type::RouterSolicitation => {
                let (_, rs) = RouterSolicitation::from_bytes((data, 0))
                    .map_err(|e| NetProtoError::Deku(e.to_string()))?;
                Icmpv6Message::RouterSolicitation(rs)
            }
            Icmpv6Type::NeighborSolicitation => {
                let (_, ns) = NeighborSolicitation::from_bytes((data, 0))
                    .map_err(|e| NetProtoError::Deku(e.to_string()))?;
                Icmpv6Message::NeighborSolicitation(ns)
            }
            Icmpv6Type::NeighborAdvertisement => {
                let (_, na) = NeighborAdvertisement::from_bytes((data, 0))
                    .map_err(|e| NetProtoError::Deku(e.to_string()))?;
                Icmpv6Message::NeighborAdvertisement(na)
            }
            _ => Icmpv6Message::Unassigned(src[0], data.to_vec()),
        };
        src.advance(src.len());
        Ok(Some(result))
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), NetProtoError> {
        match self {
            Icmpv6Message::RouterAdvertisement(ra) => {
                let bytes = ra.to_bytes().map_err(|e| NetProtoError::Deku(e.to_string()))?;
                dst.extend_from_slice(&bytes);
            }
            Icmpv6Message::NeighborSolicitation(ns) => {
                let bytes = ns.to_bytes().map_err(|e| NetProtoError::Deku(e.to_string()))?;
                dst.extend_from_slice(&bytes);
            }
            Icmpv6Message::NeighborAdvertisement(na) => {
                let bytes = na.to_bytes().map_err(|e| NetProtoError::Deku(e.to_string()))?;
                dst.extend_from_slice(&bytes);
            }
            _ => {}
        }
        Ok(())
    }
}

pub type Icmpv6Codec = LandscapeCodec<Icmpv6Message>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmpv6_type_roundtrip() {
        for i in 0..=255u8 {
            let t: Icmpv6Type = i.into();
            let back: u8 = t.into();
            assert_eq!(i, back);
        }
    }

    #[test]
    fn test_router_advertisement_roundtrip() {
        let mut opts = IcmpV6Options::new();
        opts.insert(IcmpV6Option::source_link_layer_address(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        opts.insert(IcmpV6Option::mtu(1500));
        opts.insert(IcmpV6Option::advertisement_interval(60_000));

        let ra = RouterAdvertisement::new(0x80, opts); // M=1

        let bytes = ra.to_bytes().unwrap();
        let (_, decoded) = RouterAdvertisement::from_bytes((&bytes, 0)).unwrap();

        assert_eq!(decoded.msg_type, 134);
        assert_eq!(decoded.flags, 0x80);
        assert_eq!(decoded.cur_hop_limit, 64);
        assert_eq!(decoded.router_lifetime, 1800);

        // Check options
        assert!(decoded.opts.get(1).is_some()); // SourceLinkLayerAddress
        assert!(decoded.opts.get(5).is_some()); // MTU
        assert!(decoded.opts.get(7).is_some()); // AdvertisementInterval
    }

    #[test]
    fn test_icmpv6_message_encode_decode() {
        let mut opts = IcmpV6Options::new();
        opts.insert(IcmpV6Option::mtu(1500));

        let ra = RouterAdvertisement::new(0, opts);
        let msg = Icmpv6Message::RouterAdvertisement(ra);

        let mut dst = BytesMut::new();
        NetProtoCodec::encode(&msg, &mut dst).unwrap();

        assert!(!dst.is_empty());
        // First byte should be 134 (RouterAdvertisement type)
        assert_eq!(dst[0], 134);
    }

    #[test]
    fn test_neighbor_solicitation_roundtrip_with_source_link_layer_address() {
        let target = "fe80::1".parse().unwrap();
        let mac = [0x02, 0x00, 0x00, 0x12, 0x34, 0x56];
        let mut opts = IcmpV6Options::new();
        opts.insert(IcmpV6Option::source_link_layer_address(&mac));

        let ns = NeighborSolicitation::new(target, opts);
        let msg = Icmpv6Message::NeighborSolicitation(ns);

        let mut encoded = BytesMut::new();
        NetProtoCodec::encode(&msg, &mut encoded).unwrap();

        let decoded = NetProtoCodec::decode(&mut encoded).unwrap().unwrap();
        match decoded {
            Icmpv6Message::NeighborSolicitation(ns) => {
                assert_eq!(ns.target_addr(), target);
                assert!(
                    matches!(ns.opts.get(1), Some(IcmpV6Option::SourceLinkLayerAddress { addr, .. }) if addr == &mac)
                );
            }
            other => panic!("expected NeighborSolicitation, got {other:?}"),
        }
    }
}
