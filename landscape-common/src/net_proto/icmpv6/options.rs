use std::net::Ipv6Addr;

use deku::ctx::Endian;
use deku::reader::Reader;
use deku::writer::Writer;
use deku::{DekuError, DekuReader, DekuWriter};
use serde::{Deserialize, Serialize};

// ─── IcmpV6Option ──────────────────────────────────────────────────────────

/// ICMPv6 Neighbor Discovery Option (RFC 4861, Section 4.6)
///
/// Options are TLV-encoded:
///   Type   (1 byte)
///   Length (1 byte, in units of 8 octets including Type + Length)
///   Value  (variable)
#[derive(Debug, Clone)]
pub enum IcmpV6Option {
    /// Type 1 - Source Link-Layer Address
    SourceLinkLayerAddress { length: u8, addr: [u8; 6] },
    /// Type 2 - Target Link-Layer Address
    TargetLinkLayerAddress { length: u8, addr: [u8; 6] },
    /// Type 3 - Prefix Information (RFC 4861 Section 4.6.2)
    PrefixInformation {
        length: u8,
        prefix_length: u8,
        flags: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        reserved2: u32,
        prefix: [u8; 16],
    },
    /// Type 5 - MTU
    MTU { length: u8, reserved: u16, mtu: u32 },
    /// Type 7 - Advertisement Interval (RFC 6275 Section 7.3)
    AdvertisementInterval { length: u8, reserved: u16, interval: u32 },
    /// Type 24 - Route Information (RFC 4191)
    RouteInformation {
        length: u8,
        prefix_length: u8,
        flags: u8,
        route_lifetime: u32,
        prefix: Vec<u8>,
    },
    /// Type 25 - Recursive DNS Server (RFC 8106)
    RecursiveDNSServer { length: u8, reserved: u16, lifetime: u32, addresses: Vec<u8> },
    /// Unknown / unsupported option type
    Unknown { code: u8, length: u8, data: Vec<u8> },
}

// ─── code() + convenience constructors ──────────────────────────────────────

impl IcmpV6Option {
    /// Returns the option type code.
    pub fn code(&self) -> u8 {
        match self {
            IcmpV6Option::SourceLinkLayerAddress { .. } => 1,
            IcmpV6Option::TargetLinkLayerAddress { .. } => 2,
            IcmpV6Option::PrefixInformation { .. } => 3,
            IcmpV6Option::MTU { .. } => 5,
            IcmpV6Option::AdvertisementInterval { .. } => 7,
            IcmpV6Option::RouteInformation { .. } => 24,
            IcmpV6Option::RecursiveDNSServer { .. } => 25,
            IcmpV6Option::Unknown { code, .. } => *code,
        }
    }

    pub fn source_link_layer_address(mac: &[u8; 6]) -> Self {
        Self::SourceLinkLayerAddress { length: 1, addr: *mac }
    }

    pub fn prefix_information(
        prefix_length: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        prefix: Ipv6Addr,
        autonomous: bool,
    ) -> Self {
        // L=1 always (0x80), A depends on autonomous flag (0x40)
        let flags = if autonomous { 0xc0 } else { 0x80 };
        Self::PrefixInformation {
            length: 4,
            prefix_length,
            flags,
            valid_lifetime,
            preferred_lifetime,
            reserved2: 0,
            prefix: prefix.octets(),
        }
    }

    pub fn route_information(prefix_length: u8, prefix: Ipv6Addr) -> Self {
        Self::route_information_with_lifetime(prefix_length, 1800, prefix)
    }

    pub fn route_information_with_lifetime(
        prefix_length: u8,
        route_lifetime: u32,
        prefix: Ipv6Addr,
    ) -> Self {
        Self::RouteInformation {
            length: 3, // (2 + 1 + 1 + 4 + 16) / 8 = 3
            prefix_length,
            flags: 0,
            route_lifetime,
            prefix: prefix.octets().to_vec(),
        }
    }

    pub fn recursive_dns_server(lifetime: u32, addr: Ipv6Addr) -> Self {
        Self::RecursiveDNSServer {
            length: 3, // (2 + 2 + 4 + 16) / 8 = 3
            reserved: 0,
            lifetime,
            addresses: addr.octets().to_vec(),
        }
    }

    pub fn mtu(value: u32) -> Self {
        Self::MTU { length: 1, reserved: 0, mtu: value }
    }

    pub fn advertisement_interval(ms: u32) -> Self {
        Self::AdvertisementInterval { length: 1, reserved: 0, interval: ms }
    }
}

// ─── DekuReader ─────────────────────────────────────────────────────────────

impl<'a> DekuReader<'a> for IcmpV6Option {
    fn from_reader_with_ctx<R: std::io::Read + std::io::Seek>(
        reader: &mut Reader<R>,
        _ctx: (),
    ) -> Result<Self, DekuError> {
        let option_type = u8::from_reader_with_ctx(reader, Endian::Big)?;
        let length = u8::from_reader_with_ctx(reader, Endian::Big)?;
        let data_len = (length as usize).saturating_mul(8).saturating_sub(2);

        match option_type {
            1 => {
                // SourceLinkLayerAddress: 6-byte MAC
                let addr = <[u8; 6]>::from_reader_with_ctx(reader, Endian::Big)?;
                let skip = data_len.saturating_sub(6);
                for _ in 0..skip {
                    let _ = u8::from_reader_with_ctx(reader, Endian::Big)?;
                }
                Ok(IcmpV6Option::SourceLinkLayerAddress { length, addr })
            }
            2 => {
                // TargetLinkLayerAddress: 6-byte MAC
                let addr = <[u8; 6]>::from_reader_with_ctx(reader, Endian::Big)?;
                let skip = data_len.saturating_sub(6);
                for _ in 0..skip {
                    let _ = u8::from_reader_with_ctx(reader, Endian::Big)?;
                }
                Ok(IcmpV6Option::TargetLinkLayerAddress { length, addr })
            }
            3 => {
                // PrefixInformation: 30 bytes payload
                let prefix_length = u8::from_reader_with_ctx(reader, Endian::Big)?;
                let flags = u8::from_reader_with_ctx(reader, Endian::Big)?;
                let valid_lifetime = u32::from_reader_with_ctx(reader, Endian::Big)?;
                let preferred_lifetime = u32::from_reader_with_ctx(reader, Endian::Big)?;
                let reserved2 = u32::from_reader_with_ctx(reader, Endian::Big)?;
                let prefix = <[u8; 16]>::from_reader_with_ctx(reader, Endian::Big)?;
                Ok(IcmpV6Option::PrefixInformation {
                    length,
                    prefix_length,
                    flags,
                    valid_lifetime,
                    preferred_lifetime,
                    reserved2,
                    prefix,
                })
            }
            5 => {
                // MTU: reserved(2) + mtu(4) = 6 bytes
                let reserved = u16::from_reader_with_ctx(reader, Endian::Big)?;
                let mtu = u32::from_reader_with_ctx(reader, Endian::Big)?;
                Ok(IcmpV6Option::MTU { length, reserved, mtu })
            }
            7 => {
                // AdvertisementInterval: reserved(2) + interval(4) = 6 bytes
                let reserved = u16::from_reader_with_ctx(reader, Endian::Big)?;
                let interval = u32::from_reader_with_ctx(reader, Endian::Big)?;
                Ok(IcmpV6Option::AdvertisementInterval { length, reserved, interval })
            }
            24 => {
                // RouteInformation: prefix_length(1) + flags(1) + route_lifetime(4) + prefix(var)
                let prefix_length = u8::from_reader_with_ctx(reader, Endian::Big)?;
                let flags = u8::from_reader_with_ctx(reader, Endian::Big)?;
                let route_lifetime = u32::from_reader_with_ctx(reader, Endian::Big)?;
                let prefix_data_len = data_len.saturating_sub(6);
                let mut prefix = vec![0u8; prefix_data_len];
                for byte in prefix.iter_mut() {
                    *byte = u8::from_reader_with_ctx(reader, Endian::Big)?;
                }
                Ok(IcmpV6Option::RouteInformation {
                    length,
                    prefix_length,
                    flags,
                    route_lifetime,
                    prefix,
                })
            }
            25 => {
                // RecursiveDNSServer: reserved(2) + lifetime(4) + addresses(var)
                let reserved = u16::from_reader_with_ctx(reader, Endian::Big)?;
                let lifetime = u32::from_reader_with_ctx(reader, Endian::Big)?;
                let addr_data_len = data_len.saturating_sub(6);
                let mut addresses = vec![0u8; addr_data_len];
                for byte in addresses.iter_mut() {
                    *byte = u8::from_reader_with_ctx(reader, Endian::Big)?;
                }
                Ok(IcmpV6Option::RecursiveDNSServer { length, reserved, lifetime, addresses })
            }
            code => {
                let mut data = vec![0u8; data_len];
                for byte in data.iter_mut() {
                    *byte = u8::from_reader_with_ctx(reader, Endian::Big)?;
                }
                Ok(IcmpV6Option::Unknown { code, length, data })
            }
        }
    }
}

// ─── DekuWriter ─────────────────────────────────────────────────────────────

impl DekuWriter for IcmpV6Option {
    fn to_writer<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut Writer<W>,
        _ctx: (),
    ) -> Result<(), DekuError> {
        match self {
            IcmpV6Option::SourceLinkLayerAddress { length, addr } => {
                1u8.to_writer(writer, Endian::Big)?;
                length.to_writer(writer, Endian::Big)?;
                writer.write_bytes(addr)?;
            }
            IcmpV6Option::TargetLinkLayerAddress { length, addr } => {
                2u8.to_writer(writer, Endian::Big)?;
                length.to_writer(writer, Endian::Big)?;
                writer.write_bytes(addr)?;
            }
            IcmpV6Option::PrefixInformation {
                length,
                prefix_length,
                flags,
                valid_lifetime,
                preferred_lifetime,
                reserved2,
                prefix,
            } => {
                3u8.to_writer(writer, Endian::Big)?;
                length.to_writer(writer, Endian::Big)?;
                prefix_length.to_writer(writer, Endian::Big)?;
                flags.to_writer(writer, Endian::Big)?;
                valid_lifetime.to_writer(writer, Endian::Big)?;
                preferred_lifetime.to_writer(writer, Endian::Big)?;
                reserved2.to_writer(writer, Endian::Big)?;
                writer.write_bytes(prefix)?;
            }
            IcmpV6Option::MTU { length, reserved, mtu } => {
                5u8.to_writer(writer, Endian::Big)?;
                length.to_writer(writer, Endian::Big)?;
                reserved.to_writer(writer, Endian::Big)?;
                mtu.to_writer(writer, Endian::Big)?;
            }
            IcmpV6Option::AdvertisementInterval { length, reserved, interval } => {
                7u8.to_writer(writer, Endian::Big)?;
                length.to_writer(writer, Endian::Big)?;
                reserved.to_writer(writer, Endian::Big)?;
                interval.to_writer(writer, Endian::Big)?;
            }
            IcmpV6Option::RouteInformation {
                length,
                prefix_length,
                flags,
                route_lifetime,
                prefix,
            } => {
                24u8.to_writer(writer, Endian::Big)?;
                length.to_writer(writer, Endian::Big)?;
                prefix_length.to_writer(writer, Endian::Big)?;
                flags.to_writer(writer, Endian::Big)?;
                route_lifetime.to_writer(writer, Endian::Big)?;
                writer.write_bytes(prefix)?;
            }
            IcmpV6Option::RecursiveDNSServer { length, reserved, lifetime, addresses } => {
                25u8.to_writer(writer, Endian::Big)?;
                length.to_writer(writer, Endian::Big)?;
                reserved.to_writer(writer, Endian::Big)?;
                lifetime.to_writer(writer, Endian::Big)?;
                writer.write_bytes(addresses)?;
            }
            IcmpV6Option::Unknown { code, length, data } => {
                code.to_writer(writer, Endian::Big)?;
                length.to_writer(writer, Endian::Big)?;
                writer.write_bytes(data)?;
            }
        }
        Ok(())
    }
}

// ─── IcmpV6Options (sorted collection) ─────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct IcmpV6Options(pub(crate) Vec<IcmpV6Option>);

impl IcmpV6Options {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an option, maintaining sort order by code.
    pub fn insert(&mut self, opt: IcmpV6Option) {
        let i = self.0.partition_point(|x| x.code() < opt.code());
        self.0.insert(i, opt);
    }

    /// Get the first option matching this type code.
    pub fn get(&self, code: u8) -> Option<&IcmpV6Option> {
        self.0.iter().find(|x| x.code() == code)
    }

    /// Get all options matching this type code.
    pub fn get_all(&self, code: u8) -> Vec<&IcmpV6Option> {
        self.0.iter().filter(|x| x.code() == code).collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &IcmpV6Option> {
        self.0.iter()
    }
}

impl IntoIterator for IcmpV6Options {
    type Item = IcmpV6Option;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<IcmpV6Option> for IcmpV6Options {
    fn from_iter<T: IntoIterator<Item = IcmpV6Option>>(iter: T) -> Self {
        let mut opts: Vec<_> = iter.into_iter().collect();
        opts.sort_by_key(|o| o.code());
        IcmpV6Options(opts)
    }
}

// ─── Config structs (kept for serde serialization) ──────────────────────────

/// https://www.rfc-editor.org/rfc/rfc4861.html#section-4.6.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixInformation {
    pub prefix_length: u8,
    pub flags: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub reserved2: u32,
    pub prefix: Ipv6Addr,
}

impl PrefixInformation {
    pub fn new(
        prefix_length: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        prefix: Ipv6Addr,
    ) -> Self {
        Self::with_autonomous(prefix_length, valid_lifetime, preferred_lifetime, prefix, true)
    }

    pub fn with_autonomous(
        prefix_length: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        prefix: Ipv6Addr,
        autonomous: bool,
    ) -> Self {
        let flags = if autonomous { 0xc0 } else { 0x80 };
        PrefixInformation {
            prefix_length,
            flags,
            valid_lifetime,
            preferred_lifetime,
            reserved2: 0,
            prefix,
        }
    }
}

impl From<PrefixInformation> for IcmpV6Option {
    fn from(pi: PrefixInformation) -> Self {
        IcmpV6Option::PrefixInformation {
            length: 4,
            prefix_length: pi.prefix_length,
            flags: pi.flags,
            valid_lifetime: pi.valid_lifetime,
            preferred_lifetime: pi.preferred_lifetime,
            reserved2: pi.reserved2,
            prefix: pi.prefix.octets(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteInformation {
    pub prefix_length: u8,
    pub flags: u8,
    pub route_lifetime: u32,
    pub prefix: Ipv6Addr,
}

impl RouteInformation {
    pub fn new(prefix_length: u8, prefix: Ipv6Addr) -> Self {
        RouteInformation {
            prefix_length,
            flags: 0,
            route_lifetime: 1800,
            prefix,
        }
    }
}

impl From<RouteInformation> for IcmpV6Option {
    fn from(ri: RouteInformation) -> Self {
        IcmpV6Option::RouteInformation {
            length: 3,
            prefix_length: ri.prefix_length,
            flags: ri.flags,
            route_lifetime: ri.route_lifetime,
            prefix: ri.prefix.octets().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_code() {
        assert_eq!(IcmpV6Option::source_link_layer_address(&[1, 2, 3, 4, 5, 6]).code(), 1);
        assert_eq!(IcmpV6Option::mtu(1500).code(), 5);
        assert_eq!(
            IcmpV6Option::prefix_information(64, 600, 300, Ipv6Addr::UNSPECIFIED, true).code(),
            3
        );
    }

    #[test]
    fn test_options_insert_sorted() {
        let mut opts = IcmpV6Options::new();
        opts.insert(IcmpV6Option::mtu(1500)); // code 5
        opts.insert(IcmpV6Option::source_link_layer_address(&[0; 6])); // code 1
        opts.insert(IcmpV6Option::advertisement_interval(60_000)); // code 7

        let codes: Vec<u8> = opts.iter().map(|o| o.code()).collect();
        assert_eq!(codes, vec![1, 5, 7]);
    }

    #[test]
    fn test_options_get() {
        let mut opts = IcmpV6Options::new();
        opts.insert(IcmpV6Option::mtu(1500));
        assert!(opts.get(5).is_some());
        assert!(opts.get(1).is_none());
    }

    #[test]
    fn test_roundtrip_source_link_layer_address() {
        let opt = IcmpV6Option::source_link_layer_address(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // Write
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut writer = Writer::new(&mut buf);
        opt.to_writer(&mut writer, ()).unwrap();
        writer.finalize().unwrap();
        let bytes = buf.into_inner();

        // Read
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut reader = Reader::new(&mut cursor);
        let decoded = IcmpV6Option::from_reader_with_ctx(&mut reader, ()).unwrap();

        assert_eq!(decoded.code(), 1);
        if let IcmpV6Option::SourceLinkLayerAddress { addr, .. } = decoded {
            assert_eq!(addr, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        } else {
            panic!("Expected SourceLinkLayerAddress");
        }
    }

    #[test]
    fn test_roundtrip_prefix_information() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let opt = IcmpV6Option::prefix_information(64, 600, 300, prefix, true);

        let mut buf = std::io::Cursor::new(Vec::new());
        let mut writer = Writer::new(&mut buf);
        opt.to_writer(&mut writer, ()).unwrap();
        writer.finalize().unwrap();
        let bytes = buf.into_inner();

        assert_eq!(bytes.len(), 32); // type(1) + len(1) + payload(30)

        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut reader = Reader::new(&mut cursor);
        let decoded = IcmpV6Option::from_reader_with_ctx(&mut reader, ()).unwrap();

        if let IcmpV6Option::PrefixInformation {
            prefix_length,
            flags,
            valid_lifetime,
            preferred_lifetime,
            prefix: decoded_prefix,
            ..
        } = decoded
        {
            assert_eq!(prefix_length, 64);
            assert_eq!(flags, 0xc0);
            assert_eq!(valid_lifetime, 600);
            assert_eq!(preferred_lifetime, 300);
            assert_eq!(decoded_prefix, prefix.octets());
        } else {
            panic!("Expected PrefixInformation");
        }
    }

    #[test]
    fn test_roundtrip_mtu() {
        let opt = IcmpV6Option::mtu(1500);

        let mut buf = std::io::Cursor::new(Vec::new());
        let mut writer = Writer::new(&mut buf);
        opt.to_writer(&mut writer, ()).unwrap();
        writer.finalize().unwrap();
        let bytes = buf.into_inner();

        assert_eq!(bytes.len(), 8);

        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut reader = Reader::new(&mut cursor);
        let decoded = IcmpV6Option::from_reader_with_ctx(&mut reader, ()).unwrap();

        if let IcmpV6Option::MTU { mtu, .. } = decoded {
            assert_eq!(mtu, 1500);
        } else {
            panic!("Expected MTU");
        }
    }

    #[test]
    fn test_from_prefix_information() {
        let pi =
            PrefixInformation::new(64, 600, 300, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        let opt: IcmpV6Option = pi.into();
        assert_eq!(opt.code(), 3);
    }

    #[test]
    fn test_roundtrip_route_information_zero_lifetime() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
        let opt = IcmpV6Option::route_information_with_lifetime(64, 0, prefix);

        let mut buf = std::io::Cursor::new(Vec::new());
        let mut writer = Writer::new(&mut buf);
        opt.to_writer(&mut writer, ()).unwrap();
        writer.finalize().unwrap();
        let bytes = buf.into_inner();

        assert_eq!(bytes.len(), 24);
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut reader = Reader::new(&mut cursor);
        let decoded = IcmpV6Option::from_reader_with_ctx(&mut reader, ()).unwrap();

        match decoded {
            IcmpV6Option::RouteInformation {
                prefix_length,
                route_lifetime,
                prefix: decoded_prefix,
                ..
            } => {
                assert_eq!(prefix_length, 64);
                assert_eq!(route_lifetime, 0);
                assert_eq!(decoded_prefix, prefix.octets().to_vec());
            }
            other => panic!("Expected RouteInformation, got {other:?}"),
        }
    }
}
