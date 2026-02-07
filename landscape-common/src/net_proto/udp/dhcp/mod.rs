use bytes::{Buf, BufMut, BytesMut};
use crate::net_proto::error::NetProtoError;
use crate::net_proto::NetProtoCodec;

pub use dhcproto::v4;
pub use dhcproto::v6;
pub use dhcproto::{Decoder, Encoder, Decodable, Encodable};

/// Unified type for DHCPv4 messages.
pub type DhcpV4Message = v4::Message;

/// Unified type for DHCPv6 messages.
pub type DhcpV6Message = v6::Message;

/// DHCPv4 Message Type.
pub use v4::MessageType as DhcpV4MessageType;

/// DHCPv6 Message Type.
pub use v6::MessageType as DhcpV6MessageType;

/// Common DHCPv4 option codes for convenience.
pub use v4::OptionCode as DhcpV4OptionCode;

/// Common DHCPv6 option codes for convenience.
pub use v6::OptionCode as DhcpV6OptionCode;

/// DHCPv4 Option types.
pub use v4::DhcpOption as DhcpV4Option;

/// DHCPv6 Option types.
pub use v6::DhcpOption as DhcpV6Option;

/// DHCPv4 Options collection.
pub use v4::DhcpOptions as DhcpV4Options;

/// DHCPv6 Options collection.
pub use v6::DhcpOptions as DhcpV6Options;

impl NetProtoCodec for DhcpV4Message {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>, NetProtoError> {
        if src.is_empty() {
            return Ok(None);
        }
        let mut decoder = Decoder::new(&src[..]);
        let msg = Self::decode(&mut decoder)?;
        // In UDP/DHCP, we usually consume the whole buffer
        src.advance(src.len());
        Ok(Some(msg))
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), NetProtoError> {
        let mut writer = dst.writer();
        let mut encoder = Encoder::new(&mut writer);
        self.encode(&mut encoder)?;
        Ok(())
    }
}

impl NetProtoCodec for DhcpV6Message {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>, NetProtoError> {
        if src.is_empty() {
            return Ok(None);
        }
        let mut decoder = Decoder::new(&src[..]);
        let msg = Self::decode(&mut decoder)?;
        src.advance(src.len());
        Ok(Some(msg))
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), NetProtoError> {
        let mut writer = dst.writer();
        let mut encoder = Encoder::new(&mut writer);
        self.encode(&mut encoder)?;
        Ok(())
    }
}

/// Codec for DHCPv4 messages.
pub type DhcpV4Codec = crate::net_proto::LandscapeCodec<DhcpV4Message>;

/// Codec for DHCPv6 messages.
pub type DhcpV6Codec = crate::net_proto::LandscapeCodec<DhcpV6Message>;
