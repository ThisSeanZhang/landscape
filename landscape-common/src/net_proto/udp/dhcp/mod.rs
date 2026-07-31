use crate::net_proto::error::NetProtoError;
use crate::net_proto::NetProtoCodec;
use bytes::{Buf, BytesMut};

pub mod v4_helpers;

pub use dhcproto::v4;
pub use dhcproto::v6;
pub use dhcproto::{Decodable, Decoder, Encodable, Encoder};

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
/// DHCPv4 Flags.
pub use v4::Flags as DhcpV4Flags;
/// DHCPv4 OpCode.
pub use v4::Opcode as DhcpV4OpCode;

/// DHCPv6 Options collection.
pub use v6::DhcpOptions as DhcpV6Options;

impl NetProtoCodec for DhcpV4Message {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>, NetProtoError> {
        if src.is_empty() {
            return Ok(None);
        }
        // Route through the panic-proof wrapper: dhcproto's option decoder
        // trips `debug_assert!`/underflow panics on hostile lengths (see
        // try_decode_dhcpv4), so untrusted wire input must never decode
        // directly. This covers every codec user, e.g. the DHCPv4 client's
        // raw AF_PACKET path.
        let msg = try_decode_dhcpv4(&src[..]).ok_or_else(|| {
            NetProtoError::Protocol("malformed or unsafe DHCPv4 packet rejected".to_string())
        })?;
        // In UDP/DHCP, we usually consume the whole buffer
        src.advance(src.len());
        Ok(Some(msg))
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), NetProtoError> {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(&mut buffer);
        <Self as Encodable>::encode(self, &mut encoder)?;
        dst.extend_from_slice(&buffer);
        Ok(())
    }
}

impl NetProtoCodec for DhcpV6Message {
    fn decode(src: &mut BytesMut) -> Result<Option<Self>, NetProtoError> {
        if src.is_empty() {
            return Ok(None);
        }
        let mut decoder = Decoder::new(&src[..]);
        let msg = <Self as Decodable>::decode(&mut decoder)?;
        src.advance(src.len());
        Ok(Some(msg))
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), NetProtoError> {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(&mut buffer);
        <Self as Encodable>::encode(self, &mut encoder)?;
        dst.extend_from_slice(&buffer);
        Ok(())
    }
}

/// Codec for DHCPv4 messages.
pub type DhcpV4Codec = crate::net_proto::LandscapeCodec<DhcpV4Message>;

/// Codec for DHCPv6 messages.
pub type DhcpV6Codec = crate::net_proto::LandscapeCodec<DhcpV6Message>;

/// Decode a DHCPv4 message from untrusted wire bytes.
///
/// dhcproto validates the length of a few options with `debug_assert!` (or an
/// unchecked `len - 1`), so in debug builds a malformed length in hostile
/// input panics instead of erroring. This wrapper rejects exactly those
/// packets before decoding, making the decode below total in every build. In
/// release builds the pre-check is a no-op and behavior is unchanged.
pub fn try_decode_dhcpv4(data: &[u8]) -> Option<DhcpV4Message> {
    if data.len() >= 240 && !dhcpv4_options_are_safe(&data[240..]) {
        return None;
    }
    let mut decoder = Decoder::new(data);
    <DhcpV4Message as Decodable>::decode(&mut decoder).ok()
}

/// Option codes whose dhcproto 0.15 decoder can panic on a malformed length
/// in debug builds: `debug_assert!` length checks and a `len - 1` underflow.
/// (code, (min, max) merged length after RFC 3396 concatenation)
#[cfg(debug_assertions)]
const DHCPV4_LENGTH_SENSITIVE_OPTIONS: &[(u8, (usize, usize))] = &[
    // 80 RapidCommit: must be zero-length (`debug_assert!(len == 0)`).
    (80, (0, 0)),
    // 81 ClientFQDN: three 1-byte header fields (`debug_assert!(len >= 3)`).
    (81, (3, usize::MAX)),
    // 94 ClientNetworkInterface: three 1-byte fields (`debug_assert!(len == 3)`).
    (94, (3, 3)),
    // 151 BulkLeaseQueryStatusCode: `read_string(len - 1)` underflows at 0.
    (151, (1, usize::MAX)),
    // 152..=155 BulkLeaseQuery times: 4-byte values (`debug_assert!(len == 4)`).
    (152, (4, 4)),
    (153, (4, 4)),
    (154, (4, 4)),
    (155, (4, 4)),
];

/// Pre-scan the DHCPv4 option area for the length mismatches that would trip
/// dhcproto's `debug_assert!`/underflow panics. Consecutive same-code options
/// are concatenated per RFC 3396 exactly like dhcproto, so the merged length
/// is validated only once the option's run ends (next code, Pad, End, EOF).
/// A truncated trailing option is fine: dhcproto stops parsing gracefully and
/// never reaches the assert.
#[cfg(debug_assertions)]
fn dhcpv4_options_are_safe(options: &[u8]) -> bool {
    let mut i = 0usize;
    let mut prev_code: Option<u8> = None;
    let mut merged_len = 0usize;
    while i < options.len() {
        let code = options[i];
        i += 1;
        match code {
            // Padding and the end marker carry no length; both also end any
            // in-progress RFC 3396 concatenation.
            0 => {
                if !dhcpv4_option_length_is_valid(prev_code, merged_len) {
                    return false;
                }
                prev_code = None;
            }
            255 => return dhcpv4_option_length_is_valid(prev_code, merged_len),
            _ => {
                let Some(len) = options.get(i).copied().map(usize::from) else {
                    return false;
                };
                i += 1;
                if i + len > options.len() {
                    return true; // truncated option: dhcproto errors gracefully
                }
                if prev_code == Some(code) {
                    merged_len += len;
                } else {
                    if !dhcpv4_option_length_is_valid(prev_code, merged_len) {
                        return false;
                    }
                    prev_code = Some(code);
                    merged_len = len;
                }
                i += len;
            }
        }
    }
    dhcpv4_option_length_is_valid(prev_code, merged_len)
}

#[cfg(debug_assertions)]
fn dhcpv4_option_length_is_valid(code: Option<u8>, merged_len: usize) -> bool {
    match code.and_then(|code| DHCPV4_LENGTH_SENSITIVE_OPTIONS.iter().find(|(c, _)| *c == code)) {
        None => true,
        Some((_, (min, max))) => merged_len >= *min && merged_len <= *max,
    }
}

#[cfg(not(debug_assertions))]
fn dhcpv4_options_are_safe(_options: &[u8]) -> bool {
    true
}

/// Default option set for a DHCPv6 Solicit (ORO + IA_PD + ReconfAccept).
pub fn get_solicit_options() -> DhcpV6Options {
    let mut options = DhcpV6Options::new();
    let oro = v6::ORO {
        opts: vec![v6::OptionCode::IAPrefix, v6::OptionCode::DomainNameServers],
    };

    let iapd = v6::IAPD { id: 1, t1: 0, t2: 0, opts: DhcpV6Options::new() };
    options.insert(v6::DhcpOption::ORO(oro));
    options.insert(v6::DhcpOption::IAPD(iapd));
    options.insert(v6::DhcpOption::ReconfAccept);
    options
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_proto::udp::dhcp::v4::MessageType;

    /// Encode a bare 240-byte DHCPv4 header (fixed fields + magic cookie) with
    /// a Discover message type and the given raw options appended verbatim, so
    /// wire bytes are exact.
    fn build_message(opts: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let header = DhcpV4Message::default();
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        <DhcpV4Message as Encodable>::encode(&header, &mut e).expect("encode header");
        buf.extend_from_slice(&[53, 1, MessageType::Discover.into()]);
        for (code, data) in opts {
            buf.push(*code);
            buf.push(data.len() as u8);
            buf.extend_from_slice(data);
        }
        buf.push(255);
        buf
    }

    #[test]
    fn try_decode_dhcpv4_round_trips_valid_message() {
        let decoded = try_decode_dhcpv4(&build_message(&[(66, b"tftp".to_vec())])).expect("decode");
        assert_eq!(decoded.opts().msg_type(), Some(MessageType::Discover));
    }

    #[test]
    fn try_decode_dhcpv4_rejects_short_input() {
        assert!(try_decode_dhcpv4(&[0; 100]).is_none());
        assert!(try_decode_dhcpv4(&[]).is_none());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn try_decode_dhcpv4_rejects_length_sensitive_option_mismatches() {
        // Option 80 (RapidCommit) must be zero-length.
        assert!(try_decode_dhcpv4(&build_message(&[(80, vec![0])])).is_none());
        assert!(try_decode_dhcpv4(&build_message(&[(80, vec![])])).is_some());
        // Option 94 (ClientNetworkInterface) must be exactly 3 bytes.
        assert!(try_decode_dhcpv4(&build_message(&[(94, vec![1, 2])])).is_none());
        assert!(try_decode_dhcpv4(&build_message(&[(94, vec![1, 2, 3])])).is_some());
        // Option 151 (BulkLeaseQueryStatusCode) length must not underflow.
        assert!(try_decode_dhcpv4(&build_message(&[(151, vec![])])).is_none());
        assert!(try_decode_dhcpv4(&build_message(&[(151, vec![1, 2])])).is_some());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn try_decode_dhcpv4_concatenated_options_use_merged_length() {
        // RFC 3396: chunked option 94 must be validated on the merged length.
        // 1 + 2 bytes merge to the valid 3-byte length...
        let bytes = build_message(&[(94, vec![1]), (94, vec![2, 3])]);
        assert!(try_decode_dhcpv4(&bytes).is_some());
        // ...while 2 + 2 merge to 4, which would trip dhcproto's assert.
        let bytes = build_message(&[(94, vec![1, 2]), (94, vec![3, 4])]);
        assert!(try_decode_dhcpv4(&bytes).is_none());
    }
}
