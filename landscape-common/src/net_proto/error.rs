use std::io;
use thiserror::Error;

/// Unified error type for network protocol encoding/decoding.
#[derive(Error, Debug)]
pub enum NetProtoError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// DHCPv4 or DHCPv6 decode error from dhcproto
    #[error("DHCP decode error: {0}")]
    DhcpDecode(#[from] dhcproto::error::DecodeError),

    /// DHCPv4 or DHCPv6 encode error from dhcproto
    #[error("DHCP encode error: {0}")]
    DhcpEncode(#[from] dhcproto::error::EncodeError),

    /// Generic packet error (e.g. invalid length, invalid data)
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Custom error for specific protocol implementations
    #[error("{0}")]
    Other(String),
}

/// Convenience result type
pub type NetProtoResult<T> = Result<T, NetProtoError>;

// For backward compatibility if needed, you can aliase old types
pub type DecodeError = NetProtoError;
pub type EncodeError = NetProtoError;
pub type DecodeResult<T> = Result<T, NetProtoError>;
pub type EncodeResult<T> = Result<T, NetProtoError>;
