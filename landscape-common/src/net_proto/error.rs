use std::io;

use thiserror::Error;

/// Convenience type for decode errors
pub type DecodeResult<T> = Result<T, DecodeError>;

/// Returned from types that decode
#[derive(Error, Debug)]
pub enum DecodeError {
    /// io error
    #[error("io error {0}")]
    IoError(#[from] io::Error),

    /// DHCP PROTO
    #[error("dhcproto error {0}")]
    DHCProtoError(#[from] dhcproto::error::DecodeError),
}

/// Returned from types that encode
#[derive(Error, Debug)]
pub enum EncodeError {
    /// io error
    #[error("io error {0}")]
    IoError(#[from] io::Error),

    /// DHCP PROTO
    #[error("dhcproto error {0}")]
    DHCProtoError(#[from] dhcproto::error::EncodeError),
}

/// Convenience type for encode errors
pub type EncodeResult<T> = Result<T, EncodeError>;
