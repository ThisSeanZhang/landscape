use hickory_proto::op::ResponseCode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS Protocol error: {0}")]
    Protocol(ResponseCode),

    #[error("Upstream timeout")]
    Timeout,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("No rule matched for domain: {0}")]
    NoRuleMatched(String),

    #[error("Io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cache error: {0}")]
    Cache(String),
}

pub type DnsResult<T> = Result<T, DnsError>;
