mod error;
mod runtime;

pub use crate::pppoe_client::PPPoEClientConfig;
pub use error::PppoeError;
pub use runtime::run;

pub(crate) type PppoeResult<T> = Result<T, PppoeError>;

pub const DEFAULT_TIMEOUT: u64 = 3;
pub const LCP_ECHO_INTERVAL: u64 = 20;
pub const DEFAULT_CLIENT_MRU: u16 = 1492;
pub const ETH_P_PPOED: u16 = 0x8863;
pub const ETH_P_PPOES: u16 = 0x8864;
