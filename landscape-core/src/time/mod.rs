mod ntp;
mod sync;

pub use ntp::{NtpClient, NtpQueryResult, UdpNtpClient};
pub use sync::{RealSystemClock, SyncTimeService, SystemClock, set_system_time};
