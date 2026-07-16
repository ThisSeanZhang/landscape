mod clock;
mod sync;

pub use clock::{get_boot_time_ns, get_current_time_ms, get_current_time_ns, get_relative_time_ns};
pub use sync::{
    get_time_sync_status, set_system_time, start_ntp_sync_thread, start_time_sync_service,
    update_time_sync_config,
};
