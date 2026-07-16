use std::mem;

use libc::{clock_gettime, timespec, CLOCK_BOOTTIME, CLOCK_MONOTONIC};

use super::sync::get_synced_system_time;

pub fn get_boot_time_ns() -> Result<u64, i32> {
    let mut ts: timespec = unsafe { mem::zeroed() };

    let result = unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts) };

    if result == 0 {
        let ns = (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64);
        Ok(ns)
    } else {
        Err(unsafe { *libc::__errno_location() })
    }
}

pub fn get_current_time_ns() -> Result<u64, i32> {
    let time =
        get_synced_system_time().duration_since(std::time::UNIX_EPOCH).map_err(|_| libc::EINVAL)?;
    Ok(time.as_nanos() as u64)
}

pub fn get_current_time_ms() -> Result<u64, i32> {
    Ok(get_current_time_ns()? / 1_000_000)
}

pub fn get_relative_time_ns() -> Result<u64, i32> {
    let current_time_ns = get_current_time_ns()?;
    let mut monotonic: timespec = unsafe { std::mem::zeroed() };

    if unsafe { clock_gettime(CLOCK_MONOTONIC, &mut monotonic) } != 0 {
        return Err(unsafe { *libc::__errno_location() });
    }

    let monotonic_ns = (monotonic.tv_sec as u64) * 1_000_000_000 + (monotonic.tv_nsec as u64);
    current_time_ns.checked_sub(monotonic_ns).ok_or(libc::EINVAL)
}

#[cfg(test)]
mod tests {
    use super::{get_boot_time_ns, get_current_time_ms};

    #[test]
    fn clock_values_are_available() {
        assert!(get_boot_time_ns().unwrap() > 0);
        assert!(get_current_time_ms().unwrap() > 1_000_000_000_000);
    }
}
