use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};

pub(crate) mod test_time {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_time.skel.rs"));
}

use test_time::{types, TestTimeSkelBuilder};

fn clock_gettime_ns(clock_id: libc::clockid_t) -> std::io::Result<u64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::clock_gettime(clock_id, &mut ts) };

    if result == 0 {
        Ok((ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn read_unaligned<T: Copy>(bytes: &[u8]) -> T {
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESULT_KEY: u32 = 0;
    const CLOCK_TOLERANCE_NS: u64 = 50_000_000;
    const RELATIVE_TIME_MIN_GAP_NS: u64 = 86_400 * 1_000_000_000;

    #[test]
    fn bpf_tai_time_is_absolute() {
        let before_tai = clock_gettime_ns(libc::CLOCK_TAI).expect("read CLOCK_TAI before test");
        let before_mono =
            clock_gettime_ns(libc::CLOCK_MONOTONIC).expect("read CLOCK_MONOTONIC before test");

        let builder = TestTimeSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).expect("open test_time skeleton");
        let skel = open.load().expect("load test_time skeleton");

        let data = vec![0_u8; 64];
        let result = skel
            .progs
            .test_time
            .test_run(ProgramInput { data_in: Some(&data), ..Default::default() })
            .expect("run test_time program");
        assert_eq!(result.return_value as i32, 0, "test_time program should return TC_ACT_OK");

        let after_tai = clock_gettime_ns(libc::CLOCK_TAI).expect("read CLOCK_TAI after test");
        let after_mono =
            clock_gettime_ns(libc::CLOCK_MONOTONIC).expect("read CLOCK_MONOTONIC after test");

        let bytes = skel
            .maps
            .test_time_result_map
            .lookup(&RESULT_KEY.to_le_bytes(), MapFlags::ANY)
            .expect("lookup test time result map")
            .expect("time test result missing");
        let result = read_unaligned::<types::time_test_result>(&bytes);

        assert!(
            result.tai_ns >= before_tai.saturating_sub(CLOCK_TOLERANCE_NS),
            "bpf_ktime_get_tai_ns() should not be older than CLOCK_TAI before test"
        );
        assert!(
            result.tai_ns <= after_tai.saturating_add(CLOCK_TOLERANCE_NS),
            "bpf_ktime_get_tai_ns() should be close to CLOCK_TAI after test"
        );

        assert!(
            result.mono_ns >= before_mono.saturating_sub(CLOCK_TOLERANCE_NS)
                && result.mono_ns <= after_mono.saturating_add(CLOCK_TOLERANCE_NS),
            "bpf_ktime_get_ns() should track CLOCK_MONOTONIC"
        );
        assert!(
            result.boot_ns >= result.mono_ns.saturating_sub(CLOCK_TOLERANCE_NS),
            "bpf_ktime_get_boot_ns() should not lag behind monotonic time in test context"
        );

        assert!(
            result.tai_ns.abs_diff(result.mono_ns) > RELATIVE_TIME_MIN_GAP_NS,
            "TAI helper must be absolute time, not monotonic uptime"
        );
        assert!(
            result.tai_ns.abs_diff(result.boot_ns) > RELATIVE_TIME_MIN_GAP_NS,
            "TAI helper must be absolute time, not boot-relative uptime"
        );
    }
}
