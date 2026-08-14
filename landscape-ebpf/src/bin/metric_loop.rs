use std::time::{Duration, Instant};

use landscape_core::time::get_boot_time_ns;

// cargo run --package landscape-ebpf --bin metric_loop

pub fn main() {
    const MILL_SECOND: u64 = 1_000_000_000;
    let interval = Duration::from_secs(1);

    let (mut next_tick, _next_sec) = if let Ok(current_time) = get_boot_time_ns() {
        let mill = current_time % MILL_SECOND;
        let next_sec = current_time / MILL_SECOND + 1;
        let wait_mill = MILL_SECOND - mill;
        let next_tick_interval = Duration::new(0, wait_mill as u32) + interval;
        (Instant::now() + next_tick_interval, next_sec)
    } else {
        return;
    };

    loop {
        println!("Tick at {:?}", Instant::now());

        let time = get_boot_time_ns().unwrap_or_default();
        println!("Tick at {:?}", time / 1_000_000_000);
        // 睡到精确的下一个时刻（避免时间漂移）
        let now = Instant::now();
        if now < next_tick {
            std::thread::sleep(next_tick - now);
        } else {
            // 如果执行过慢，跳过滞后的部分
            next_tick = now;
        }
        next_tick += interval;
    }
}
