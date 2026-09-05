mod cmd;
mod env;
mod runner;
mod scenarios;
mod scripted_server;

use std::fs;

/// Isolated BPF map space name for this test process.  `require_root()`
/// installs it via `LANDSCAPE_EBPF_MAP_SPACE` so the client's pipeline
/// pins its maps under a unique directory instead of the global `default`
/// space (hygiene; the tests assert per-interface artifacts, not these
/// shared maps).
pub(super) fn test_bpf_map_space() -> String {
    format!("pppoe-e2e-{}", std::process::id())
}

/// Tests need root (netns, veth, eBPF).  When not root, skip the whole
/// binary gracefully so `cargo test --workspace` stays green on dev
/// machines — mirrors the behaviour of the previous pppoe_integration
/// suite.  Tests are additionally `#[ignore]`d; `require_root` guards
/// manual `--include-ignored` runs.
pub(super) fn require_root() {
    std::env::set_var("LANDSCAPE_IGNORE_CLI_ARGS", "1");

    // Surface the client's tracing output in test logs (idempotent).
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();

    // Isolate the client's BPF map space for the whole test process so the
    // PPPoE pipeline pins its maps under a unique directory instead of the
    // global `default` space (LAND_ARGS is a process-global Lazy, so this
    // must be fixed before the first client connects).
    std::env::set_var("LANDSCAPE_EBPF_MAP_SPACE", test_bpf_map_space());

    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return,
    };
    let uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    if uid != 0 {
        eprintln!("skipping test: requires root privileges (current uid: {uid})");
        std::process::exit(0);
    }
}
