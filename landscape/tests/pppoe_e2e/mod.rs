mod cmd;
mod env;
mod runner;
mod scenarios;
mod scripted_server;

use std::fs;
use std::path::PathBuf;

/// Isolated BPF map space name for one e2e scenario.  Each scenario pins its
/// maps under its own directory (`pppoe-e2e-{pid}-{scenario}`) instead of the
/// global `default` space (hygiene; the tests assert per-interface
/// artifacts, not these shared maps).  A per-scenario space also makes
/// parallel scenario execution safe: an `EbpfRuntime` exclusively owns its
/// space, so two scenarios calling `EbpfRuntime::init` on a shared space
/// would race on map creation and lose with `File exists` pin errors.
pub(super) fn test_bpf_map_space(scenario: &str) -> String {
    format!("pppoe-e2e-{}-{scenario}", std::process::id())
}

/// Removes the scenario's eBPF map space directory when dropped, so repeated
/// runs don't leak pinned maps (each pin keeps its kernel object — and its
/// kernel memory — alive even after the test process exits).
///
/// Declare it as the FIRST binding of a scenario so it drops LAST: after the
/// client has fully exited and released its map fds.  Drop also runs on
/// panic unwind, so a failing scenario still cleans up after itself.
pub(super) struct MapSpaceCleanup {
    root: PathBuf,
}

impl MapSpaceCleanup {
    pub(super) fn new(scenario: &str) -> Self {
        // Matches the bpffs root layout of `EbpfRuntime` (`root_for_space`).
        Self {
            root: PathBuf::from("/sys/fs/bpf/landscape").join(test_bpf_map_space(scenario)),
        }
    }
}

impl Drop for MapSpaceCleanup {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!("failed to clean up eBPF map space {}: {e}", self.root.display());
            }
        }
    }
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
