//! Test-only helpers shared by the in-crate unit tests (`maps::*`) and the
//! feature-gated integration test tree (`src/tests`). Kept out of
//! `src/tests` so unit tests compile without the `bpf-test` feature.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Ensure the BPF filesystem is mounted at `/sys/fs/bpf`.
///
/// BPF pinning (LIBBPF_PIN_BY_NAME) requires it; mount it once if missing.
pub(crate) fn ensure_bpffs() {
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let mounted = mounts.lines().any(|l| l.split_whitespace().nth(1) == Some("/sys/fs/bpf"));
    if mounted {
        return;
    }
    let _ = std::fs::create_dir_all("/sys/fs/bpf");
    let out = Command::new("mount")
        .args(["-t", "bpf", "bpf", "/sys/fs/bpf"])
        .output()
        .expect("mount bpf fs");
    assert!(
        out.status.success(),
        "mount bpf fs on /sys/fs/bpf failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

static TEST_PIN_ROOT_COUNTER: AtomicU32 = AtomicU32::new(0);

/// An isolated BPF pin root under `/sys/fs/bpf/landscape-test/`.
///
/// Maps declared with `LIBBPF_PIN_BY_NAME` are auto-pinned by libbpf on load,
/// so tests redirect them into a unique per-test directory. The directory is
/// removed on drop (after all skels referencing it have been dropped), so
/// pinned maps never outlive the test that created them.
pub(crate) struct PinRootGuard(PathBuf);

impl PinRootGuard {
    pub(crate) fn new(prefix: &str) -> Self {
        ensure_bpffs();
        let unique = TEST_PIN_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            "/sys/fs/bpf/landscape-test/{prefix}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create isolated bpf pin root");
        Self(path)
    }
}

impl Deref for PinRootGuard {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for PinRootGuard {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for PinRootGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn isolated_pin_root(prefix: &str) -> PinRootGuard {
    PinRootGuard::new(prefix)
}
