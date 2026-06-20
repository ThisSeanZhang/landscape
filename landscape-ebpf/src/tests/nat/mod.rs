use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

pub(crate) static NAT_V3_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static NAT_TEST_PIN_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub(crate) mod test_nat6_v3;
mod v4;
mod v6;

pub(crate) fn isolated_pin_root(prefix: &str) -> PathBuf {
    let unique = NAT_TEST_PIN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = PathBuf::from(format!(
        "/sys/fs/bpf/landscape-test/{prefix}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create isolated bpf pin root");
    path
}
