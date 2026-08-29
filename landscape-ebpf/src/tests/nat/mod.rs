use crate::tests::PinRootGuard;

pub(crate) static NAT_V3_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) mod test_nat6_v3;
mod v4;
mod v6;

pub(crate) fn isolated_pin_root(prefix: &str) -> PinRootGuard {
    PinRootGuard::new(prefix)
}
