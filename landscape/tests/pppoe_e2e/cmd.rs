use pnet::datalink;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};

// ── helpers ──────────────────────────────────────────────────────────────────

pub(super) fn cmd_output(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to run `{cmd}`: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("`{cmd} {}` failed: {stderr}", args.join(" ")))
    }
}

pub(super) fn cmd_ok(cmd: &str, args: &[&str]) -> Result<(), String> {
    cmd_output(cmd, args).map(|_| ())
}

pub(super) fn cmd_ok_ignore_failure(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).stdout(Stdio::null()).stderr(Stdio::null()).status();
}

/// Resolve a network interface by name using pnet.
pub(super) fn resolve_iface(name: &str) -> Result<datalink::NetworkInterface, String> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| format!("interface not found: {name}"))
}

/// Enter a network namespace (affects only the calling thread).
pub(super) fn enter_netns(ns_name: &str) -> Result<(), String> {
    let path = format!("/var/run/netns/{ns_name}");
    let fd = fs::File::open(&path).map_err(|e| format!("open netns {path}: {e}"))?;
    let ret = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) };
    if ret != 0 {
        Err(format!("setns({ns_name}) failed: errno={}", unsafe { *libc::__errno_location() }))
    } else {
        Ok(())
    }
}
