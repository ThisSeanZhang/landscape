use super::cmd::{cmd_ok, cmd_ok_ignore_failure, resolve_iface};
use landscape_common::net::MacAddr;
use std::fs;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

// ── configuration ────────────────────────────────────────────────────────────

pub(super) struct EnvConfig {
    pub(super) client_ns: String,
    pub(super) server_ns: String,
    pub(super) client_iface: String,
    pub(super) server_iface: String,
    pub(super) client_mac: String,
    pub(super) server_mac: String,
    pub(super) username: String,
    pub(super) password: String,
    pub(super) enable_ipv6cp: bool,
    /// If true, don't start pppoe-server (simulates unreachable server).
    pub(super) no_server: bool,
    /// Extra lines appended to the pppoe-server-options file.
    pub(super) extra_pppd_options: Vec<String>,
}

impl Default for EnvConfig {
    fn default() -> Self {
        let id: u16 = ((std::process::id() as u64).wrapping_add(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
        ) & 0xFFFF) as u16;
        Self {
            client_ns: format!("ld-pppoe-cl-{id:04x}"),
            server_ns: format!("ld-pppoe-sv-{id:04x}"),
            client_iface: format!("ld-pppoe-c-{id:04x}"),
            server_iface: format!("ld-pppoe-s-{id:04x}"),
            client_mac: "02:00:00:00:00:11".into(),
            server_mac: "02:00:00:00:00:22".into(),
            username: "pppoe-user".into(),
            password: "pppoe-pass".into(),
            enable_ipv6cp: true,
            no_server: false,
            extra_pppd_options: vec![],
        }
    }
}
pub(super) struct ClientConfig {
    pub(super) username: String,
    pub(super) password: String,
    pub(super) mtu: u16,
    pub(super) timeout_secs: u64,
    /// Whether to install a default route via the peer (maps to
    /// `PPPoEClientConfig::default_router`).
    pub(super) default_router: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            username: "pppoe-user".into(),
            password: "pppoe-pass".into(),
            mtu: 1492,
            timeout_secs: 30,
            default_router: false,
        }
    }
}

/// Snapshot of the client interface captured before moving it into its
/// namespace.  The ifindex is globally unique and stays valid across netns
/// moves.
pub(super) struct ClientIfaceInfo {
    pub(super) index: u32,
    pub(super) name: String,
    pub(super) mac: MacAddr,
}

// ── test environment (RAII) ──────────────────────────────────────────────────

pub(super) struct PPPoETestEnv {
    client_ns: String,
    server_ns: String,
    server_iface: String,
    client_info: ClientIfaceInfo,
    etc_netns_dir: PathBuf,
    _runtime_dir: TempDir,
    server_child: Option<Child>,
}

impl PPPoETestEnv {
    /// Bring up the full test environment: two netns, veth, pppoe-server.
    pub(super) fn up(cfg: &EnvConfig) -> Result<Self, String> {
        // 1. Runtime directory
        let runtime_dir = TempDir::new().map_err(|e| format!("tempdir: {e}"))?;
        let server_etc = PathBuf::from("/etc/netns").join(&cfg.server_ns).join("ppp");
        let pppd_log = runtime_dir.path().join("pppd.log");

        // 2. Write pppoe-server config under /etc/netns/{server_ns}/ppp
        fs::create_dir_all(&server_etc)
            .map_err(|e| format!("create {}: {e}", server_etc.display()))?;
        cmd_ok("chmod", &["700", &server_etc.to_string_lossy()])?;

        let ipv6_block: &str = if cfg.enable_ipv6cp {
            "+ipv6\nipv6cp-accept-local\nipv6cp-accept-remote"
        } else {
            "noipv6"
        };

        let extra = if cfg.extra_pppd_options.is_empty() {
            String::new()
        } else {
            format!("{}\n", cfg.extra_pppd_options.join("\n"))
        };
        let options_content = format!(
            "\
noauth
require-pap
refuse-chap
refuse-mschap
refuse-mschap-v2
{ipv6_block}
lcp-echo-interval 5
lcp-echo-failure 3
mtu 1492
mru 1492
debug
logfile {pppd_log}
{extra}",
            pppd_log = pppd_log.display(),
            extra = extra,
        );
        let options_path = server_etc.join("pppoe-server-options");
        fs::write(&options_path, &options_content)
            .map_err(|e| format!("write {}: {e}", options_path.display()))?;

        let pap_path = server_etc.join("pap-secrets");
        fs::write(&pap_path, format!("\"{}\" * \"{}\" *\n", cfg.username, cfg.password))
            .map_err(|e| format!("write {}: {e}", pap_path.display()))?;

        let chap_path = server_etc.join("chap-secrets");
        fs::write(&chap_path, "").map_err(|e| format!("write {}: {e}", chap_path.display()))?;
        cmd_ok("chmod", &["600", &pap_path.to_string_lossy(), &chap_path.to_string_lossy()])?;

        // 3. Create both network namespaces
        cmd_ok("ip", &["netns", "add", &cfg.client_ns])?;
        cmd_ok("ip", &["netns", "add", &cfg.server_ns])?;

        // 4. Create veth pair (temporarily in root namespace)
        cmd_ok(
            "ip",
            &["link", "add", &cfg.client_iface, "type", "veth", "peer", "name", &cfg.server_iface],
        )?;

        // 5. Set MAC addresses before moving (in root namespace)
        cmd_ok("ip", &["link", "set", "dev", &cfg.client_iface, "address", &cfg.client_mac])?;
        cmd_ok("ip", &["link", "set", "dev", &cfg.server_iface, "address", &cfg.server_mac])?;

        // 6. Resolve client iface (capture ifindex + MAC) BEFORE moving to netns
        let resolved = resolve_iface(&cfg.client_iface)?;
        let client_info = ClientIfaceInfo {
            index: resolved.index,
            name: resolved.name.clone(),
            mac: resolved
                .mac
                .ok_or_else(|| format!("no MAC on {}", cfg.client_iface))?
                .octets()
                .into(),
        };

        // 7. Move each end into its namespace
        cmd_ok("ip", &["link", "set", &cfg.client_iface, "netns", &cfg.client_ns])?;
        cmd_ok("ip", &["link", "set", &cfg.server_iface, "netns", &cfg.server_ns])?;

        // 8. Bring interfaces up inside their namespaces
        cmd_ok("ip", &["netns", "exec", &cfg.client_ns, "ip", "link", "set", "lo", "up"])?;
        cmd_ok(
            "ip",
            &["netns", "exec", &cfg.client_ns, "ip", "link", "set", &cfg.client_iface, "up"],
        )?;
        cmd_ok("ip", &["netns", "exec", &cfg.server_ns, "ip", "link", "set", "lo", "up"])?;
        cmd_ok(
            "ip",
            &["netns", "exec", &cfg.server_ns, "ip", "link", "set", &cfg.server_iface, "up"],
        )?;

        // 9. Optionally start pppoe-server in the server namespace
        let mut server_child: Option<Child> = None;

        if !cfg.no_server {
            let server_log = runtime_dir.path().join("pppoe-server.log");
            let server_pid_file = runtime_dir.path().join("pppoe-server.pid");
            // Open the log file once and dup the fd so both stdout and stderr
            // share the same underlying file.
            let server_log_file =
                fs::File::create(&server_log).map_err(|e| format!("server log: {e}"))?;
            let server_log_fd = server_log_file.as_raw_fd();
            let dup_fd = unsafe { libc::dup(server_log_fd) };
            if dup_fd < 0 {
                return Err("dup server log fd".into());
            }

            let mut child = Command::new("ip")
                .args([
                    "netns",
                    "exec",
                    &cfg.server_ns,
                    "pppoe-server",
                    "-F",
                    "-X",
                    &server_pid_file.to_string_lossy(),
                    "-I",
                    &cfg.server_iface,
                    "-C",
                    "landscape-test-ac",
                    "-S",
                    "landscape-test-service",
                    "-L",
                    "10.0.0.1",
                    "-R",
                    "10.0.0.100",
                    "-N",
                    "8",
                    "-O",
                    "/etc/ppp/pppoe-server-options",
                ])
                .stdout(Stdio::from(server_log_file))
                .stderr(unsafe { Stdio::from_raw_fd(dup_fd) })
                .spawn()
                .map_err(|e| format!("spawn pppoe-server: {e}"))?;

            // 10. Wait for server to be ready (poll PID file, up to 4 s)
            let mut ready = false;
            for _ in 0..20 {
                if server_pid_file.exists() {
                    if let Ok(pid_str) = fs::read_to_string(&server_pid_file) {
                        if !pid_str.trim().is_empty() {
                            ready = true;
                            break;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }

            if !ready {
                let log_tail = fs::read_to_string(&server_log).unwrap_or_default();
                let _ = child.kill();
                let _ = Command::new("ip").args(["netns", "del", &cfg.client_ns]).status();
                let _ = Command::new("ip").args(["netns", "del", &cfg.server_ns]).status();
                return Err(format!(
                    "pppoe-server did not become ready within 4 s.\nServer log:\n{log_tail}"
                ));
            }

            server_child = Some(child);
        }

        Ok(Self {
            client_ns: cfg.client_ns.clone(),
            server_ns: cfg.server_ns.clone(),
            server_iface: cfg.server_iface.clone(),
            client_info,
            etc_netns_dir: server_etc,
            _runtime_dir: runtime_dir,
            server_child,
        })
    }

    pub(super) fn client_ns(&self) -> &str {
        &self.client_ns
    }

    pub(super) fn server_ns(&self) -> &str {
        &self.server_ns
    }

    pub(super) fn server_iface(&self) -> &str {
        &self.server_iface
    }

    pub(super) fn server_pid(&self) -> Option<u32> {
        self.server_child.as_ref().map(|c| c.id())
    }

    pub(super) fn client_info(&self) -> &ClientIfaceInfo {
        &self.client_info
    }
}

impl Drop for PPPoETestEnv {
    fn drop(&mut self) {
        // Kill pppoe-server first
        if let Some(child) = self.server_child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Delete namespaces (this also cleans up veth interfaces)
        cmd_ok_ignore_failure("ip", &["netns", "del", &self.client_ns]);
        cmd_ok_ignore_failure("ip", &["netns", "del", &self.server_ns]);
        // Clean up /etc/netns/ files
        let _ = fs::remove_dir_all(&self.etc_netns_dir);
    }
}
