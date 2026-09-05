use super::cmd::{cmd_ok, cmd_ok_ignore_failure, resolve_iface};
use landscape_common::net::MacAddr;

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
            client_ns: format!("ld-e2e-cl-{id:04x}"),
            server_ns: format!("ld-e2e-sv-{id:04x}"),
            client_iface: format!("ld-e2e-c-{id:04x}"),
            server_iface: format!("ld-e2e-s-{id:04x}"),
            client_mac: "02:00:00:00:00:11".into(),
            server_mac: "02:00:00:00:00:22".into(),
            username: "pppoe-user".into(),
            password: "pppoe-pass".into(),
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
    server_mac: MacAddr,
    client_info: ClientIfaceInfo,
}

impl PPPoETestEnv {
    /// Bring up the topology: two netns joined by a veth pair.  The PPPoE
    /// server side is provided by the scripted server, not by an external
    /// `pppoe-server` binary.
    pub(super) fn up(cfg: &EnvConfig) -> Result<Self, String> {
        // 1. Create both network namespaces
        cmd_ok("ip", &["netns", "add", &cfg.client_ns])?;
        cmd_ok("ip", &["netns", "add", &cfg.server_ns])?;

        // 2. Create veth pair (temporarily in root namespace)
        cmd_ok(
            "ip",
            &["link", "add", &cfg.client_iface, "type", "veth", "peer", "name", &cfg.server_iface],
        )?;

        // 3. Set MAC addresses before moving (in root namespace)
        cmd_ok("ip", &["link", "set", "dev", &cfg.client_iface, "address", &cfg.client_mac])?;
        cmd_ok("ip", &["link", "set", "dev", &cfg.server_iface, "address", &cfg.server_mac])?;

        // 4. Resolve both ends (capture ifindex + MAC) BEFORE moving to netns
        let resolved_client = resolve_iface(&cfg.client_iface)?;
        let client_info = ClientIfaceInfo {
            index: resolved_client.index,
            name: resolved_client.name.clone(),
            mac: resolved_client
                .mac
                .ok_or_else(|| format!("no MAC on {}", cfg.client_iface))?
                .octets()
                .into(),
        };
        let server_mac: MacAddr = resolve_iface(&cfg.server_iface)?
            .mac
            .ok_or_else(|| format!("no MAC on {}", cfg.server_iface))?
            .octets()
            .into();

        // 5. Move each end into its namespace
        cmd_ok("ip", &["link", "set", &cfg.client_iface, "netns", &cfg.client_ns])?;
        cmd_ok("ip", &["link", "set", &cfg.server_iface, "netns", &cfg.server_ns])?;

        // 6. Bring interfaces up inside their namespaces
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

        Ok(Self {
            client_ns: cfg.client_ns.clone(),
            server_ns: cfg.server_ns.clone(),
            server_iface: cfg.server_iface.clone(),
            server_mac,
            client_info,
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

    pub(super) fn server_mac(&self) -> MacAddr {
        self.server_mac
    }

    pub(super) fn client_info(&self) -> &ClientIfaceInfo {
        &self.client_info
    }

    /// Bring the server-side veth up/down — a real link-level loss for the
    /// client (packets stop flowing in both directions).
    pub(super) fn set_server_link(&self, up: bool) -> Result<(), String> {
        let verb = if up { "up" } else { "down" };
        cmd_ok(
            "ip",
            &[
                "netns",
                "exec",
                self.server_ns.as_str(),
                "ip",
                "link",
                "set",
                "dev",
                self.server_iface.as_str(),
                verb,
            ],
        )
    }
}

impl Drop for PPPoETestEnv {
    fn drop(&mut self) {
        // Deleting the namespaces also cleans up the veth interfaces.
        cmd_ok_ignore_failure("ip", &["netns", "del", &self.client_ns]);
        cmd_ok_ignore_failure("ip", &["netns", "del", &self.server_ns]);
    }
}
