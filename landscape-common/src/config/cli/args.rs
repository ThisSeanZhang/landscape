use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use clap::{Args, ValueEnum};

use crate::wan_service::pppd::PPPoEPlugin;

use super::{DEFAULT_LAN_IP, DEFAULT_PPPD_IFACE, DEFAULT_PPPOE_MTU};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum WanMode {
    #[default]
    Dhcp,
    Static,
    Pppoe,
    Pppd,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum PppdPluginArg {
    #[default]
    RpPppoe,
    Pppoe,
}

impl From<PppdPluginArg> for PPPoEPlugin {
    fn from(value: PppdPluginArg) -> Self {
        match value {
            PppdPluginArg::RpPppoe => PPPoEPlugin::RpPppoe,
            PppdPluginArg::Pppoe => PPPoEPlugin::Pppoe,
        }
    }
}

/// Generate a `landscape_init.toml` from high-level deployment options.
///
/// # Stability
///
/// This is a stable, public interface. Deployment tooling should depend only
/// on these flags, never on the on-disk `landscape_init.toml` layout. Adding
/// flags is a backward-compatible change; removing or renaming flags, or
/// changing their defaults, is a breaking change and must go through a
/// deprecation cycle.
///
/// The generated file embeds the running binary's version and can only be
/// imported by the same version, so always generate it with the target binary.
///
/// Interface names are always explicit; no interface probing is performed.
///
/// Supported topologies: WAN + LAN bridge (default), LAN-only
/// (`--wan-mode none`) and WAN-only (omit `--lan-iface`).
#[derive(Args, Debug, Clone)]
pub struct ConfigCliArgs {
    /// Print the generated TOML to stdout instead of writing a file
    #[arg(long)]
    pub stdout: bool,

    /// Write landscape_init.toml into this directory (default: home config dir)
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Overwrite an existing landscape_init.toml
    #[arg(short, long)]
    pub force: bool,

    // ── Auth ─────────────────────────────────────────────────────────────
    /// Admin username written to [config.auth] (default: root)
    #[arg(long, value_name = "USER")]
    pub admin_user: Option<String>,

    /// Admin password written to [config.auth] (default: root)
    #[arg(long, value_name = "PASS")]
    pub admin_pass: Option<String>,

    // ── WAN ──────────────────────────────────────────────────────────────
    /// WAN physical interface name (required unless --wan-mode none)
    #[arg(long, value_name = "NAME")]
    pub wan_iface: Option<String>,

    /// WAN address acquisition mode
    #[arg(long, value_enum, default_value_t = WanMode::Dhcp)]
    pub wan_mode: WanMode,

    /// Static WAN address, e.g. 203.0.113.2/24
    #[arg(long, value_name = "CIDR")]
    pub wan_ip: Option<String>,

    /// Static WAN default gateway
    #[arg(long, value_name = "IP")]
    pub wan_gateway: Option<Ipv4Addr>,

    /// Static WAN IPv6 address
    #[arg(long, value_name = "ADDR")]
    pub wan_ipv6: Option<Ipv6Addr>,

    /// Do not install a default route for the WAN interface
    #[arg(long)]
    pub no_wan_default_route: bool,

    /// PPPoE username (native pppoe: username, pppd: peer_id)
    #[arg(long, value_name = "USER")]
    pub pppoe_username: Option<String>,

    /// PPPoE password
    #[arg(long, value_name = "PASS")]
    pub pppoe_password: Option<String>,

    /// PPPoE access concentrator name
    #[arg(long, value_name = "NAME")]
    pub pppoe_ac_name: Option<String>,

    /// MTU for native --wan-mode pppoe
    #[arg(long, value_name = "MTU", default_value_t = DEFAULT_PPPOE_MTU)]
    pub pppoe_mtu: u32,

    /// PPP virtual interface name for --wan-mode pppd
    #[arg(long, value_name = "NAME", default_value = DEFAULT_PPPD_IFACE)]
    pub pppd_iface: String,

    /// PPPoE plugin for --wan-mode pppd
    #[arg(long, value_enum, default_value_t = PppdPluginArg::RpPppoe)]
    pub pppd_plugin: PppdPluginArg,

    // ── Static NAT ───────────────────────────────────────────────────────
    /// Static NAT port mapping to the router itself (TCP only, repeatable):
    /// <wan_port>:<lan_port>, e.g. --static-nat 22:22
    #[arg(long = "static-nat", value_name = "WAN_PORT:LAN_PORT")]
    pub static_nat: Vec<String>,

    // ── LAN ──────────────────────────────────────────────────────────────
    /// LAN bridge interface name (omit for a WAN-only deployment)
    #[arg(long, value_name = "NAME")]
    pub lan_iface: Option<String>,

    /// LAN bridge address, e.g. 192.168.5.1/24 (unused without --lan-iface)
    #[arg(long, value_name = "CIDR", default_value = DEFAULT_LAN_IP)]
    pub lan_ip: String,

    /// Physical interface to attach to the LAN bridge (repeatable)
    #[arg(long = "lan-member", value_name = "NAME")]
    pub lan_member: Vec<String>,

    /// Disable the LAN DHCPv4 server
    #[arg(long)]
    pub no_lan_dhcp: bool,

    /// DHCPv4 pool range: <start> or <start>-<end>
    #[arg(long, value_name = "RANGE")]
    pub lan_dhcp_range: Option<String>,

    /// DHCPv4 address lease time in seconds
    #[arg(long, value_name = "SECONDS")]
    pub lan_dhcp_lease: Option<u32>,

    // ── Services ─────────────────────────────────────────────────────────
    /// Services to enable (comma separated): nat, firewall, mss-clamp, route-wan, route-lan
    /// (mss-clamp is enabled by default only for pppoe/pppd)
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub enable: Vec<String>,

    /// Services to disable (comma separated), see --enable
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub disable: Vec<String>,
}

impl Default for ConfigCliArgs {
    fn default() -> Self {
        Self {
            stdout: false,
            dir: None,
            force: false,
            admin_user: None,
            admin_pass: None,
            wan_iface: None,
            wan_mode: WanMode::Dhcp,
            wan_ip: None,
            wan_gateway: None,
            wan_ipv6: None,
            no_wan_default_route: false,
            pppoe_username: None,
            pppoe_password: None,
            pppoe_ac_name: None,
            pppoe_mtu: DEFAULT_PPPOE_MTU,
            pppd_iface: DEFAULT_PPPD_IFACE.to_string(),
            pppd_plugin: PppdPluginArg::RpPppoe,
            static_nat: Vec::new(),
            lan_iface: None,
            lan_ip: DEFAULT_LAN_IP.to_string(),
            lan_member: Vec::new(),
            no_lan_dhcp: false,
            lan_dhcp_range: None,
            lan_dhcp_lease: None,
            enable: Vec::new(),
            disable: Vec::new(),
        }
    }
}
