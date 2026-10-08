//! `config` subcommand: generate a `landscape_init.toml` from high-level
//! deployment options.
//!
//! The command is intentionally decoupled from the exact `InitConfig` layout:
//! callers pass deployment-level flags (`--wan-mode`, `--lan-iface`, ...) and
//! this module expands them into the concrete init config. Interface names are
//! always explicit; no interface probing is performed.

mod args;
mod error;
mod generate;
mod output;

pub use args::{ConfigCliArgs, PppdPluginArg, WanMode};
pub use error::ConfigCliError;
pub use output::{ConfigOutput, render_init_config, run_config_cli, write_init_config_file};

const DEFAULT_LAN_IP: &str = "192.168.5.1/24";
const DEFAULT_PPPOE_MTU: u32 = 1492;
const DEFAULT_PPPD_IFACE: &str = "ppp0";
const DEFAULT_MSS_CLAMP_SIZE: u16 = 1492;

const KNOWN_SERVICES: &[&str] = &["nat", "firewall", "mss-clamp", "route-wan", "route-lan"];
/// Enabled by default whenever the corresponding side (WAN or LAN) exists.
const BASE_ENABLED_SERVICES: &[&str] = &["nat", "route-wan", "route-lan"];
const WAN_SERVICES: &[&str] = &["nat", "firewall", "mss-clamp", "route-wan"];
const LAN_SERVICES: &[&str] = &["route-lan"];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::{CommandFactory, Parser};

    use crate::args::{LandscapeAction, WebCommArgs};

    use super::{ConfigCliArgs, PppdPluginArg, WanMode};

    #[test]
    fn clap_parses_config_subcommand() {
        let args = WebCommArgs::try_parse_from([
            "landscape",
            "config",
            "--wan-iface",
            "eth0",
            "--lan-iface",
            "br_lan",
            "--wan-mode",
            "static",
            "--wan-ip",
            "10.0.0.2/24",
            "--wan-gateway",
            "10.0.0.1",
            "--enable",
            "nat,firewall",
            "--lan-member",
            "eth1",
            "--lan-member",
            "eth2",
        ])
        .unwrap();

        match args.action {
            Some(LandscapeAction::Config(config)) => {
                assert_eq!(config.wan_iface.as_deref(), Some("eth0"));
                assert_eq!(config.wan_mode, WanMode::Static);
                assert_eq!(config.enable, vec!["nat".to_string(), "firewall".to_string()]);
                assert_eq!(config.lan_member, vec!["eth1".to_string(), "eth2".to_string()]);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn defaults_are_stable() {
        let config = ConfigCliArgs::default();
        assert_eq!(config.wan_mode, WanMode::Dhcp);
        assert!(config.wan_iface.is_none());
        assert!(config.lan_iface.is_none());
        assert_eq!(config.pppd_iface, "ppp0");
    }

    // ── CLI surface lock ─────────────────────────────────────────────────
    //
    // These tests intentionally fail whenever the public `config` flag surface
    // changes. Adding a flag requires updating the golden set below (a
    // backward-compatible change); removing/renaming a flag or changing a
    // default is a breaking change and must go through a deprecation cycle.

    fn config_command() -> clap::Command {
        WebCommArgs::command().find_subcommand("config").expect("config subcommand").clone()
    }

    fn long_flags(cmd: &clap::Command) -> BTreeSet<String> {
        cmd.get_arguments().filter_map(|arg| arg.get_long().map(str::to_string)).collect()
    }

    fn possible_values(cmd: &clap::Command, long: &str) -> BTreeSet<String> {
        cmd.get_arguments()
            .find(|arg| arg.get_long() == Some(long))
            .expect("argument exists")
            .get_possible_values()
            .iter()
            .map(|value| value.get_name().to_string())
            .collect()
    }

    #[test]
    fn config_cli_flags_are_locked() {
        let expected: BTreeSet<String> = [
            "stdout",
            "dir",
            "force",
            "admin-user",
            "admin-pass",
            "wan-iface",
            "wan-mode",
            "wan-ip",
            "wan-gateway",
            "wan-ipv6",
            "no-wan-default-route",
            "pppoe-username",
            "pppoe-password",
            "pppoe-ac-name",
            "pppoe-mtu",
            "pppd-iface",
            "pppd-plugin",
            "static-nat",
            "lan-iface",
            "lan-ip",
            "lan-member",
            "no-lan-dhcp",
            "lan-dhcp-range",
            "lan-dhcp-lease",
            "enable",
            "disable",
        ]
        .iter()
        .map(|flag| flag.to_string())
        .collect();

        assert_eq!(
            long_flags(&config_command()),
            expected,
            "config CLI flag surface changed; removing/renaming a flag is a breaking change"
        );
    }

    #[test]
    fn config_cli_force_keeps_short_flag() {
        let cmd = config_command();
        let force = cmd.get_arguments().find(|arg| arg.get_long() == Some("force")).unwrap();
        assert_eq!(force.get_short(), Some('f'));
    }

    #[test]
    fn config_cli_enums_are_locked() {
        let cmd = config_command();
        assert_eq!(
            possible_values(&cmd, "wan-mode"),
            BTreeSet::from(["dhcp", "static", "pppoe", "pppd", "none"].map(str::to_string))
        );
        assert_eq!(
            possible_values(&cmd, "pppd-plugin"),
            BTreeSet::from(["rp-pppoe", "pppoe"].map(str::to_string))
        );
    }

    #[test]
    fn config_cli_defaults_are_locked() {
        let args = ConfigCliArgs::default();
        assert_eq!(args.wan_mode, WanMode::Dhcp);
        assert_eq!(args.lan_ip, "192.168.5.1/24");
        assert_eq!(args.pppoe_mtu, 1492);
        assert_eq!(args.pppd_iface, "ppp0");
        assert_eq!(args.pppd_plugin, PppdPluginArg::RpPppoe);
    }

    fn default_services(
        mode: WanMode,
        wan_iface: Option<&str>,
        lan_iface: Option<&str>,
    ) -> BTreeSet<&'static str> {
        let mut args = ConfigCliArgs {
            wan_iface: wan_iface.map(str::to_string),
            lan_iface: lan_iface.map(str::to_string),
            wan_mode: mode,
            ..Default::default()
        };
        match mode {
            WanMode::Static => {
                args.wan_ip = Some("203.0.113.2/24".to_string());
                args.wan_gateway = Some("203.0.113.1".parse().unwrap());
            }
            WanMode::Pppoe | WanMode::Pppd => {
                args.pppoe_username = Some("user".to_string());
                args.pppoe_password = Some("pass".to_string());
            }
            _ => {}
        }

        let init = args.build_init_config().unwrap();
        let mut services = BTreeSet::new();
        if let Some(link) = init.wan_links.first() {
            if link.nat.enable {
                services.insert("nat");
            }
            if link.firewall.enable {
                services.insert("firewall");
            }
            if link.mss.enable {
                services.insert("mss-clamp");
            }
        }
        if !init.route_wans.is_empty() {
            services.insert("route-wan");
        }
        if !init.route_lans.is_empty() {
            services.insert("route-lan");
        }
        services
    }

    #[test]
    fn config_cli_default_services_are_locked() {
        let wan = Some("eth0");
        let lan = Some("br_lan");
        assert_eq!(
            default_services(WanMode::Dhcp, wan, lan),
            BTreeSet::from(["nat", "route-wan", "route-lan"])
        );
        assert_eq!(
            default_services(WanMode::Static, wan, lan),
            BTreeSet::from(["nat", "route-wan", "route-lan"])
        );
        assert_eq!(
            default_services(WanMode::Pppoe, wan, lan),
            BTreeSet::from(["nat", "mss-clamp", "route-wan", "route-lan"])
        );
        assert_eq!(
            default_services(WanMode::Pppd, wan, lan),
            BTreeSet::from(["nat", "mss-clamp", "route-wan", "route-lan"])
        );
        assert_eq!(default_services(WanMode::None, None, lan), BTreeSet::from(["route-lan"]));

        // WAN-only deployments drop route-lan from the defaults.
        assert_eq!(
            default_services(WanMode::Dhcp, wan, None),
            BTreeSet::from(["nat", "route-wan"])
        );
        assert_eq!(
            default_services(WanMode::Static, wan, None),
            BTreeSet::from(["nat", "route-wan"])
        );

        // `--wan-mode none` with an interface registers the WAN side without
        // address configuration; WAN services stay enabled.
        assert_eq!(
            default_services(WanMode::None, wan, lan),
            BTreeSet::from(["nat", "route-wan", "route-lan"])
        );

        // Empty deployments enable no services.
        assert!(default_services(WanMode::Dhcp, None, None).is_empty());
    }
}
