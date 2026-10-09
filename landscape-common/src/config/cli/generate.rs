use std::net::Ipv4Addr;

use crate::{
    VERSION,
    config::{InitConfig, settings::LandscapeConfig},
    config_service::{
        iface::{CreateDevType, IfaceZoneType, NetworkIfaceConfig, WifiMode},
        static_nat::{
            config::StaticMapPair,
            config4::{StaticNatMappingV4Config, StaticNatV4Target},
        },
    },
    database::validator::ValidatableConfig,
    lan_service::{
        lan_dhcpv4::config::{DHCPv4ServerConfig, DHCPv4ServiceConfig},
        lan_route::RouteLanServiceConfig,
    },
    utils::{id::gen_database_uuid, time::get_f64_timestamp},
    wan_link::{
        WanLinkConfig, WanLinkFirewallConfig, WanLinkHealthCheckConfig, WanLinkKind,
        WanLinkMssConfig, WanLinkNatConfig, WanLinkV4Config, WanLinkV4Model,
    },
    wan_service::{nat::config::NatConfig, wan_route::RouteWanServiceConfig},
};

use super::{
    BASE_ENABLED_SERVICES, ConfigCliArgs, ConfigCliError, DEFAULT_MSS_CLAMP_SIZE, KNOWN_SERVICES,
    LAN_SERVICES, WAN_SERVICES, WanMode,
};

/// TCP protocol number, the only L4 protocol emitted by `--static-nat`.
const TCP_L4_PROTOCOL: u8 = 6;

impl ConfigCliArgs {
    fn default_route(&self) -> bool {
        !self.no_wan_default_route
    }

    fn resolve_enabled_services(
        &self,
        has_wan: bool,
        has_lan: bool,
    ) -> Result<Vec<&'static str>, ConfigCliError> {
        for name in self.enable.iter().chain(self.disable.iter()) {
            if !KNOWN_SERVICES.contains(&name.as_str()) {
                return Err(ConfigCliError::UnknownService(name.clone()));
            }
        }
        for name in &self.enable {
            if self.disable.contains(name) {
                return Err(ConfigCliError::ConflictingService(name.clone()));
            }
        }

        let mut enabled: Vec<&'static str> = BASE_ENABLED_SERVICES.to_vec();
        if matches!(self.wan_mode, WanMode::Pppoe | WanMode::Pppd) {
            enabled.push("mss-clamp");
        }
        for name in &self.enable {
            let known = KNOWN_SERVICES.iter().find(|k| **k == name.as_str()).unwrap();
            if !enabled.contains(known) {
                enabled.push(*known);
            }
        }
        enabled.retain(|name| !self.disable.iter().any(|d| d.as_str() == *name));
        if !has_wan {
            enabled.retain(|name| !WAN_SERVICES.contains(name));
        }
        if !has_lan {
            enabled.retain(|name| !LAN_SERVICES.contains(name));
        }

        Ok(enabled)
    }

    /// Build the [`InitConfig`] described by these arguments.
    ///
    /// The topology is driven solely by which interface names are passed:
    /// `--wan-iface` controls whether the WAN side exists and `--lan-iface`
    /// the LAN side. Flags belonging to an absent side are silently ignored.
    pub fn build_init_config(&self) -> Result<InitConfig, ConfigCliError> {
        let lan_iface = self.lan_iface.clone();
        let wan_iface = self.wan_iface.clone();

        let mut members = Vec::new();
        if lan_iface.is_some() {
            for member in &self.lan_member {
                if members.contains(member) {
                    continue;
                }
                if Some(member) == wan_iface.as_ref() || Some(member) == lan_iface.as_ref() {
                    return Err(ConfigCliError::InvalidLanMember(member.clone()));
                }
                members.push(member.clone());
            }
        }

        let enabled = self.resolve_enabled_services(wan_iface.is_some(), lan_iface.is_some())?;
        let static_nat_pairs =
            if wan_iface.is_some() { self.parse_static_nat_pairs()? } else { Vec::new() };
        let now = get_f64_timestamp();

        let mut ifaces = Vec::new();
        if let Some(wan_iface) = &wan_iface {
            ifaces.push(NetworkIfaceConfig {
                name: wan_iface.clone(),
                create_dev_type: CreateDevType::NoNeedToCreate,
                controller_name: None,
                zone_type: IfaceZoneType::Wan,
                enable_in_boot: true,
                wifi_mode: WifiMode::default(),
                xps_rps: None,
                update_at: now,
            });
        }
        if let Some(lan_iface) = &lan_iface {
            ifaces.push(NetworkIfaceConfig::crate_bridge(
                lan_iface.clone(),
                Some(IfaceZoneType::Lan),
            ));
            for member in &members {
                ifaces.push(NetworkIfaceConfig {
                    name: member.clone(),
                    create_dev_type: CreateDevType::NoNeedToCreate,
                    controller_name: Some(lan_iface.clone()),
                    zone_type: IfaceZoneType::default(),
                    enable_in_boot: true,
                    wifi_mode: WifiMode::default(),
                    xps_rps: None,
                    update_at: now,
                });
            }
        }

        let wan_link = wan_iface
            .as_deref()
            .map(|iface| self.build_wan_link(iface, &enabled, now))
            .transpose()?;
        // For pppd, the WAN-facing services bind to the PPP virtual interface.
        let wan_service_iface = wan_link.as_ref().map(|link| link.section_iface_name().to_string());

        let mut config = LandscapeConfig::default();
        if let Some(user) = &self.admin_user {
            if user.is_empty() {
                return Err(ConfigCliError::EmptyAdminCredential("admin-user"));
            }
            config.auth.admin_user = Some(user.clone());
        }
        if let Some(pass) = &self.admin_pass {
            if pass.is_empty() {
                return Err(ConfigCliError::EmptyAdminCredential("admin-pass"));
            }
            config.auth.admin_pass = Some(pass.clone());
        }

        let mut init = InitConfig {
            version: VERSION.to_string(),
            config,
            ifaces,
            wan_links: wan_link.clone().map(|link| vec![link]).unwrap_or_default(),
            ..Default::default()
        };

        if let (Some(link), Some(iface)) = (&wan_link, &wan_service_iface)
            && !static_nat_pairs.is_empty()
        {
            let mapping = StaticNatMappingV4Config {
                id: gen_database_uuid(),
                name: None,
                enable: true,
                remark: "generated by `landscape config`".to_string(),
                wan_link_id: Some(link.id),
                wan_iface_name: Some(iface.clone()),
                mapping_pair_ports: static_nat_pairs,
                lan_target: Some(StaticNatV4Target::Local),
                l4_protocols: vec![TCP_L4_PROTOCOL],
                update_at: now,
            };
            mapping
                .validate()
                .map_err(|e| ConfigCliError::InvalidStaticNatConfig(e.to_string()))?;
            if let Some(nat_config) = nat_ranges_of(link) {
                mapping
                    .validate_no_dynamic_port_overlap(&nat_config)
                    .map_err(|e| ConfigCliError::InvalidStaticNatConfig(e.to_string()))?;
            }
            init.static_nat_mappings_v4.push(mapping);
        }

        if let Some(lan_iface) = &lan_iface
            && !self.no_lan_dhcp
        {
            init.dhcpv4_services.push(self.build_dhcp_config(lan_iface, now)?);
        }

        if let Some(iface) = &wan_service_iface
            && enabled.contains(&"route-wan")
        {
            init.route_wans.push(RouteWanServiceConfig {
                iface_name: iface.clone(),
                enable: true,
                update_at: now,
            });
        }
        if let Some(lan_iface) = lan_iface.as_deref()
            && enabled.contains(&"route-lan")
        {
            push_route_lan(&mut init, lan_iface, now);
        }

        Ok(init)
    }

    /// Build the single WAN link described by `--wan-mode`; the enabled WAN
    /// services (`nat` / `firewall` / `mss-clamp`) become link sections.
    fn build_wan_link(
        &self,
        wan_iface: &str,
        enabled: &[&'static str],
        now: f64,
    ) -> Result<WanLinkConfig, ConfigCliError> {
        let mut link = WanLinkConfig {
            id: gen_database_uuid(),
            name: wan_iface.to_string(),
            attach_iface_name: wan_iface.to_string(),
            link_chain_id: 0,
            kind: WanLinkKind::Ethernet,
            v4: WanLinkV4Config::default(),
            pd: Default::default(),
            nat: WanLinkNatConfig::default(),
            firewall: WanLinkFirewallConfig::default(),
            mss: WanLinkMssConfig::default(),
            health_check: WanLinkHealthCheckConfig::default(),
            update_at: now,
        };

        match self.wan_mode {
            WanMode::Dhcp => {
                link.v4 = WanLinkV4Config {
                    enable: true,
                    model: WanLinkV4Model::DhcpClient {
                        hostname: None,
                        default_router: self.default_route(),
                        custome_opts: Vec::new(),
                    },
                };
            }
            WanMode::Static => {
                let raw = self.wan_ip.as_deref().ok_or(ConfigCliError::MissingWanIp)?;
                let (ipv4, mask) = parse_ipv4_cidr(raw)?;
                let gateway = self.wan_gateway.ok_or(ConfigCliError::MissingWanGateway)?;
                link.v4 = WanLinkV4Config {
                    enable: true,
                    model: WanLinkV4Model::Static {
                        ipv4: Some(ipv4),
                        ipv4_mask: Some(mask),
                        ipv6: self.wan_ipv6,
                        default_router: self.default_route(),
                        default_router_ip: Some(gateway),
                    },
                };
            }
            WanMode::Pppoe => {
                let (username, password) = self.pppoe_credentials("pppoe")?;
                link.kind = WanLinkKind::PppoeNative {
                    username,
                    password,
                    requested_mru: u16::try_from(self.pppoe_mtu).unwrap_or(1492),
                    ac_name: self.pppoe_ac_name.clone(),
                    lcp_echo_interval: None,
                    redial_backoff_base_secs: None,
                };
                link.v4 = WanLinkV4Config {
                    enable: true,
                    model: WanLinkV4Model::Ipcp { default_router: self.default_route() },
                };
            }
            WanMode::Pppd => {
                let (peer_id, password) = self.pppoe_credentials("pppd")?;
                link.kind = WanLinkKind::Pppd {
                    ppp_iface_name: self.pppd_iface.clone(),
                    peer_id,
                    password,
                    ac: self.pppoe_ac_name.clone(),
                    plugin: self.pppd_plugin.into(),
                };
                link.v4 = WanLinkV4Config {
                    enable: true,
                    model: WanLinkV4Model::Ipcp { default_router: self.default_route() },
                };
            }
            WanMode::None => {}
        }

        if enabled.contains(&"nat") {
            let defaults = NatConfig::default();
            link.nat = WanLinkNatConfig {
                enable: true,
                tcp_range: Some(defaults.tcp_range),
                udp_range: Some(defaults.udp_range),
                icmp_in_range: Some(defaults.icmp_in_range),
            };
        }
        if enabled.contains(&"firewall") {
            link.firewall = WanLinkFirewallConfig { enable: true };
        }
        if enabled.contains(&"mss-clamp") {
            link.mss = WanLinkMssConfig {
                enable: true,
                clamp_size: Some(DEFAULT_MSS_CLAMP_SIZE),
            };
        }

        Ok(link)
    }

    fn parse_static_nat_pairs(&self) -> Result<Vec<StaticMapPair>, ConfigCliError> {
        self.static_nat.iter().map(|raw| parse_static_nat_pair(raw)).collect()
    }

    fn pppoe_credentials(&self, mode: &'static str) -> Result<(String, String), ConfigCliError> {
        match (self.pppoe_username.clone(), self.pppoe_password.clone()) {
            (Some(username), Some(password)) if !username.is_empty() && !password.is_empty() => {
                Ok((username, password))
            }
            _ => Err(ConfigCliError::MissingPppoeCredentials(mode)),
        }
    }

    fn build_dhcp_config(
        &self,
        lan_iface: &str,
        now: f64,
    ) -> Result<DHCPv4ServiceConfig, ConfigCliError> {
        let (server_ip, network_mask) = parse_ipv4_cidr(&self.lan_ip)?;
        let (ip_range_start, ip_range_end) = match &self.lan_dhcp_range {
            Some(range) => parse_dhcp_range(range)?,
            None => (default_dhcp_range_start(server_ip, network_mask), None),
        };

        let config = DHCPv4ServerConfig {
            ip_range_start,
            ip_range_end,
            server_ip_addr: server_ip,
            network_mask,
            address_lease_time: self.lan_dhcp_lease,
            custom_options: Vec::new(),
        };
        config.validate().map_err(|e| ConfigCliError::InvalidDhcpConfig(e.to_string()))?;

        Ok(DHCPv4ServiceConfig {
            iface_name: lan_iface.to_string(),
            enable: true,
            config,
            update_at: now,
        })
    }
}

/// The link's NAT dynamic port ranges as a [`NatConfig`], when the NAT
/// section is enabled with explicit ranges (None otherwise — no overlap
/// check applies without NAT).
fn nat_ranges_of(link: &WanLinkConfig) -> Option<NatConfig> {
    if !link.nat.enable {
        return None;
    }
    Some(NatConfig {
        tcp_range: link.nat.tcp_range.clone()?,
        udp_range: link.nat.udp_range.clone()?,
        icmp_in_range: link.nat.icmp_in_range.clone()?,
    })
}

fn parse_ipv4_cidr(raw: &str) -> Result<(Ipv4Addr, u8), ConfigCliError> {
    let (ip, prefix) =
        raw.split_once('/').ok_or_else(|| ConfigCliError::InvalidCidr(raw.into()))?;
    let ip = ip
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| ConfigCliError::InvalidIp(ip.trim().to_string()))?;
    let prefix = prefix
        .trim()
        .parse::<u8>()
        .map_err(|_| ConfigCliError::InvalidPrefix(prefix.trim().to_string()))?;
    if prefix > 32 {
        return Err(ConfigCliError::InvalidPrefix(prefix.to_string()));
    }
    Ok((ip, prefix))
}

fn parse_dhcp_range(raw: &str) -> Result<(Ipv4Addr, Option<Ipv4Addr>), ConfigCliError> {
    let (start, end) = match raw.split_once('-') {
        Some((start, end)) => (start, Some(end)),
        None => (raw, None),
    };
    let start = start
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| ConfigCliError::InvalidDhcpRange(raw.to_string()))?;
    let end = match end {
        Some(end) => Some(
            end.trim()
                .parse::<Ipv4Addr>()
                .map_err(|_| ConfigCliError::InvalidDhcpRange(raw.to_string()))?,
        ),
        None => None,
    };
    Ok((start, end))
}

fn parse_static_nat_pair(raw: &str) -> Result<StaticMapPair, ConfigCliError> {
    let invalid = || ConfigCliError::InvalidStaticNat(raw.to_string());
    let (wan_port, lan_port) = raw.split_once(':').ok_or_else(invalid)?;
    let wan_port = wan_port.trim().parse::<u16>().map_err(|_| invalid())?;
    let lan_port = lan_port.trim().parse::<u16>().map_err(|_| invalid())?;
    Ok(StaticMapPair { wan_port, lan_port })
}

fn push_route_lan(init: &mut InitConfig, lan_iface: &str, now: f64) {
    init.route_lans.push(RouteLanServiceConfig {
        iface_name: lan_iface.to_string(),
        enable: true,
        static_routes: None,
        update_at: now,
    });
}

fn default_dhcp_range_start(server_ip: Ipv4Addr, network_mask: u8) -> Ipv4Addr {
    let mask_bits = if network_mask == 0 { 0 } else { u32::MAX << (32 - network_mask) };
    let network = u32::from(server_ip) & mask_bits;
    let broadcast = network | !mask_bits;
    let start = network.saturating_add(100);
    if start >= broadcast {
        Ipv4Addr::from(network.saturating_add(2))
    } else {
        Ipv4Addr::from(start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::cli::{DEFAULT_PPPD_IFACE, DEFAULT_PPPOE_MTU},
        wan_service::pppd::PPPoEPlugin,
    };

    fn base_args() -> ConfigCliArgs {
        ConfigCliArgs {
            wan_iface: Some("eth0".to_string()),
            lan_iface: Some("br_lan".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn default_dhcp_generation_matches_expected_shape() {
        let init = base_args().build_init_config().unwrap();

        assert_eq!(init.version, VERSION);
        assert_eq!(init.ifaces.len(), 2);
        assert_eq!(init.ifaces[0].name, "eth0");
        assert_eq!(init.ifaces[0].zone_type, IfaceZoneType::Wan);
        assert_eq!(init.ifaces[1].name, "br_lan");
        assert_eq!(init.ifaces[1].zone_type, IfaceZoneType::Lan);

        assert_eq!(init.wan_links.len(), 1);
        let link = &init.wan_links[0];
        assert_eq!(link.attach_iface_name, "eth0");
        assert!(matches!(link.kind, WanLinkKind::Ethernet));
        assert!(link.v4.enable);
        assert!(matches!(&link.v4.model, WanLinkV4Model::DhcpClient { default_router: true, .. }));

        assert_eq!(init.dhcpv4_services.len(), 1);
        let dhcp = &init.dhcpv4_services[0].config;
        assert_eq!(dhcp.server_ip_addr, Ipv4Addr::new(192, 168, 5, 1));
        assert_eq!(dhcp.network_mask, 24);
        assert_eq!(dhcp.ip_range_start, Ipv4Addr::new(192, 168, 5, 100));

        assert!(link.nat.enable);
        assert_eq!(init.route_wans.len(), 1);
        assert_eq!(init.route_lans.len(), 1);
        assert!(!link.mss.enable);
        assert!(!link.firewall.enable);
    }

    #[test]
    fn omitted_wan_iface_builds_lan_only() {
        let args = ConfigCliArgs {
            wan_iface: None,
            lan_iface: Some("br_lan".to_string()),
            ..Default::default()
        };
        let init = args.build_init_config().unwrap();

        assert!(init.ifaces.iter().all(|iface| iface.zone_type != IfaceZoneType::Wan));
        assert!(init.wan_links.is_empty());
        assert!(init.route_wans.is_empty());
        assert_eq!(init.route_lans.len(), 1);
        assert_eq!(init.dhcpv4_services.len(), 1);
    }

    #[test]
    fn omitted_both_ifaces_builds_empty_config() {
        let args = ConfigCliArgs::default();
        let init = args.build_init_config().unwrap();

        assert!(init.ifaces.is_empty());
        assert!(init.wan_links.is_empty());
        assert!(init.route_wans.is_empty());
        assert!(init.route_lans.is_empty());
        assert!(init.dhcpv4_services.is_empty());
        assert!(init.static_nat_mappings_v4.is_empty());
        assert_eq!(init.version, VERSION);
    }

    #[test]
    fn wan_only_omits_lan_bridge_dhcp_and_route_lan() {
        let args = ConfigCliArgs {
            wan_iface: Some("eth0".to_string()),
            lan_iface: None,
            ..Default::default()
        };
        let init = args.build_init_config().unwrap();

        assert_eq!(init.ifaces.len(), 1);
        assert_eq!(init.ifaces[0].name, "eth0");
        assert_eq!(init.ifaces[0].zone_type, IfaceZoneType::Wan);

        assert_eq!(init.dhcpv4_services.len(), 0);
        assert_eq!(init.route_lans.len(), 0);
        assert!(init.wan_links[0].nat.enable);
        assert_eq!(init.route_wans.len(), 1);
        assert!(init.static_nat_mappings_v4.is_empty());
    }

    #[test]
    fn wan_only_ignores_lan_scoped_flags() {
        let cases: Vec<ConfigCliArgs> = vec![
            ConfigCliArgs {
                wan_iface: Some("eth0".to_string()),
                lan_member: vec!["eth1".to_string()],
                ..Default::default()
            },
            ConfigCliArgs {
                wan_iface: Some("eth0".to_string()),
                no_lan_dhcp: true,
                ..Default::default()
            },
            ConfigCliArgs {
                wan_iface: Some("eth0".to_string()),
                lan_dhcp_range: Some("192.168.5.10".to_string()),
                ..Default::default()
            },
            ConfigCliArgs {
                wan_iface: Some("eth0".to_string()),
                lan_dhcp_lease: Some(3600),
                ..Default::default()
            },
            ConfigCliArgs {
                wan_iface: Some("eth0".to_string()),
                lan_ip: "10.0.0.1/24".to_string(),
                ..Default::default()
            },
        ];
        for args in cases {
            let init = args.build_init_config().unwrap();
            assert_eq!(init.ifaces.len(), 1, "only the WAN interface is written");
            assert!(init.dhcpv4_services.is_empty());
            assert!(init.route_lans.is_empty());
        }
    }

    #[test]
    fn wan_only_strips_explicit_lan_service() {
        let args = ConfigCliArgs {
            wan_iface: Some("eth0".to_string()),
            enable: vec!["route-lan".to_string()],
            ..Default::default()
        };
        let init = args.build_init_config().unwrap();
        assert!(init.route_lans.is_empty());
        assert!(init.wan_links[0].nat.enable);
        assert_eq!(init.route_wans.len(), 1);
    }

    #[test]
    fn admin_credentials_land_in_config_auth() {
        let mut args = base_args();
        args.admin_user = Some("admin".to_string());
        args.admin_pass = Some("secret".to_string());

        let init = args.build_init_config().unwrap();
        assert_eq!(init.config.auth.admin_user.as_deref(), Some("admin"));
        assert_eq!(init.config.auth.admin_pass.as_deref(), Some("secret"));

        let init = base_args().build_init_config().unwrap();
        assert_eq!(init.config.auth.admin_user, None);
        assert_eq!(init.config.auth.admin_pass, None);
    }

    #[test]
    fn partial_admin_credentials_are_allowed() {
        let mut args = base_args();
        args.admin_pass = Some("secret".to_string());
        let init = args.build_init_config().unwrap();
        assert_eq!(init.config.auth.admin_user, None);
        assert_eq!(init.config.auth.admin_pass.as_deref(), Some("secret"));
    }

    #[test]
    fn empty_admin_credentials_are_rejected() {
        let mut args = base_args();
        args.admin_user = Some(String::new());
        assert!(matches!(
            args.build_init_config(),
            Err(ConfigCliError::EmptyAdminCredential("admin-user"))
        ));

        let mut args = base_args();
        args.admin_pass = Some(String::new());
        assert!(matches!(
            args.build_init_config(),
            Err(ConfigCliError::EmptyAdminCredential("admin-pass"))
        ));
    }

    #[test]
    fn static_nat_pairs_become_one_local_tcp_mapping() {
        let mut args = base_args();
        args.wan_mode = WanMode::Static;
        args.wan_ip = Some("203.0.113.2/24".to_string());
        args.wan_gateway = Some(Ipv4Addr::new(203, 0, 113, 1));
        args.static_nat = vec!["22:22".to_string(), "6443:16443".to_string()];

        let init = args.build_init_config().unwrap();
        assert_eq!(init.static_nat_mappings_v4.len(), 1);
        let mapping = &init.static_nat_mappings_v4[0];
        assert!(mapping.enable);
        assert_eq!(mapping.wan_iface_name.as_deref(), Some("eth0"));
        assert_eq!(mapping.wan_link_id, Some(init.wan_links[0].id));
        assert_eq!(
            mapping.mapping_pair_ports,
            vec![
                StaticMapPair { wan_port: 22, lan_port: 22 },
                StaticMapPair { wan_port: 6443, lan_port: 16443 }
            ]
        );
        assert_eq!(mapping.lan_target, Some(StaticNatV4Target::Local));
        assert_eq!(mapping.l4_protocols, vec![TCP_L4_PROTOCOL]);
    }

    #[test]
    fn static_nat_attaches_to_pppd_iface() {
        let mut args = base_args();
        args.wan_mode = WanMode::Pppd;
        args.pppoe_username = Some("user".to_string());
        args.pppoe_password = Some("pass".to_string());
        args.static_nat = vec!["22:22".to_string()];

        let init = args.build_init_config().unwrap();
        assert_eq!(init.static_nat_mappings_v4[0].wan_iface_name.as_deref(), Some("ppp0"));
    }

    #[test]
    fn static_nat_without_wan_iface_is_ignored() {
        let args = ConfigCliArgs {
            lan_iface: Some("br_lan".to_string()),
            static_nat: vec!["22:22".to_string()],
            ..Default::default()
        };
        let init = args.build_init_config().unwrap();
        assert!(init.static_nat_mappings_v4.is_empty());
    }

    #[test]
    fn invalid_static_nat_is_rejected() {
        let mut args = base_args();
        args.static_nat = vec!["22".to_string()];
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::InvalidStaticNat(_))));

        args.static_nat = vec!["a:b".to_string()];
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::InvalidStaticNat(_))));

        // Port 0 is rejected by the mapping validation.
        args.static_nat = vec!["0:22".to_string()];
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::InvalidStaticNatConfig(_))));

        // Duplicate WAN ports would produce conflicting DNAT rules.
        args.static_nat = vec!["22:22".to_string(), "22:8080".to_string()];
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::InvalidStaticNatConfig(_))));
    }

    #[test]
    fn static_nat_wan_port_in_nat_dynamic_range_is_rejected() {
        let mut args = base_args();
        args.static_nat = vec!["40000:22".to_string()];
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::InvalidStaticNatConfig(_))));

        let err = args.build_init_config().unwrap_err().to_string();
        assert!(err.contains("overlaps the NAT dynamic port range"), "got: {err}");
    }

    #[test]
    fn static_nat_dynamic_range_check_requires_nat_service() {
        let mut args = base_args();
        args.disable = vec!["nat".to_string()];
        args.static_nat = vec!["40000:22".to_string()];

        let init = args.build_init_config().unwrap();
        assert!(!init.wan_links[0].nat.enable);
        assert_eq!(init.static_nat_mappings_v4.len(), 1);
        assert_eq!(init.static_nat_mappings_v4[0].mapping_pair_ports[0].wan_port, 40000);
    }

    #[test]
    fn wan_mode_none_omits_wan_iface_and_wan_services() {
        let args = ConfigCliArgs {
            wan_iface: None,
            wan_mode: WanMode::None,
            lan_iface: Some("br_lan".to_string()),
            ..Default::default()
        };
        let init = args.build_init_config().unwrap();

        assert!(init.ifaces.iter().all(|iface| iface.zone_type != IfaceZoneType::Wan));
        assert!(init.wan_links.is_empty());
        assert!(init.route_wans.is_empty());
        assert_eq!(init.route_lans.len(), 1);
    }

    #[test]
    fn lan_only_strips_explicit_wan_service() {
        let args = ConfigCliArgs {
            wan_mode: WanMode::None,
            lan_iface: Some("br_lan".to_string()),
            enable: vec!["nat".to_string()],
            ..Default::default()
        };
        let init = args.build_init_config().unwrap();
        assert!(init.wan_links.is_empty());
        assert_eq!(init.route_lans.len(), 1);
    }

    #[test]
    fn lan_only_disable_route_lan_is_respected() {
        let args = ConfigCliArgs {
            wan_mode: WanMode::None,
            lan_iface: Some("br_lan".to_string()),
            disable: vec!["route-lan".to_string()],
            ..Default::default()
        };
        let init = args.build_init_config().unwrap();
        assert!(init.route_lans.is_empty());
        assert_eq!(init.dhcpv4_services.len(), 1);
    }

    #[test]
    fn wan_mode_none_with_iface_registers_wan_without_address() {
        let args = ConfigCliArgs {
            wan_iface: Some("eth0".to_string()),
            wan_mode: WanMode::None,
            lan_iface: Some("br_lan".to_string()),
            ..Default::default()
        };
        let init = args.build_init_config().unwrap();

        let wan = init.ifaces.iter().find(|iface| iface.name == "eth0").unwrap();
        assert_eq!(wan.zone_type, IfaceZoneType::Wan);
        assert_eq!(init.wan_links.len(), 1);
        let link = &init.wan_links[0];
        assert!(!link.v4.enable);
        assert!(matches!(link.v4.model, WanLinkV4Model::Nothing));
        assert!(link.nat.enable);
        assert_eq!(init.route_wans.len(), 1);
        assert_eq!(init.route_wans[0].iface_name, "eth0");
        assert_eq!(init.route_lans.len(), 1);
        assert_eq!(init.dhcpv4_services.len(), 1);
    }

    #[test]
    fn pppd_without_wan_iface_omits_wan_services() {
        let args = ConfigCliArgs {
            wan_iface: None,
            wan_mode: WanMode::Pppd,
            lan_iface: Some("br_lan".to_string()),
            pppoe_username: Some("user".to_string()),
            pppoe_password: Some("pass".to_string()),
            ..Default::default()
        };
        let init = args.build_init_config().unwrap();

        assert!(init.wan_links.is_empty(), "no service may reference the uncreated ppp0");
        assert!(init.route_wans.is_empty());
        assert_eq!(init.route_lans.len(), 1);
    }

    #[test]
    fn static_mode_requires_ip_and_gateway() {
        let mut args = base_args();
        args.wan_mode = WanMode::Static;
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::MissingWanIp)));

        args.wan_ip = Some("203.0.113.2/24".to_string());
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::MissingWanGateway)));

        args.wan_gateway = Some(Ipv4Addr::new(203, 0, 113, 1));
        let init = args.build_init_config().unwrap();
        match &init.wan_links[0].v4.model {
            WanLinkV4Model::Static { ipv4, ipv4_mask, default_router_ip, .. } => {
                assert_eq!(*ipv4, Some(Ipv4Addr::new(203, 0, 113, 2)));
                assert_eq!(*ipv4_mask, Some(24));
                assert_eq!(*default_router_ip, Some(Ipv4Addr::new(203, 0, 113, 1)));
            }
            other => panic!("unexpected v4 model: {other:?}"),
        }
    }

    #[test]
    fn pppoe_mode_builds_native_link() {
        let mut args = base_args();
        args.wan_mode = WanMode::Pppoe;
        args.pppoe_username = Some("user".to_string());
        args.pppoe_password = Some("pass".to_string());
        args.pppoe_ac_name = Some("ac".to_string());

        let init = args.build_init_config().unwrap();
        assert_eq!(init.wan_links.len(), 1);
        let link = &init.wan_links[0];
        assert!(link.mss.enable, "pppoe defaults to mss-clamp");
        assert!(link.v4.enable);
        assert!(matches!(link.v4.model, WanLinkV4Model::Ipcp { default_router: true }));
        match &link.kind {
            WanLinkKind::PppoeNative { username, password, requested_mru, ac_name, .. } => {
                assert_eq!(username, "user");
                assert_eq!(password, "pass");
                assert_eq!(*requested_mru as u32, DEFAULT_PPPOE_MTU);
                assert_eq!(ac_name.as_deref(), Some("ac"));
            }
            other => panic!("unexpected link kind: {other:?}"),
        }
    }

    #[test]
    fn pppd_mode_builds_pppd_link_and_targets_ppp_iface() {
        let mut args = base_args();
        args.wan_mode = WanMode::Pppd;
        args.pppoe_username = Some("user".to_string());
        args.pppoe_password = Some("pass".to_string());

        let init = args.build_init_config().unwrap();
        assert_eq!(init.wan_links.len(), 1);
        let link = &init.wan_links[0];
        assert_eq!(link.attach_iface_name, "eth0");
        assert!(link.v4.enable);
        assert!(matches!(link.v4.model, WanLinkV4Model::Ipcp { default_router: true }));
        match &link.kind {
            WanLinkKind::Pppd { ppp_iface_name, peer_id, password, plugin, .. } => {
                assert_eq!(ppp_iface_name, DEFAULT_PPPD_IFACE);
                assert_eq!(peer_id, "user");
                assert_eq!(password, "pass");
                assert!(matches!(plugin, PPPoEPlugin::RpPppoe));
            }
            other => panic!("unexpected link kind: {other:?}"),
        }

        assert!(link.nat.enable);
        assert_eq!(init.route_wans[0].iface_name, DEFAULT_PPPD_IFACE);
        assert!(link.mss.enable, "pppd defaults to mss-clamp");
    }

    #[test]
    fn pppoe_credentials_are_required() {
        let mut args = base_args();
        args.wan_mode = WanMode::Pppoe;
        assert!(matches!(
            args.build_init_config(),
            Err(ConfigCliError::MissingPppoeCredentials("pppoe"))
        ));

        args.wan_mode = WanMode::Pppd;
        assert!(matches!(
            args.build_init_config(),
            Err(ConfigCliError::MissingPppoeCredentials("pppd"))
        ));
    }

    #[test]
    fn unknown_service_is_rejected() {
        let mut args = base_args();
        args.enable = vec!["dns".to_string()];
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::UnknownService(_))));
    }

    #[test]
    fn conflicting_service_is_rejected() {
        let mut args = base_args();
        args.enable = vec!["nat".to_string()];
        args.disable = vec!["nat".to_string()];
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::ConflictingService(_))));
    }

    #[test]
    fn disable_and_enable_adjust_defaults() {
        let mut args = base_args();
        args.disable = vec!["nat".to_string(), "route-lan".to_string()];
        args.enable = vec!["firewall".to_string()];
        let init = args.build_init_config().unwrap();

        assert!(!init.wan_links[0].nat.enable);
        assert!(init.route_lans.is_empty());
        assert!(init.wan_links[0].firewall.enable);
        assert!(!init.wan_links[0].mss.enable, "dhcp does not default mss-clamp");
    }

    #[test]
    fn mss_clamp_defaults_only_for_ppp_modes() {
        for mode in [WanMode::Dhcp, WanMode::Static] {
            let mut args = base_args();
            args.wan_mode = mode;
            if mode == WanMode::Static {
                args.wan_ip = Some("203.0.113.2/24".to_string());
                args.wan_gateway = Some(Ipv4Addr::new(203, 0, 113, 1));
            }
            let init = args.build_init_config().unwrap();
            assert!(!init.wan_links[0].mss.enable, "{mode:?} must not default mss-clamp");
        }

        for mode in [WanMode::Pppoe, WanMode::Pppd] {
            let mut args = base_args();
            args.wan_mode = mode;
            args.pppoe_username = Some("user".to_string());
            args.pppoe_password = Some("pass".to_string());
            let init = args.build_init_config().unwrap();
            assert!(init.wan_links[0].mss.enable, "{mode:?} must default mss-clamp");
        }
    }

    #[test]
    fn mss_clamp_can_be_explicitly_enabled_for_dhcp() {
        let mut args = base_args();
        args.enable = vec!["mss-clamp".to_string()];
        let init = args.build_init_config().unwrap();
        assert!(init.wan_links[0].mss.enable);
    }

    #[test]
    fn lan_members_attach_to_bridge() {
        let mut args = base_args();
        args.lan_member = vec!["eth1".to_string(), "eth2".to_string(), "eth1".to_string()];
        let init = args.build_init_config().unwrap();

        let bridges: Vec<_> = init.ifaces.iter().filter(|iface| iface.name == "br_lan").collect();
        assert_eq!(bridges.len(), 1);
        let eth1 = init.ifaces.iter().find(|iface| iface.name == "eth1").unwrap();
        assert_eq!(eth1.controller_name.as_deref(), Some("br_lan"));
        assert_eq!(
            init.ifaces.iter().filter(|iface| iface.name == "eth1").count(),
            1,
            "duplicate members must be deduplicated"
        );
    }

    #[test]
    fn lan_member_cannot_be_wan_or_lan_iface() {
        let mut args = base_args();
        args.lan_member = vec!["eth0".to_string()];
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::InvalidLanMember(_))));

        args.lan_member = vec!["br_lan".to_string()];
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::InvalidLanMember(_))));
    }

    #[test]
    fn lan_dhcp_can_be_disabled() {
        let mut args = base_args();
        args.no_lan_dhcp = true;
        let init = args.build_init_config().unwrap();
        assert!(init.dhcpv4_services.is_empty());
    }

    #[test]
    fn explicit_dhcp_range_and_lease_are_applied() {
        let mut args = base_args();
        args.lan_dhcp_range = Some("192.168.5.50-192.168.5.80".to_string());
        args.lan_dhcp_lease = Some(3600);
        let init = args.build_init_config().unwrap();

        let dhcp = &init.dhcpv4_services[0].config;
        assert_eq!(dhcp.ip_range_start, Ipv4Addr::new(192, 168, 5, 50));
        assert_eq!(dhcp.ip_range_end, Some(Ipv4Addr::new(192, 168, 5, 80)));
        assert_eq!(dhcp.address_lease_time, Some(3600));
    }

    #[test]
    fn invalid_dhcp_range_is_rejected() {
        let mut args = base_args();
        args.lan_dhcp_range = Some("192.168.5.200-192.168.5.10".to_string());
        assert!(matches!(args.build_init_config(), Err(ConfigCliError::InvalidDhcpConfig(_))));
    }
}
