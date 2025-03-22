use std::{collections::HashSet, fs::OpenOptions, io::Write, path::Path};

use landscape_ebpf::map_setting;
use serde::{Deserialize, Serialize};

use crate::{
    firewall::FirewallServiceConfig,
    iface::config::NetworkIfaceConfig,
    service::{
        ipconfig::IfaceIpServiceConfig, ipv6pd::IPV6PDServiceConfig, nat_service::NatServiceConfig,
        packet_mark_service::PacketMarkServiceConfig, pppd_service::PPPDServiceConfig,
        ra::IPV6RAServiceConfig,
    },
};
use landscape_common::{
    args::LAND_ARGS,
    dns::DNSRuleConfig,
    error::{LdError, LdResult},
    firewall::FirewallRuleConfig,
    ip_mark::{LanIPRuleConfig, WanIPRuleConfig},
    INIT_FILE_NAME, INIT_LOCK_FILE_NAME,
};

pub mod log;

const INIT_LOCK_FILE_CONTENT: &'static str = r#"⚠ 警告 ⚠
如果您不知道删除这个文件的操作是否正确, 请不要删除这个文件.
此文件用于确定当前的 Landscape Router 是否已经初始化.
删除后将会依照 landscape_init.toml 中的配置进行初始化.
如果不存在 landscape_init.toml 则会清空已有的所有配置.

⚠ WARNING ⚠
If you don't know whether deleting this file is correct, please do not delete it.
This file is used to determine whether the current Landscape Router has been initialized.
After deletion, it will be initialized according to the configuration in landscape_init.toml.
If landscape_init.toml does not exist, all existing configurations will be cleared.
"#;

/// 返回是否进行初始化操作  
/// Some: 需要清空并初始化  
/// None: 无需进行初始化  
/// Err: 出现错误退出  
pub fn boot_check<P: AsRef<Path>>(home_path: P) -> LdResult<Option<InitConfig>> {
    let lock_path = home_path.as_ref().join(INIT_LOCK_FILE_NAME);

    if !lock_path.exists() {
        let mut file =
            OpenOptions::new().write(true).truncate(true).create(true).open(&lock_path)?;
        file.write_all(INIT_LOCK_FILE_CONTENT.as_bytes())?;

        drop(file);
        let config_path = home_path.as_ref().join(INIT_FILE_NAME);
        let config = if config_path.exists() && config_path.is_file() {
            let config_raw = std::fs::read_to_string(config_path).unwrap();
            toml::from_str(&config_raw).unwrap()
        } else {
            InitConfig::default()
        };
        return Ok(Some(config));
    }

    if lock_path.is_file() {
        return Ok(None);
    }

    Err(LdError::Boot("check boot lock file faile: is not a file".to_string()))
}

/// 初始化配置结构体
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct InitConfig {
    pub ifaces: Vec<NetworkIfaceConfig>,
    pub ipconfigs: Vec<IfaceIpServiceConfig>,
    pub nats: Vec<NatServiceConfig>,
    pub marks: Vec<PacketMarkServiceConfig>,
    pub pppds: Vec<PPPDServiceConfig>,
    pub dns_rules: Vec<DNSRuleConfig>,

    pub lan_ip_mark: Vec<LanIPRuleConfig>,
    pub wan_ip_mark: Vec<WanIPRuleConfig>,

    pub dhcpv6pds: Vec<IPV6PDServiceConfig>,
    pub icmpras: Vec<IPV6RAServiceConfig>,

    pub firewalls: Vec<FirewallServiceConfig>,
    pub firewall_rules: Vec<FirewallRuleConfig>,
}

pub fn init_ports() {
    // ssh port
    map_setting::add_expose_port(22);

    #[cfg(debug_assertions)]
    {
        map_setting::add_expose_port(5173);
        map_setting::add_expose_port(5800);
    }
    #[cfg(not(debug_assertions))]
    {}

    if LAND_ARGS.export_manager {
        map_setting::add_expose_port(LAND_ARGS.port);
    }

    if let Some(ports) = &LAND_ARGS.through_nat_port {
        let mut insert_ports = HashSet::new();
        for port in ports {
            if port.start <= port.end {
                for insert_port in port.start..=port.end {
                    insert_ports.insert(insert_port);
                }
            } else {
                tracing::error!("port range error: {port:?}");
            }
        }
        let ports = insert_ports.into_iter().collect();
        tracing::debug!("through nat ports: {:?}", ports);
        map_setting::add_expose_ports(ports);
    }
}
