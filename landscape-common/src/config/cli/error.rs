#[derive(Debug, thiserror::Error)]
pub enum ConfigCliError {
    #[error("--wan-iface is required when --wan-mode is not 'none'")]
    MissingWanIface,
    #[error("at least one of --wan-iface or --lan-iface is required")]
    MissingAnyIface,
    #[error("--{0} must not be empty when provided")]
    EmptyAdminCredential(&'static str),
    #[error("--wan-ip is required for --wan-mode static (format: <ip>/<prefix>)")]
    MissingWanIp,
    #[error("--wan-gateway is required for --wan-mode static")]
    MissingWanGateway,
    #[error("--pppoe-username and --pppoe-password are required for --wan-mode {0}")]
    MissingPppoeCredentials(&'static str),
    #[error("invalid CIDR '{0}', expected <ip>/<prefix>")]
    InvalidCidr(String),
    #[error("invalid IP address '{0}'")]
    InvalidIp(String),
    #[error("invalid prefix length '{0}'")]
    InvalidPrefix(String),
    #[error("invalid DHCP range '{0}', expected <start> or <start>-<end>")]
    InvalidDhcpRange(String),
    #[error(
        "unknown service '{0}', expected one of: nat, firewall, mss-clamp, route-wan, route-lan"
    )]
    UnknownService(String),
    #[error("service '{0}' appears in both --enable and --disable")]
    ConflictingService(String),
    #[error("service '{0}' requires --wan-mode other than 'none'")]
    WanServiceWithoutWan(String),
    #[error("service '{0}' requires --lan-iface")]
    LanServiceWithoutLan(String),
    #[error("--{0} requires --lan-iface")]
    LanFlagWithoutLan(&'static str),
    #[error("invalid static NAT mapping '{0}', expected <wan_port>:<lan_port>")]
    InvalidStaticNat(String),
    #[error("--static-nat requires --wan-mode other than 'none'")]
    StaticNatWithoutWan,
    #[error("invalid static NAT configuration: {0}")]
    InvalidStaticNatConfig(String),
    #[error("LAN member interface '{0}' must differ from --wan-iface and --lan-iface")]
    InvalidLanMember(String),
    #[error("invalid DHCP configuration: {0}")]
    InvalidDhcpConfig(String),
    #[error("init config at {0} already exists; pass --force to overwrite")]
    AlreadyExists(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize init config: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error(transparent)]
    InitConfig(#[from] crate::config::InitConfigError),
}
