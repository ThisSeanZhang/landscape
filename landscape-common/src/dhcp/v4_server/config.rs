use std::collections::HashSet;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::database::repository::LandscapeDBStore;
use crate::net_proto::udp::dhcp::{DhcpV4Option, Encodable};
use crate::service::ServiceConfigError;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;
use crate::LANDSCAPE_DEFAULT_LAN_NAME;

use crate::{
    LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START, LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP,
    LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK, LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME,
};

// ─── Option code classification ─────────────────────────────────────────────

/// DHCP option codes that cannot be used as custom options (protocol reserved).
const PROTOCOL_RESERVED_OPTION_CODES: &[u8] = &[
    0,   // Pad
    255, // End
];

/// DHCP option codes managed by the server (injected automatically).
/// - Cannot be overridden via custom_options
/// - Must NOT be filtered out from responses (would break DHCP functionality)
const SERVER_MANAGED_OPTION_CODES: &[u8] = &[
    1,  // Subnet Mask
    3,  // Router
    6,  // Domain Name Server
    51, // Address Lease Time
    53, // Message Type
    54, // Server Identifier
];

const MAX_CUSTOM_OPTION_DATA_LEN: usize = u8::MAX as usize;

/// Check if an option code is reserved and cannot be used as a custom option.
pub fn is_reserved_option_code(code: u8) -> bool {
    PROTOCOL_RESERVED_OPTION_CODES.contains(&code) || SERVER_MANAGED_OPTION_CODES.contains(&code)
}

/// Check if an option code is server-managed and must not be filtered out.
pub fn is_server_managed(code: u8) -> bool {
    SERVER_MANAGED_OPTION_CODES.contains(&code)
}

/// Human-readable name for common DHCP option codes (best-effort lookup).
fn option_code_name(code: u8) -> &'static str {
    match code {
        0 => "Pad",
        1 => "Subnet Mask",
        3 => "Router",
        6 => "Domain Name Server",
        12 => "Host Name",
        15 => "Domain Name",
        28 => "Broadcast Address",
        43 => "Vendor Extensions",
        51 => "Address Lease Time",
        53 => "Message Type",
        54 => "Server Identifier",
        66 => "TFTP Server Name",
        67 => "Bootfile Name",
        82 => "Relay Agent Information",
        255 => "End",
        _ => "unknown",
    }
}

// ─── RelayAgentInfo wrapper ──────────────────────────────────────────────────

/// Newtype wrapper for [`dhcproto::v4::relay::RelayAgentInformation`].
/// Required because the upstream type does not implement `utoipa::ToSchema`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = Object))]
pub struct RelayAgentInfo(pub dhcproto::v4::relay::RelayAgentInformation);

// ─── CustomDhcpOption ───────────────────────────────────────────────────────

/// Supported custom DHCP option types.
///
/// This enum is the **whitelist** of options that can be configured via API.
/// Each variant maps 1:1 to a frontend UI component.
///
/// JSON format (serde externally tagged):
/// ```json
/// {"TFTPServerName": "192.168.1.1"}
/// {"BootfileName": "ipxe.kpxe"}
/// {"VendorExtensions": "ff0001"}
/// {"RelayAgentInformation": {"AgentCircuitId": "010203"}}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum CustomDhcpOption {
    /// Option 66 — TFTP server name (iPXE, string)
    TFTPServerName(String),
    /// Option 67 — Boot file name (iPXE, string)
    BootfileName(String),
    /// Option 43 — Vendor-specific extensions (binary, hex string)
    VendorExtensions(String),
    /// Option 82 — Relay Agent Information (structured sub-options)
    RelayAgentInformation(RelayAgentInfo),
    /// Option 162 — Discovery of Network-designated Resolvers (RFC 9463)
    Dnr(DhcpV4DnrOptionConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum DhcpV4DnrOptionConfig {
    Local,
    Custom {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
        domains: Vec<String>,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
        ips: Vec<Ipv4Addr>,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        doh_path: Option<String>,
    },
}

impl CustomDhcpOption {
    /// DHCP option code for this custom option.
    pub fn code(&self) -> u8 {
        match self {
            CustomDhcpOption::TFTPServerName(_) => 66,
            CustomDhcpOption::BootfileName(_) => 67,
            CustomDhcpOption::VendorExtensions(_) => 43,
            CustomDhcpOption::RelayAgentInformation(RelayAgentInfo(_)) => 82,
            CustomDhcpOption::Dnr(_) => 162,
        }
    }

    /// Convert to dhcproto [`DhcpV4Option`].
    pub fn to_dhcp_option(&self) -> DhcpV4Option {
        match self {
            CustomDhcpOption::TFTPServerName(s) => {
                DhcpV4Option::TFTPServerName(s.as_bytes().to_vec())
            }
            CustomDhcpOption::BootfileName(s) => DhcpV4Option::BootfileName(s.as_bytes().to_vec()),
            CustomDhcpOption::VendorExtensions(hex) => {
                DhcpV4Option::VendorExtensions(hex_decode(hex).expect("validated hex string"))
            }
            CustomDhcpOption::RelayAgentInformation(RelayAgentInfo(info)) => {
                DhcpV4Option::RelayAgentInformation(info.clone())
            }
            CustomDhcpOption::Dnr(_) => unreachable!("DNR is encoded with runtime context"),
        }
    }

    /// Encode to `(code, raw_data_bytes)`.
    ///
    /// Returns an error if the underlying dhcproto encoding fails
    /// (e.g. malformed RelayAgentInformation sub-options).
    pub fn to_raw(&self) -> Result<(u8, Vec<u8>), String> {
        if matches!(self, CustomDhcpOption::Dnr(_)) {
            return Err("DNR option requires runtime DNS context".to_string());
        }
        let opt = self.to_dhcp_option();
        let mut buf = Vec::new();
        let mut encoder = dhcproto::Encoder::new(&mut buf);
        opt.encode(&mut encoder)
            .map_err(|e| format!("DHCP option code {} encode failed: {}", self.code(), e))?;
        if buf.len() < 2 {
            return Err(format!("DHCP option code {} encoded no data", self.code()));
        }

        let encoded_code = buf[0];
        if encoded_code != self.code() {
            return Err(format!(
                "DHCP option code {} encoded as unexpected code {}",
                self.code(),
                encoded_code
            ));
        }

        // dhcproto encodes a single option as [code, len, data...]. It splits
        // payloads over 255 bytes into repeated options, which this server's
        // raw-option path does not support.
        let data_len = buf[1] as usize;
        if data_len == 0 {
            return Err(format!("DHCP option code {} data must not be empty", self.code()));
        }
        if data_len != buf.len() - 2 {
            return Err(format!(
                "DHCP option code {} data too long or malformed ({} encoded bytes, max {})",
                self.code(),
                buf.len() - 2,
                MAX_CUSTOM_OPTION_DATA_LEN
            ));
        }

        Ok((encoded_code, buf[2..].to_vec()))
    }

    /// Validate this custom option's data constraints.
    ///
    /// - String options (TFTP/Bootfile) must be non-empty ASCII and <= 255 bytes.
    /// - Binary options (VendorExtensions) must be non-empty and <= 255 bytes.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            CustomDhcpOption::TFTPServerName(s) => {
                if s.is_empty() {
                    return Err("TFTPServerName must not be empty".into());
                }
                if !s.is_ascii() {
                    return Err("TFTPServerName must contain only ASCII characters".into());
                }
                if s.len() > MAX_CUSTOM_OPTION_DATA_LEN {
                    return Err(format!(
                        "TFTPServerName too long ({} bytes, max {})",
                        s.len(),
                        MAX_CUSTOM_OPTION_DATA_LEN
                    ));
                }
            }
            CustomDhcpOption::BootfileName(s) => {
                if s.is_empty() {
                    return Err("BootfileName must not be empty".into());
                }
                if !s.is_ascii() {
                    return Err("BootfileName must contain only ASCII characters".into());
                }
                if s.len() > MAX_CUSTOM_OPTION_DATA_LEN {
                    return Err(format!(
                        "BootfileName too long ({} bytes, max {})",
                        s.len(),
                        MAX_CUSTOM_OPTION_DATA_LEN
                    ));
                }
            }
            CustomDhcpOption::VendorExtensions(hex) => {
                if hex.is_empty() {
                    return Err("VendorExtensions must not be empty".into());
                }
                let bytes = hex_decode(hex).map_err(|e| format!("VendorExtensions: {}", e))?;
                if bytes.len() > MAX_CUSTOM_OPTION_DATA_LEN {
                    return Err(format!(
                        "VendorExtensions too long ({} bytes, max {})",
                        bytes.len(),
                        MAX_CUSTOM_OPTION_DATA_LEN
                    ));
                }
            }
            CustomDhcpOption::RelayAgentInformation(_) => {
                // Eagerly verify the data encodes cleanly so callers of
                // `to_raw()` never hit an unexpected encode failure at
                // DHCP server startup time.
                self.to_raw().map_err(|e| format!("RelayAgentInformation encode failed: {}", e))?;
            }
            CustomDhcpOption::Dnr(config) => validate_dnr_config(config)?,
        }
        Ok(())
    }
}

fn validate_dnr_config(config: &DhcpV4DnrOptionConfig) -> Result<(), String> {
    let DhcpV4DnrOptionConfig::Custom { domains, ips, port, doh_path } = config else {
        return Ok(());
    };

    for domain in domains {
        crate::dns::dnr::normalize_advertise_domain(domain)
            .ok_or_else(|| format!("invalid DNR domain: {domain}"))?;
    }
    for ip in ips {
        if !crate::dns::dnr::is_valid_dnr_ipv4_addr(*ip) {
            return Err(format!("invalid DNR IPv4 address: {ip}"));
        }
    }
    if matches!(port, Some(0)) {
        return Err("port must be between 1 and 65535".to_string());
    }
    if let Some(path) = doh_path {
        crate::dns::dnr::normalize_doh_path_template(path)
            .ok_or_else(|| "doh_path must be an ASCII path starting with '/'".to_string())?;
    }
    Ok(())
}

// ─── hex helper (for VendorExtensions) ───────────────────────────────────────

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok(vec![]);
    }
    if hex.len() % 2 != 0 {
        return Err(format!("hex string must have even length, got {}", hex.len()));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hi = from_hex_digit(chunk[0])
            .ok_or_else(|| format!("invalid hex char: {}", chunk[0] as char))?;
        let lo = from_hex_digit(chunk[1])
            .ok_or_else(|| format!("invalid hex char: {}", chunk[1] as char))?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── Validation ─────────────────────────────────────────────────────────────

/// Validate a list of custom options: no duplicates, and reserved codes are
/// impossible because `CustomDhcpOption` is an enum (whitelist by construction).
pub fn validate_custom_options(opts: &[CustomDhcpOption]) -> Result<(), ServiceConfigError> {
    let mut seen = HashSet::new();
    for opt in opts {
        opt.validate().map_err(|e| ServiceConfigError::InvalidConfig {
            reason: format!("custom option code {}: {}", opt.code(), e),
        })?;
        if !seen.insert(opt.code()) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("duplicate custom option code {}", opt.code()),
            });
        }
    }
    Ok(())
}

/// Validate a list of filter option codes.
///
/// - Server-managed codes cannot be filtered.
/// - No duplicate codes allowed.
pub fn validate_filter_options(filters: &[u8]) -> Result<(), ServiceConfigError> {
    let mut seen = HashSet::new();
    for &code in filters {
        if PROTOCOL_RESERVED_OPTION_CODES.contains(&code) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "filter_options: code {} is protocol reserved ({}) and cannot be used",
                    code,
                    option_code_name(code),
                ),
            });
        }
        if is_server_managed(code) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "filter_options: code {} ({}) is server-managed and cannot be filtered out \
                     (would break DHCP functionality)",
                    code,
                    option_code_name(code),
                ),
            });
        }
        if !seen.insert(code) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("duplicate filter option code {}", code),
            });
        }
    }
    Ok(())
}

// ─── Config structs ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv4ServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub config: DHCPv4ServerConfig,
    /// 最近一次更新时间
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl Default for DHCPv4ServiceConfig {
    fn default() -> Self {
        Self {
            iface_name: LANDSCAPE_DEFAULT_LAN_NAME.into(),
            enable: true,
            config: DHCPv4ServerConfig::default(),
            update_at: get_f64_timestamp(),
        }
    }
}

impl LandscapeStore for DHCPv4ServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for DHCPv4ServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

impl crate::iface::config::ZoneAwareConfig for DHCPv4ServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> crate::iface::config::ZoneRequirement {
        crate::iface::config::ZoneRequirement::LanOnly
    }
    fn service_kind() -> crate::iface::config::ServiceKind {
        crate::iface::config::ServiceKind::DhcpV4
    }
}

/// DHCP Server IPv4 Config
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv4ServerConfig {
    /// range start
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip_range_start: Ipv4Addr,
    /// range end [not include]
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true, value_type = Option<String>))]
    pub ip_range_end: Option<Ipv4Addr>,

    /// DHCP Server Addr e.g. 192.168.1.1
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub server_ip_addr: Ipv4Addr,
    /// network mask e.g. 255.255.255.0 = 24
    pub network_mask: u8,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub address_lease_time: Option<u32>,

    /// 自定义 DHCP option，会无条件注入到所有 DHCP 响应中。
    /// 适用于 iPXE (option 66/67) 等需要 server 主动下发的场景。
    /// 注意：此字段的修改需要重启 DHCP 服务才能生效。
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub custom_options: Vec<CustomDhcpOption>,
}

impl DHCPv4ServerConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        // mask must be 1-30 (0/31/32 cannot form a usable address pool)
        if self.network_mask == 0 || self.network_mask > 30 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("network_mask ({}) must be between 1 and 30", self.network_mask),
            });
        }

        let mask_bits = 0xFFFFFFFFu32 << (32 - self.network_mask);
        let server_u32 = u32::from(self.server_ip_addr);
        let network = server_u32 & mask_bits;
        let broadcast = network | !mask_bits;

        let is_usable_host = |ip: Ipv4Addr| -> bool {
            let ip_u32 = u32::from(ip);
            ip_u32 & mask_bits == network && ip_u32 != network && ip_u32 != broadcast
        };

        if !is_usable_host(self.server_ip_addr) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "server_ip_addr ({}) is not a usable host in the /{} subnet",
                    self.server_ip_addr, self.network_mask
                ),
            });
        }

        if !is_usable_host(self.ip_range_start) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "ip_range_start ({}) is not in the /{} subnet",
                    self.ip_range_start, self.network_mask
                ),
            });
        }
        if self.ip_range_start == self.server_ip_addr {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "ip_range_start ({}) must not equal server_ip_addr",
                    self.ip_range_start
                ),
            });
        }

        if let Some(end) = self.ip_range_end {
            let end_u32 = u32::from(end);
            if end_u32 & mask_bits != network || end_u32 == network {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "ip_range_end ({}) is not in the /{} subnet",
                        end, self.network_mask
                    ),
                });
            }
            if end_u32 < u32::from(self.ip_range_start) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "ip_range_end ({}) must be >= ip_range_start ({})",
                        end, self.ip_range_start
                    ),
                });
            }
        }

        if let Some(lease) = self.address_lease_time {
            if lease == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "address_lease_time must be > 0".to_string(),
                });
            }
        }

        validate_custom_options(&self.custom_options)?;

        Ok(())
    }

    /// 获取IP范围的起始和结束地址
    pub fn get_ip_range(&self) -> (Ipv4Addr, Ipv4Addr) {
        let start = self.ip_range_start;
        let end = self.ip_range_end.unwrap_or_else(|| {
            let network = u32::from(start) & (0xFFFFFFFFu32 << (32 - self.network_mask));
            let broadcast = network | (0xFFFFFFFFu32 >> self.network_mask);
            Ipv4Addr::from(broadcast - 1)
        });
        (start, end)
    }

    /// 检查两个IP范围是否有重叠
    pub fn has_ip_range_overlap(&self, other: &DHCPv4ServerConfig) -> bool {
        let (start1, end1) = self.get_ip_range();
        let (start2, end2) = other.get_ip_range();

        let start1_u32 = u32::from(start1);
        let end1_u32 = u32::from(end1);
        let start2_u32 = u32::from(start2);
        let end2_u32 = u32::from(end2);

        start1_u32 <= end2_u32 && start2_u32 <= end1_u32
    }
}

impl Default for DHCPv4ServerConfig {
    fn default() -> Self {
        Self {
            ip_range_start: LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START,
            ip_range_end: None,
            server_ip_addr: LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP,
            network_mask: LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK,
            address_lease_time: Some(LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME),
            custom_options: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CustomDhcpOption serde ────────────────────────────────────

    #[test]
    fn serde_tftp_server_name() {
        let json = r#"{"TFTPServerName":"192.168.1.1"}"#;
        let opt: CustomDhcpOption = serde_json::from_str(json).unwrap();
        assert_eq!(opt.code(), 66);
        assert_eq!(opt.to_raw().unwrap().1, b"192.168.1.1");
        assert_eq!(serde_json::to_string(&opt).unwrap(), json);
    }

    #[test]
    fn serde_vendor_extensions_hex() {
        let json = r#"{"VendorExtensions":"ff0001"}"#;
        let opt: CustomDhcpOption = serde_json::from_str(json).unwrap();
        assert_eq!(opt.code(), 43);
        assert_eq!(opt.to_raw().unwrap().1, vec![0xff, 0x00, 0x01]);
        assert_eq!(serde_json::to_string(&opt).unwrap(), json);
    }

    #[test]
    fn serde_relay_agent_information() {
        let json = r#"{"RelayAgentInformation":{}}"#;
        let opt: CustomDhcpOption = serde_json::from_str(json).unwrap();
        assert_eq!(opt.code(), 82);
        assert!(opt.validate().is_err());
    }

    #[test]
    fn serde_unsupported_key_rejected() {
        let json = r#"{"Hostname":"test"}"#;
        let result: Result<CustomDhcpOption, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ── Validation ────────────────────────────────────────────────

    #[test]
    fn duplicate_custom_option_codes_rejected() {
        let opts = vec![
            CustomDhcpOption::TFTPServerName("192.168.1.1".to_string()),
            CustomDhcpOption::TFTPServerName("192.168.1.2".to_string()),
        ];
        assert!(validate_custom_options(&opts).is_err());
    }

    #[test]
    fn different_codes_accepted() {
        let opts = vec![
            CustomDhcpOption::TFTPServerName("192.168.1.1".to_string()),
            CustomDhcpOption::BootfileName("ipxe.kpxe".to_string()),
            CustomDhcpOption::VendorExtensions("ff".to_string()),
        ];
        assert!(validate_custom_options(&opts).is_ok());
    }

    #[test]
    fn config_validate_accepts_valid_custom_options() {
        let mut config = DHCPv4ServerConfig::default();
        config.custom_options.push(CustomDhcpOption::TFTPServerName("192.168.1.1".to_string()));
        config.custom_options.push(CustomDhcpOption::BootfileName("ipxe.kpxe".to_string()));
        config.custom_options.push(CustomDhcpOption::VendorExtensions("ff0001".to_string()));
        assert!(config.validate().is_ok());
    }

    // ── custom option data validation ──────────────────────────────

    #[test]
    fn validate_tftp_server_name_rejects_non_ascii() {
        let opt = CustomDhcpOption::TFTPServerName("中文服务器".to_string());
        assert!(opt.validate().is_err());
    }

    #[test]
    fn validate_bootfile_name_rejects_non_ascii() {
        let opt = CustomDhcpOption::BootfileName("文件名.kpxe".to_string());
        assert!(opt.validate().is_err());
    }

    #[test]
    fn validate_vendor_extensions_rejects_over_255_bytes() {
        let opt = CustomDhcpOption::VendorExtensions("ff".repeat(256));
        assert!(opt.validate().is_err());
    }

    #[test]
    fn validate_string_options_rejects_over_255_bytes() {
        let long = "a".repeat(256);
        let opt = CustomDhcpOption::TFTPServerName(long);
        assert!(opt.validate().is_err());
    }

    #[test]
    fn validate_custom_options_rejects_empty_data() {
        assert!(CustomDhcpOption::TFTPServerName("".to_string()).validate().is_err());
        assert!(CustomDhcpOption::BootfileName("".to_string()).validate().is_err());
        assert!(CustomDhcpOption::VendorExtensions("".to_string()).validate().is_err());
    }

    #[test]
    fn validate_custom_options_propagates_data_errors() {
        let opts = vec![CustomDhcpOption::TFTPServerName("中文".to_string())];
        assert!(validate_custom_options(&opts).is_err());
    }

    #[test]
    fn validate_dnr_rejects_invalid_custom_values() {
        let bad_port = CustomDhcpOption::Dnr(DhcpV4DnrOptionConfig::Custom {
            domains: vec![],
            ips: vec![],
            port: Some(0),
            doh_path: None,
        });
        assert!(bad_port.validate().is_err());

        let bad_domain = CustomDhcpOption::Dnr(DhcpV4DnrOptionConfig::Custom {
            domains: vec!["bad_domain.example".to_string()],
            ips: vec![],
            port: None,
            doh_path: None,
        });
        assert!(bad_domain.validate().is_err());

        let bad_path = CustomDhcpOption::Dnr(DhcpV4DnrOptionConfig::Custom {
            domains: vec![],
            ips: vec![],
            port: None,
            doh_path: Some("/dns-query?foo=bar".to_string()),
        });
        assert!(bad_path.validate().is_err());
    }

    #[test]
    fn validate_dnr_accepts_valid_custom_values() {
        let opt = CustomDhcpOption::Dnr(DhcpV4DnrOptionConfig::Custom {
            domains: vec!["doh.example.com".to_string()],
            ips: vec![Ipv4Addr::new(192, 168, 5, 1)],
            port: Some(6053),
            doh_path: Some("/dns-query".to_string()),
        });
        assert!(opt.validate().is_ok());
    }

    // ── filter validation ─────────────────────────────────────────

    #[test]
    fn validate_filter_options_rejects_duplicates() {
        assert!(validate_filter_options(&[15, 28, 15]).is_err());
    }

    #[test]
    fn validate_filter_options_accepts_valid_codes() {
        assert!(validate_filter_options(&[15, 28]).is_ok());
    }

    // ── full config serde roundtrip ───────────────────────────────

    #[test]
    fn config_json_roundtrip_with_custom_options() {
        let mut config = DHCPv4ServerConfig::default();
        config
            .custom_options
            .push(CustomDhcpOption::TFTPServerName("tftp.example.com".to_string()));
        config.custom_options.push(CustomDhcpOption::BootfileName("boot/pxelinux.0".to_string()));

        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: DHCPv4ServerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.custom_options.len(), 2);
        assert_eq!(parsed.custom_options[0].to_raw().unwrap().1, b"tftp.example.com");
        assert_eq!(parsed.custom_options[1].to_raw().unwrap().1, b"boot/pxelinux.0");
    }
}
