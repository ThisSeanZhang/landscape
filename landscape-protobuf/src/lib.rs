use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use landscape_common::{
    config_service::geo::{GeoError, GeoIpFileFormat, GeoSiteFileConfig},
    dns::rule::DomainMatchType,
    flow::ip_mark::IpConfig,
};
use protos::geo::{mod_Domain::Type, Domain, GeoIPListOwned, GeoSiteListOwned};

pub mod adguard;
mod protos;
pub use adguard::parse_adguard_rules;

pub const DEFAULT_TXT_GEO_KEY: &str = "DEFAULT";

pub struct GeoIpParseResult {
    pub entries: HashMap<String, Vec<IpConfig>>,
    pub valid_lines: usize,
    pub skipped_lines: usize,
}

pub async fn read_geo_sites_from_bytes(
    contents: impl Into<Vec<u8>>,
) -> Result<HashMap<String, Vec<GeoSiteFileConfig>>, GeoError> {
    let mut result = HashMap::new();
    let list =
        GeoSiteListOwned::try_from(contents.into()).map_err(|_| GeoError::SiteDatDecodeError)?;

    for entry in list.proto().entry.iter() {
        let domains = entry.domain.iter().map(convert_domain_from_proto).collect();
        result.insert(entry.country_code.to_string(), domains);
    }
    Ok(result)
}

pub fn convert_match_type_from_proto(value: Type) -> DomainMatchType {
    match value {
        Type::Plain => DomainMatchType::Plain,
        Type::Regex => DomainMatchType::Regex,
        Type::Domain => DomainMatchType::Domain,
        Type::Full => DomainMatchType::Full,
    }
}

pub fn convert_domain_from_proto(value: &Domain) -> GeoSiteFileConfig {
    GeoSiteFileConfig {
        match_type: convert_match_type_from_proto(value.type_pb),
        value: value.value.to_lowercase(),
        attributes: value.attribute.iter().map(|e| e.key.to_string()).collect(),
    }
}

pub async fn read_geo_ips_from_bytes(
    contents: impl Into<Vec<u8>>,
) -> HashMap<String, Vec<IpConfig>> {
    let mut result = HashMap::new();
    let list = GeoIPListOwned::try_from(contents.into()).unwrap();

    for entry in list.proto().entry.iter() {
        let domains = entry.cidr.iter().filter_map(convert_ipconfig_from_proto).collect();
        result.insert(entry.country_code.to_string(), domains);
    }
    result
}

pub async fn read_geo_ips_from_bytes_dat(
    contents: impl Into<Vec<u8>>,
) -> Result<HashMap<String, Vec<IpConfig>>, GeoError> {
    let mut result = HashMap::new();
    let list = GeoIPListOwned::try_from(contents.into()).map_err(|_| GeoError::IpDatDecodeError)?;

    for entry in list.proto().entry.iter() {
        let domains = entry.cidr.iter().filter_map(convert_ipconfig_from_proto).collect();
        result.insert(entry.country_code.to_string(), domains);
    }

    Ok(result)
}

pub fn read_geo_ips_from_bytes_txt(
    contents: impl AsRef<[u8]>,
    txt_key: Option<&str>,
) -> Result<GeoIpParseResult, GeoError> {
    let key = txt_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_TXT_GEO_KEY)
        .to_ascii_uppercase();

    let text = String::from_utf8_lossy(contents.as_ref());
    let mut values = Vec::new();
    let mut skipped_lines = 0;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(cidr) = parse_txt_cidr_line(line) {
            values.push(cidr);
        } else {
            skipped_lines += 1;
        }
    }

    if values.is_empty() {
        return Err(GeoError::IpNoValidCidrFound);
    }

    let valid_lines = values.len();
    let mut entries = HashMap::new();
    entries.insert(key, values);

    Ok(GeoIpParseResult { entries, valid_lines, skipped_lines })
}

pub async fn read_geo_ips_from_bytes_by_format(
    contents: impl Into<Vec<u8>>,
    format: &GeoIpFileFormat,
    txt_key: Option<&str>,
) -> Result<GeoIpParseResult, GeoError> {
    let contents = contents.into();
    match format {
        GeoIpFileFormat::Dat => {
            let entries = read_geo_ips_from_bytes_dat(contents).await?;
            Ok(GeoIpParseResult { entries, valid_lines: 0, skipped_lines: 0 })
        }
        GeoIpFileFormat::Txt => read_geo_ips_from_bytes_txt(&contents, txt_key),
    }
}

pub fn convert_ipconfig_from_proto(value: &crate::protos::geo::CIDR) -> Option<IpConfig> {
    let bytes = value.ip.as_ref();
    let result = match bytes.len() {
        4 => {
            // IPv4 地址构造
            Some(IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])))
        }
        16 => {
            // IPv6 地址构造
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None, // 字节数不合法
    };
    result.map(|ip| IpConfig { ip, prefix: value.prefix })
}

fn parse_txt_cidr_line(line: &str) -> Option<IpConfig> {
    let (ip, prefix) = line.split_once('/')?;
    let ip: IpAddr = ip.trim().parse().ok()?;
    let prefix: u32 = prefix.trim().parse().ok()?;

    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix > max_prefix {
        return None;
    }

    Some(IpConfig { ip, prefix })
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    use landscape_common::dns::rule::DomainMatchType;

    use crate::{
        convert_domain_from_proto, convert_ipconfig_from_proto,
        protos::geo::{mod_Domain::Type, Domain, CIDR},
        read_geo_ips_from_bytes_txt,
    };

    #[test]
    fn convert_ipconfig_from_proto_handles_ipv4_ipv6_and_invalid() {
        let v4 =
            convert_ipconfig_from_proto(&CIDR { ip: Cow::Borrowed(&[192, 168, 1, 0]), prefix: 24 })
                .unwrap();
        assert_eq!(v4.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(v4.prefix, 24);

        let v6_bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let v6 = convert_ipconfig_from_proto(&CIDR { ip: Cow::Borrowed(&v6_bytes), prefix: 32 })
            .unwrap();
        assert_eq!(v6.ip, IpAddr::V6(Ipv6Addr::from(v6_bytes)));
        assert_eq!(v6.prefix, 32);

        let invalid =
            convert_ipconfig_from_proto(&CIDR { ip: Cow::Borrowed(&[1, 2, 3]), prefix: 24 });
        assert!(invalid.is_none());
    }

    #[test]
    fn convert_domain_from_proto_maps_type_and_lowercases_value() {
        let domain = Domain {
            type_pb: Type::Domain,
            value: Cow::Borrowed("Example.COM"),
            attribute: vec![],
        };
        let config = convert_domain_from_proto(&domain);
        assert_eq!(config.match_type, DomainMatchType::Domain);
        assert_eq!(config.value, "example.com");
        assert!(config.attributes.is_empty());

        let domain = Domain {
            type_pb: Type::Regex,
            value: Cow::Borrowed("*.Example.COM"),
            attribute: vec![],
        };
        let config = convert_domain_from_proto(&domain);
        assert_eq!(config.match_type, DomainMatchType::Regex);
        assert_eq!(config.value, "*.example.com");
    }

    #[test]
    fn parse_txt_geo_ips_skips_invalid_lines() {
        let result = read_geo_ips_from_bytes_txt(
            b"\n# comment\n1.1.1.0/24\ninvalid\n2001:db8::/32\n10.0.0.1/33\n",
            Some("custom"),
        )
        .unwrap();

        assert_eq!(result.valid_lines, 2);
        assert_eq!(result.skipped_lines, 2);
        assert_eq!(result.entries.len(), 1);

        let values = result.entries.get("CUSTOM").unwrap();
        assert_eq!(
            values[0],
            landscape_common::flow::ip_mark::IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 0)),
                prefix: 24,
            }
        );
        assert_eq!(
            values[1],
            landscape_common::flow::ip_mark::IpConfig {
                ip: IpAddr::V6(Ipv6Addr::from([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ])),
                prefix: 32,
            }
        );
    }

    #[test]
    fn parse_txt_geo_ips_uses_default_key() {
        let result = read_geo_ips_from_bytes_txt(b"1.1.1.0/24\n", Some("   ")).unwrap();
        assert!(result.entries.contains_key("DEFAULT"));
    }
}
