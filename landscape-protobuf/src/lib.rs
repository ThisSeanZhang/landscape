use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use landscape_common::{
    dns::rule::DomainMatchType,
    geo::{GeoIpError, GeoIpFileFormat, GeoSiteFileConfig},
    ip_mark::IpConfig,
};
use protos::geo::{mod_Domain::Type, Domain, GeoIPListOwned, GeoSiteListOwned};

mod protos;

pub const DEFAULT_TXT_GEO_KEY: &str = "DEFAULT";

pub struct GeoIpParseResult {
    pub entries: HashMap<String, Vec<IpConfig>>,
    pub valid_lines: usize,
    pub skipped_lines: usize,
}

pub async fn read_geo_sites_from_bytes(
    contents: impl Into<Vec<u8>>,
) -> HashMap<String, Vec<GeoSiteFileConfig>> {
    let mut result = HashMap::new();
    let list = GeoSiteListOwned::try_from(contents.into()).unwrap();

    for entry in list.proto().entry.iter() {
        let domains = entry.domain.iter().map(convert_domain_from_proto).collect();
        result.insert(entry.country_code.to_string(), domains);
    }
    result
}

pub async fn read_geo_sites<T: AsRef<Path>>(
    geo_file_path: T,
) -> HashMap<String, Vec<GeoSiteFileConfig>> {
    let mut result = HashMap::new();
    let data = tokio::fs::read(geo_file_path).await.unwrap();
    let list = GeoSiteListOwned::try_from(data).unwrap();

    for entry in list.proto().entry.iter() {
        let domains = entry.domain.iter().map(convert_domain_from_proto).collect();
        result.insert(entry.country_code.to_string(), domains);
    }
    result
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
) -> Result<HashMap<String, Vec<IpConfig>>, GeoIpError> {
    let mut result = HashMap::new();
    let list = GeoIPListOwned::try_from(contents.into()).map_err(|_| GeoIpError::DatDecodeError)?;

    for entry in list.proto().entry.iter() {
        let domains = entry.cidr.iter().filter_map(convert_ipconfig_from_proto).collect();
        result.insert(entry.country_code.to_string(), domains);
    }

    Ok(result)
}

pub fn read_geo_ips_from_bytes_txt(
    contents: impl AsRef<[u8]>,
    txt_key: Option<&str>,
) -> Result<GeoIpParseResult, GeoIpError> {
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
        return Err(GeoIpError::NoValidCidrFound);
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
) -> Result<GeoIpParseResult, GeoIpError> {
    let contents = contents.into();
    match format {
        GeoIpFileFormat::Dat => {
            let entries = read_geo_ips_from_bytes_dat(contents).await?;
            Ok(GeoIpParseResult { entries, valid_lines: 0, skipped_lines: 0 })
        }
        GeoIpFileFormat::Txt => read_geo_ips_from_bytes_txt(&contents, txt_key),
    }
}

pub async fn read_geo_ips<T: AsRef<Path>>(geo_file_path: T) -> HashMap<String, Vec<IpConfig>> {
    let mut result = HashMap::new();
    let data = tokio::fs::read(geo_file_path).await.unwrap();
    let list = GeoIPListOwned::try_from(data).unwrap();

    for entry in list.proto().entry.iter() {
        let domains = entry.cidr.iter().filter_map(convert_ipconfig_from_proto).collect();
        result.insert(entry.country_code.to_string(), domains);
    }
    result
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

/// Modifiers that make a rule context-dependent (cannot be expressed at DNS layer).
/// If any of these are present, the entire rule is skipped.
fn has_context_dependent_modifier(modifiers: &str) -> bool {
    modifiers.split(',').any(|m| {
        let m = m.trim().trim_start_matches('$').trim_start_matches('~').to_ascii_lowercase();
        m == "third-party"
            || m == "3p"
            || m.starts_with("domain=")
            || m.starts_with("denyallow=")
            || m.starts_with("to=")
            || m.starts_with("client=")
            || m.starts_with("dnstype=")
    })
}

/// Extract domain from a hosts-format line: `0.0.0.0 domain` / `127.0.0.1 domain` / `:: domain`
fn parse_hosts_line(line: &str) -> Option<&str> {
    let line = line.trim();
    // Match: IP-whitespace-domain
    let (ip_part, rest) = line.split_once(|c: char| c.is_ascii_whitespace())?;
    let rest = rest.trim_start();
    let domain = rest.split(|c: char| c.is_ascii_whitespace()).next()?;

    // Validate IP-like prefix
    if ip_part == "0.0.0.0" || ip_part == "127.0.0.1" || ip_part == "::" {
        if !domain.is_empty() && domain.contains('.') && !domain.starts_with('.') {
            return Some(domain);
        }
    }
    None
}

/// Extract domain from `||domain^...` rules.
/// Returns (domain, optional_modifiers_string).
fn parse_adguard_domain_rule(line: &str) -> Option<(&str, Option<&str>)> {
    // Must start with ||
    let line = line.strip_prefix("||")?;

    // Find the end of the domain: domain ends at `^` or `$` or end-of-string
    let domain_end = line.find(|c: char| c == '^' || c == '$').unwrap_or(line.len());
    let domain = &line[..domain_end];

    if domain.is_empty() || !domain.contains('.') || domain.contains('/') {
        return None;
    }

    // Check for modifiers after '$'
    let modifiers = if domain_end < line.len() && line.as_bytes()[domain_end] == b'^' {
        let after_caret = &line[domain_end + 1..];
        after_caret.strip_prefix('$')
    } else if domain_end < line.len() && line.as_bytes()[domain_end] == b'$' {
        Some(&line[domain_end + 1..])
    } else {
        None
    };

    Some((domain, modifiers))
}

/// Extract domain from `|https://domain|` rules (exact/full match).
fn parse_adguard_full_rule(line: &str) -> Option<&str> {
    // Pattern: |https://domain| or |http://domain|
    let line = line.strip_prefix('|')?;
    let line = line.strip_prefix("https://").or_else(|| line.strip_prefix("http://"))?;
    let domain = line.strip_suffix('|')?;

    // DNS rules cannot preserve URL path/query/fragment/port semantics.
    if domain.contains('/') || domain.contains('?') || domain.contains('#') || domain.contains(':')
    {
        return None;
    }

    if !domain.is_empty() && domain.contains('.') {
        return Some(domain);
    }
    None
}

fn is_valid_dns_domain(line: &str) -> bool {
    if !line.contains('.') {
        return false;
    }

    if line.parse::<Ipv4Addr>().is_ok() || line.parse::<Ipv6Addr>().is_ok() {
        return false;
    }

    line.split('.').all(|label| {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        let bytes = label.as_bytes();
        bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    })
}

/// Check if a line is a bare domain (e.g. "example.com" with no prefix/suffix).
/// Used as a fallback after all other parsers have been tried.
fn is_bare_domain(line: &str) -> bool {
    // Must not contain whitespace or AdGuard/URL control syntax.
    if line.contains(|c: char| {
        c.is_ascii_whitespace() || matches!(c, '/' | '?' | '#' | ':' | '@' | '$' | '^' | '|' | '*')
    }) {
        return false;
    }

    is_valid_dns_domain(line)
}

/// Parse AdGuard Home format rules into GeoSiteFileConfig domain list.
///
/// Conversion rules:
/// - `||domain^` → Domain match (subdomain-aware)
/// - `||domain^$important|$document` → Domain match (non-context modifiers ignored)
/// - `||domain^$third-party|$domain=...|$to=...` → skipped (context-dependent)
/// - `0.0.0.0 domain` / `127.0.0.1 domain` / `:: domain` → Full exact match
/// - `|https://domain|` → Full exact match
/// - Bare domain lines (e.g. "example.com") → Domain match
/// - `@@...` (exception rules) → skipped
/// - Rules with paths → skipped
/// - Cosmetic/regex rules → skipped
/// - Comments (`!`/`#`) and rules shorter than 4 chars → skipped
pub fn parse_adguard_rules(contents: &[u8]) -> Vec<GeoSiteFileConfig> {
    let text = String::from_utf8_lossy(contents);
    let mut result = Vec::new();
    let mut seen = HashSet::new();

    for line in text.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }

        // AdGuard itself ignores rules shorter than 4 characters
        if line.len() < 4 {
            continue;
        }

        // Skip cosmetic rules: ##, #@#, #?#
        if line.contains("##") || line.contains("#@#") || line.contains("#?#") {
            continue;
        }

        // Skip regex rules
        if line.starts_with('/') && line.ends_with('/') && line.len() > 2 {
            continue;
        }

        // Skip exception rules
        if line.starts_with("@@") {
            continue;
        }

        // Try hosts format first: 0.0.0.0 domain / 127.0.0.1 domain / :: domain
        if let Some(domain) = parse_hosts_line(line) {
            let domain = domain.to_ascii_lowercase();
            if !seen.insert((DomainMatchType::Full, domain.clone())) {
                continue;
            }
            result.push(GeoSiteFileConfig {
                match_type: DomainMatchType::Full,
                value: domain,
                attributes: HashSet::new(),
            });
            continue;
        }

        // Try ||domain^... format
        if let Some((domain, modifiers)) = parse_adguard_domain_rule(line) {
            // Skip if any context-dependent modifiers are present
            if let Some(mods) = modifiers {
                if has_context_dependent_modifier(mods) {
                    continue;
                }
            }
            let domain = domain.to_ascii_lowercase();
            if !seen.insert((DomainMatchType::Domain, domain.clone())) {
                continue;
            }
            result.push(GeoSiteFileConfig {
                match_type: DomainMatchType::Domain,
                value: domain,
                attributes: HashSet::new(),
            });
            continue;
        }

        // Try |https://domain| format (full exact match)
        if let Some(domain) = parse_adguard_full_rule(line) {
            let domain = domain.to_ascii_lowercase();
            if !seen.insert((DomainMatchType::Full, domain.clone())) {
                continue;
            }
            result.push(GeoSiteFileConfig {
                match_type: DomainMatchType::Full,
                value: domain,
                attributes: HashSet::new(),
            });
            continue;
        }

        // Fallback: bare domain lines (e.g. "example.com", "ads.tracker.com")
        if is_bare_domain(line) {
            let domain = line.to_ascii_lowercase();
            if seen.insert((DomainMatchType::Domain, domain.clone())) {
                result.push(GeoSiteFileConfig {
                    match_type: DomainMatchType::Domain,
                    value: domain,
                    attributes: HashSet::new(),
                });
            }
            continue;
        }

        // All other formats silently skipped
    }

    result
}

#[cfg(test)]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use jemalloc_ctl::{epoch, stats};
    use landscape_common::dns::rule::DomainMatchType;

    use crate::{
        protos::geo::{GeoIPListOwned, GeoSiteListOwned},
        read_geo_ips_from_bytes_txt, read_geo_sites,
    };

    fn test_memory_usage() {
        epoch::advance().unwrap();

        let allocated = stats::allocated::read().unwrap();
        let active = stats::active::read().unwrap();

        println!("Allocated memory: {} kbytes", allocated / 1024);
        println!("Active memory: {} kbytes", active / 1024);
    }
    #[tokio::test]
    async fn read_raw() {
        test_memory_usage();

        let data = tokio::fs::read("/root/.landscape-router/geosite.dat1").await.unwrap();
        let list = GeoSiteListOwned::try_from(data).unwrap();

        for entry in list.proto().entry.iter() {
            if entry.country_code == "STEAM" {
                for domain_config in entry.domain.iter() {
                    println!("{:?}: {:?}", entry.country_code, domain_config);
                }
            }
        }
    }

    #[tokio::test]
    async fn test() {
        test_memory_usage();
        let result = read_geo_sites("/root/.landscape-router/geosite.dat1").await;
        test_memory_usage();
        for (domain, domain_configs) in result {
            if domain == "test" {
                for domain_config in domain_configs {
                    println!("{domain:?}: {:?}", domain_config);
                }
            }
        }
        test_memory_usage();
    }

    #[tokio::test]
    async fn test_read() {
        test_memory_usage();
        let home_path = homedir::my_home().unwrap().unwrap().join(".landscape-router");
        let geo_file_path = home_path.join("geoip.dat");

        let data = tokio::fs::read(geo_file_path).await.unwrap();
        let list = GeoIPListOwned::try_from(data).unwrap();
        test_memory_usage();

        let mut sum = 0;
        for entry in list.proto().entry.iter() {
            // println!("{:?}", entry.country_code);
            if entry.country_code == "cn".to_uppercase() {
                println!("{:?}", entry.cidr.len());
            } else {
                sum += entry.cidr.len()
            }
            // println!("reverse_match : {:?}", entry.reverse_match);
            // if entry.reverse_match {
            //     println!("reverse_match : {:?}", entry.cidr);
            // }
        }
        println!("other count: {sum:?}");
        test_memory_usage();
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
            landscape_common::ip_mark::IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 0)),
                prefix: 24,
            }
        );
        assert_eq!(
            values[1],
            landscape_common::ip_mark::IpConfig {
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

    #[test]
    fn parse_adguard_basic_domain_rules() {
        let input = b"||ads.example.com^
||tracker.com^
||doubleclick.net^
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].match_type, DomainMatchType::Domain);
        assert_eq!(result[0].value, "ads.example.com");
        assert_eq!(result[1].match_type, DomainMatchType::Domain);
        assert_eq!(result[1].value, "tracker.com");
        assert_eq!(result[2].match_type, DomainMatchType::Domain);
        assert_eq!(result[2].value, "doubleclick.net");
    }

    #[test]
    fn parse_adguard_skips_comments_and_short_rules() {
        let input = b"! This is a comment
# Another comment
a
||valid.com^
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "valid.com");
    }

    #[test]
    fn parse_adguard_skips_exception_rules() {
        let input = b"||ads.example.com^
@@||whitelist.com^
||tracker.com^
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].value, "ads.example.com");
        assert_eq!(result[1].value, "tracker.com");
    }

    #[test]
    fn parse_adguard_skips_context_dependent_modifiers() {
        let input = b"||tracker.com^$third-party
||analytics.com^$domain=site.com
||ads.com^$3p
||evil.com^$denyallow=good.com
||beacon.com^$to=example.com
||not-third-party.com^$~third-party
||not-domain.com^$~domain=site.com
||safe.com^$important
||ok.com^$document
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].value, "safe.com");
        assert_eq!(result[1].value, "ok.com");
    }

    #[test]
    fn parse_adguard_hosts_format_to_full_match() {
        let input = b"0.0.0.0 blocked.com
127.0.0.1 malware.com
:: ipv6-tracker.com
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 3);
        for item in &result {
            assert_eq!(item.match_type, DomainMatchType::Full);
        }
        assert_eq!(result[0].value, "blocked.com");
        assert_eq!(result[1].value, "malware.com");
        assert_eq!(result[2].value, "ipv6-tracker.com");
    }

    #[test]
    fn parse_adguard_full_url_rule() {
        let input = b"|https://exact.example.com|
|http://another.example.com|
|https://example.com/path|
|https://example.com?query=1|
|https://example.com:8443|
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].match_type, DomainMatchType::Full);
        assert_eq!(result[0].value, "exact.example.com");
        assert_eq!(result[1].match_type, DomainMatchType::Full);
        assert_eq!(result[1].value, "another.example.com");
    }

    #[test]
    fn parse_adguard_skips_rules_with_path() {
        let input = b"||example.com/ads/banner^
||example.com^
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "example.com");
    }

    #[test]
    fn parse_adguard_skips_cosmetic_and_regex_rules() {
        let input = b"example.com##.ad-banner
example.com#@#.whitelisted
/example\\.com\\/ads\\/
||real-domain.com^
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "real-domain.com");
    }

    #[test]
    fn parse_adguard_case_normalization() {
        let input = b"||Example.COM^
0.0.0.0 BLOCKED.COM
|https://Exact.EXAMPLE.Com|
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 3);
        for item in &result {
            assert_eq!(item.value, item.value.to_lowercase());
        }
    }

    #[test]
    fn parse_adguard_deduplicates_same_match_type_and_domain() {
        let input = b"||example.com^
||Example.COM^
0.0.0.0 exact.example.com
|https://exact.example.com|
";
        let result = crate::parse_adguard_rules(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].match_type, DomainMatchType::Domain);
        assert_eq!(result[0].value, "example.com");
        assert_eq!(result[1].match_type, DomainMatchType::Full);
        assert_eq!(result[1].value, "exact.example.com");
    }

    #[test]
    fn parse_adguard_complex_real_world_ruleset() {
        let input = b"! Title: AdGuard DNS filter
! Homepage: https://github.com/AdguardTeam
# License: https://github.com/AdguardTeam/AdguardSDNSFilter/blob/master/LICENSE

||ad.doubleclick.net^
||pagead2.googlesyndication.com^$third-party
||adservice.google.com^
@@||googleadservices.com^$document
0.0.0.0 telemetry.example.org
||malware.example.com^$important
/example\\.com\\/popup/\\
example.com##.ad-container
||cdn.example.com/banners^
|https://tracking.pixel.io|
||safe-analytics.net^$domain=trusted.com
||simple-tracker.io^
! End of filter
";
        let result = crate::parse_adguard_rules(input);
        let domains: Vec<&str> = result.iter().map(|d| d.value.as_str()).collect();

        // Should include:
        assert!(domains.contains(&"ad.doubleclick.net"));
        assert!(domains.contains(&"adservice.google.com"));
        assert!(domains.contains(&"malware.example.com"));
        assert!(domains.contains(&"simple-tracker.io"));

        // telemetry.example.org is hosts format → Full match
        let telemetry = result.iter().find(|d| d.value == "telemetry.example.org").unwrap();
        assert_eq!(telemetry.match_type, DomainMatchType::Full);

        // tracking.pixel.io is |https://...| format → Full match
        let pixel = result.iter().find(|d| d.value == "tracking.pixel.io").unwrap();
        assert_eq!(pixel.match_type, DomainMatchType::Full);

        // Should NOT include:
        assert!(!domains.contains(&"pagead2.googlesyndication.com")); // $third-party
        assert!(!domains.contains(&"googleadservices.com")); // @@ exception
        assert!(!domains.contains(&"cdn.example.com")); // has path
        assert!(!domains.contains(&"safe-analytics.net")); // $domain=
    }

    #[test]
    fn parse_adguard_bare_domain_lines() {
        let input = b"example.com
ads.tracker.com
cdn.example.org
xn--fiqs8s.example
invalid
example.com/path
example.com$third-party
0.0.0.0
127.0.0.1
192.168.1.1
::1
fe80::1
user@domain.com
.example.com
";
        let result = crate::parse_adguard_rules(input);
        let domains: Vec<&str> = result.iter().map(|d| d.value.as_str()).collect();

        // Should include bare domains
        assert!(domains.contains(&"example.com"));
        assert!(domains.contains(&"ads.tracker.com"));
        assert!(domains.contains(&"cdn.example.org"));
        assert!(domains.contains(&"xn--fiqs8s.example"));
        assert_eq!(result.len(), 4);

        // All should be Domain match type
        for item in &result {
            assert_eq!(item.match_type, DomainMatchType::Domain);
        }

        // Should NOT include:
        assert!(!domains.contains(&"invalid")); // no dot
        assert!(!domains.contains(&"example.com/path")); // has path
        assert!(!domains.contains(&"example.com$third-party")); // has modifier
        assert!(!domains.contains(&"0.0.0.0")); // bare IPv4
        assert!(!domains.contains(&"127.0.0.1")); // bare IPv4
        assert!(!domains.contains(&"192.168.1.1")); // bare IPv4
        assert!(!domains.contains(&"::1")); // bare IPv6
        assert!(!domains.contains(&"fe80::1")); // bare IPv6
        assert!(!domains.contains(&"user@domain.com")); // email
        assert!(!domains.contains(&".example.com")); // leading dot
    }

    #[test]
    fn parse_adguard_rejects_invalid_bare_domain_syntax() {
        let input = b"example.com^
|example.com
example..com
-example.com
example-.com
exa_mple.com
*.example.com
example.com.
example.com|$important
valid-example.com
sub.valid-example.com
";
        let result = crate::parse_adguard_rules(input);
        let domains: Vec<&str> = result.iter().map(|d| d.value.as_str()).collect();

        assert_eq!(domains, vec!["valid-example.com", "sub.valid-example.com"]);
        assert!(!domains.contains(&"example.com^"));
        assert!(!domains.contains(&"|example.com"));
        assert!(!domains.contains(&"example..com"));
        assert!(!domains.contains(&"-example.com"));
        assert!(!domains.contains(&"example-.com"));
        assert!(!domains.contains(&"exa_mple.com"));
        assert!(!domains.contains(&"*.example.com"));
        assert!(!domains.contains(&"example.com."));
        assert!(!domains.contains(&"example.com|$important"));
    }

    #[test]
    fn parse_adguard_bare_domain_dedup_with_other_formats() {
        let input = b"||example.com^
0.0.0.0 example.com
example.com
|https://full.example.com|
full.example.com
";
        let result = crate::parse_adguard_rules(input);

        // example.com appears as both Domain(||example.com^) and Full(0.0.0.0 example.com),
        // bare "example.com" de-duplicates with the Domain one.
        // Total: Domain("example.com"), Full("example.com"), Full("full.example.com"), Domain("full.example.com")
        assert_eq!(result.len(), 4);

        let domain_items: Vec<_> = result.iter().filter(|d| d.value == "example.com").collect();
        assert_eq!(domain_items.len(), 2);
        assert!(domain_items.iter().any(|d| d.match_type == DomainMatchType::Domain));
        assert!(domain_items.iter().any(|d| d.match_type == DomainMatchType::Full));

        let full_items: Vec<_> = result.iter().filter(|d| d.value == "full.example.com").collect();
        assert_eq!(full_items.len(), 2);
        assert!(full_items.iter().any(|d| d.match_type == DomainMatchType::Domain));
        assert!(full_items.iter().any(|d| d.match_type == DomainMatchType::Full));
    }
}
