use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use landscape_common::dns::rule::DomainMatchType;
use landscape_common::geo::GeoSiteFileConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAdguardRule {
    match_type: DomainMatchType,
    value: String,
}

fn adguard_modifier_name(modifier: &str) -> Option<String> {
    let modifier = modifier.trim().trim_start_matches('$').trim_start_matches('~').trim();
    if modifier.is_empty() {
        return None;
    }

    let name_end = modifier.find('=').unwrap_or(modifier.len());
    let name = modifier[..name_end].trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_ascii_lowercase())
    }
}

fn modifier_names(modifiers: &str) -> Option<Vec<String>> {
    let mut names = Vec::new();
    for modifier in modifiers.split(',') {
        names.push(adguard_modifier_name(modifier)?);
    }
    Some(names)
}

fn modifiers_contain_badfilter(modifiers: &str) -> bool {
    modifier_names(modifiers)
        .map(|names| names.iter().any(|name| name == "badfilter"))
        .unwrap_or(false)
}

/// Only modifiers that do not narrow the matched address set or change the action
/// can be preserved at DNS domain level.
fn modifiers_are_dns_safe(modifiers: &str) -> bool {
    let Some(names) = modifier_names(modifiers) else {
        return false;
    };

    names.iter().all(|name| matches!(name.as_str(), "important" | "reason" | "noop"))
}

fn extract_adguard_modifiers(line: &str) -> Option<&str> {
    let (_, modifiers) = line.rsplit_once('$')?;
    Some(modifiers)
}

fn line_contains_badfilter(line: &str) -> bool {
    extract_adguard_modifiers(line).map(modifiers_contain_badfilter).unwrap_or(false)
}

fn is_blocking_hosts_ip(ip_part: &str) -> bool {
    matches!(ip_part, "0.0.0.0" | "127.0.0.1" | "::" | "::1")
}

/// Extract domains from a hosts-format line:
/// `0.0.0.0 domain`, `127.0.0.1 domain`, `:: domain`, `::1 domain`.
fn parse_hosts_line_domains(line: &str) -> Vec<&str> {
    let line = line.trim();
    let Some((ip_part, rest)) = line.split_once(|c: char| c.is_ascii_whitespace()) else {
        return Vec::new();
    };

    if !is_blocking_hosts_ip(ip_part) {
        return Vec::new();
    }

    let rest = rest.split_once('#').map(|(before, _)| before).unwrap_or(rest);
    rest.split(|c: char| c.is_ascii_whitespace())
        .filter(|domain| is_valid_dns_domain(domain))
        .collect()
}

/// Extract domain from `||domain^...` rules.
/// Returns (domain, optional_modifiers_string).
fn parse_adguard_domain_rule(line: &str) -> Option<(&str, Option<&str>)> {
    let line = line.strip_prefix("||")?;

    let domain_end = line.find(|c: char| c == '^' || c == '$').unwrap_or(line.len());
    let domain = &line[..domain_end];

    if !is_valid_dns_domain(domain) {
        return None;
    }

    let modifiers = if domain_end < line.len() && line.as_bytes()[domain_end] == b'^' {
        let after_caret = &line[domain_end + 1..];
        if after_caret.is_empty() {
            None
        } else {
            Some(after_caret.strip_prefix('$')?)
        }
    } else if domain_end < line.len() && line.as_bytes()[domain_end] == b'$' {
        Some(&line[domain_end + 1..])
    } else {
        None
    };

    if modifiers == Some("") {
        return None;
    }

    Some((domain, modifiers))
}

/// Extract domain from `|https://domain|` rules (exact/full match).
fn parse_adguard_full_rule(line: &str) -> Option<&str> {
    let line = line.strip_prefix('|')?;
    let line = line.strip_prefix("https://").or_else(|| line.strip_prefix("http://"))?;
    let domain = line.strip_suffix('|')?;

    if domain.contains('/') || domain.contains('?') || domain.contains('#') || domain.contains(':')
    {
        return None;
    }

    if is_valid_dns_domain(domain) {
        return Some(domain);
    }
    None
}

fn parse_bare_domain_rule(line: &str) -> Option<(&str, Option<&str>)> {
    let (domain, modifiers) = match line.split_once('$') {
        Some((domain, modifiers)) => {
            if modifiers.is_empty() {
                return None;
            }
            (domain, Some(modifiers))
        }
        None => (line, None),
    };

    if is_bare_domain(domain) {
        Some((domain, modifiers))
    } else {
        None
    }
}

fn extract_leading_dns_domain(line: &str) -> Option<&str> {
    let domain_end = line
        .find(|c: char| {
            c.is_ascii_whitespace()
                || matches!(c, '/' | '?' | '#' | ':' | '@' | '$' | '^' | '|' | '*')
        })
        .unwrap_or(line.len());
    let domain = &line[..domain_end];

    if is_valid_dns_domain(domain) {
        Some(domain)
    } else {
        None
    }
}

fn extract_http_rule_host(line: &str) -> Option<&str> {
    let line = line.strip_prefix('|').unwrap_or(line);
    let line = line.strip_prefix("https://").or_else(|| line.strip_prefix("http://"))?;
    let host_end = line
        .find(|c: char| c.is_ascii_whitespace() || matches!(c, '/' | '?' | '#' | ':' | '|' | '$'))
        .unwrap_or(line.len());
    let host = &line[..host_end];

    if is_valid_dns_domain(host) {
        Some(host)
    } else {
        None
    }
}

/// Extract an approximate domain from negative rules (`@@` / `$badfilter`).
/// Negative rules are used only to remove overlapping positive candidates.
fn parse_adguard_negative_overlap_rule(line: &str) -> Option<ParsedAdguardRule> {
    if let Some(line) = line.strip_prefix("||") {
        let domain_end = line
            .find(|c: char| {
                c.is_ascii_whitespace() || matches!(c, '^' | '$' | '/' | '?' | '#' | ':')
            })
            .unwrap_or(line.len());
        let domain = &line[..domain_end];
        if is_valid_dns_domain(domain) {
            return Some(ParsedAdguardRule {
                match_type: DomainMatchType::Domain,
                value: domain.to_ascii_lowercase(),
            });
        }
    }

    if let Some(domain) = parse_adguard_full_rule(line).or_else(|| extract_http_rule_host(line)) {
        return Some(ParsedAdguardRule {
            match_type: DomainMatchType::Full,
            value: domain.to_ascii_lowercase(),
        });
    }

    if let Some(domain) = extract_leading_dns_domain(line) {
        return Some(ParsedAdguardRule {
            match_type: DomainMatchType::Domain,
            value: domain.to_ascii_lowercase(),
        });
    }

    None
}

fn is_valid_dns_domain(line: &str) -> bool {
    if !line.contains('.') {
        return false;
    }

    if line.len() > 253 {
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
    if line.contains(|c: char| {
        c.is_ascii_whitespace() || matches!(c, '/' | '?' | '#' | ':' | '@' | '$' | '^' | '|' | '*')
    }) {
        return false;
    }

    is_valid_dns_domain(line)
}

fn domain_is_equal_or_subdomain(domain: &str, base: &str) -> bool {
    domain == base || domain.strip_suffix(base).map(|prefix| prefix.ends_with('.')).unwrap_or(false)
}

fn adguard_rules_overlap(candidate: &ParsedAdguardRule, negative: &ParsedAdguardRule) -> bool {
    match (&candidate.match_type, &negative.match_type) {
        (DomainMatchType::Full, DomainMatchType::Full) => candidate.value == negative.value,
        (DomainMatchType::Full, DomainMatchType::Domain) => {
            domain_is_equal_or_subdomain(&candidate.value, &negative.value)
        }
        (DomainMatchType::Domain, DomainMatchType::Full) => {
            domain_is_equal_or_subdomain(&negative.value, &candidate.value)
        }
        (DomainMatchType::Domain, DomainMatchType::Domain) => {
            domain_is_equal_or_subdomain(&candidate.value, &negative.value)
                || domain_is_equal_or_subdomain(&negative.value, &candidate.value)
        }
        _ => false,
    }
}

/// Parse AdGuard Home format rules into GeoSiteFileConfig domain list.
///
/// Conversion rules:
/// - `||domain^` -> Domain match (subdomain-aware)
/// - `||domain^$important` -> Domain match
/// - resource/request-context/rewrite modifiers -> skipped
/// - `0.0.0.0 domain` / `127.0.0.1 domain` / `:: domain` / `::1 domain` -> Full exact match
/// - Bare domain lines (e.g. "example.com") -> Domain match
/// - `@@...` and `$badfilter` rules -> remove overlapping positive candidates
/// - Rules with paths -> skipped
/// - Cosmetic/regex rules -> skipped
/// - Comments (`!`/`#`) and rules shorter than 4 chars -> skipped
pub fn parse_adguard_rules(contents: &[u8]) -> Vec<GeoSiteFileConfig> {
    let text = String::from_utf8_lossy(contents);
    let mut candidates = Vec::<ParsedAdguardRule>::new();
    let mut negative_rules = Vec::<ParsedAdguardRule>::new();
    let mut has_unscoped_negative_rule = false;

    for line in text.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }

        if line.len() < 4 {
            continue;
        }

        if let Some(exception_rule) = line.strip_prefix("@@") {
            if let Some(rule) = parse_adguard_negative_overlap_rule(exception_rule) {
                negative_rules.push(rule);
            } else {
                has_unscoped_negative_rule = true;
            }
            continue;
        }

        if line_contains_badfilter(line) {
            if let Some(rule) = parse_adguard_negative_overlap_rule(line) {
                negative_rules.push(rule);
            } else {
                has_unscoped_negative_rule = true;
            }
            continue;
        }

        if line.contains("##") || line.contains("#@#") || line.contains("#?#") {
            continue;
        }

        if line.starts_with('/') && line.ends_with('/') && line.len() > 2 {
            continue;
        }

        let hosts_domains = parse_hosts_line_domains(line);
        if !hosts_domains.is_empty() {
            for domain in hosts_domains {
                candidates.push(ParsedAdguardRule {
                    match_type: DomainMatchType::Full,
                    value: domain.to_ascii_lowercase(),
                });
            }
            continue;
        }

        if let Some((domain, modifiers)) = parse_adguard_domain_rule(line) {
            if let Some(mods) = modifiers {
                if modifiers_contain_badfilter(mods) || !modifiers_are_dns_safe(mods) {
                    continue;
                }
            }
            candidates.push(ParsedAdguardRule {
                match_type: DomainMatchType::Domain,
                value: domain.to_ascii_lowercase(),
            });
            continue;
        }

        // Exact URL rules only match a specific URL, not every path on the host.
        // DNS domain rules cannot preserve that safely.
        if parse_adguard_full_rule(line).is_some() {
            continue;
        }

        if let Some((domain, modifiers)) = parse_bare_domain_rule(line) {
            if let Some(mods) = modifiers {
                if modifiers_contain_badfilter(mods) || !modifiers_are_dns_safe(mods) {
                    continue;
                }
            }
            candidates.push(ParsedAdguardRule {
                match_type: DomainMatchType::Domain,
                value: domain.to_ascii_lowercase(),
            });
        }
    }

    if has_unscoped_negative_rule {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for candidate in candidates {
        if negative_rules.iter().any(|negative| adguard_rules_overlap(&candidate, negative)) {
            continue;
        }

        if !seen.insert((candidate.match_type.clone(), candidate.value.clone())) {
            continue;
        }

        result.push(GeoSiteFileConfig {
            match_type: candidate.match_type,
            value: candidate.value,
            attributes: HashSet::new(),
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use landscape_common::dns::rule::DomainMatchType;

    use super::parse_adguard_rules;

    #[test]
    fn parse_adguard_basic_domain_rules() {
        let input = b"||ads.example.com^
||tracker.com^
||doubleclick.net^
";
        let result = parse_adguard_rules(input);
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
        let result = parse_adguard_rules(input);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "valid.com");
    }

    #[test]
    fn parse_adguard_skips_exception_rules() {
        let input = b"||ads.example.com^
@@||whitelist.com^
||tracker.com^
";
        let result = parse_adguard_rules(input);
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
||image-only.com^$image
||method-only.com^$method=get
||header-only.com^$header=set-cookie
||app-only.com^$app=org.example.app
||rewrite.com^$dnsrewrite=NOERROR;A;192.0.2.1
||safe.com^$important
||ok.com^$document
bare-safe.com$important
bare-image.com$image
";
        let result = parse_adguard_rules(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].value, "safe.com");
        assert_eq!(result[1].value, "bare-safe.com");
    }

    #[test]
    fn parse_adguard_hosts_format_to_full_match() {
        let input = b"0.0.0.0 blocked.com
127.0.0.1 malware.com
:: ipv6-tracker.com
::1 loopback-v6.com
0.0.0.0 first.com second.com # inline comment
1.2.3.4 not-a-block-entry.com
";
        let result = parse_adguard_rules(input);
        assert_eq!(result.len(), 6);
        for item in &result {
            assert_eq!(item.match_type, DomainMatchType::Full);
        }
        assert_eq!(result[0].value, "blocked.com");
        assert_eq!(result[1].value, "malware.com");
        assert_eq!(result[2].value, "ipv6-tracker.com");
        assert_eq!(result[3].value, "loopback-v6.com");
        assert_eq!(result[4].value, "first.com");
        assert_eq!(result[5].value, "second.com");
    }

    #[test]
    fn parse_adguard_skips_full_url_rule_to_avoid_path_broadening() {
        let input = b"|https://exact.example.com|
|http://another.example.com|
|https://example.com/path|
|https://example.com?query=1|
|https://example.com:8443|
";
        let result = parse_adguard_rules(input);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_adguard_skips_rules_with_path() {
        let input = b"||example.com/ads/banner^
||example.com^
";
        let result = parse_adguard_rules(input);
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
        let result = parse_adguard_rules(input);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "real-domain.com");
    }

    #[test]
    fn parse_adguard_case_normalization() {
        let input = b"||Example.COM^
0.0.0.0 BLOCKED.COM
BARE.EXAMPLE.Com
";
        let result = parse_adguard_rules(input);
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
        let result = parse_adguard_rules(input);
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
        let result = parse_adguard_rules(input);
        let domains: Vec<&str> = result.iter().map(|d| d.value.as_str()).collect();

        // Should include:
        assert!(domains.contains(&"ad.doubleclick.net"));
        assert!(domains.contains(&"adservice.google.com"));
        assert!(domains.contains(&"malware.example.com"));
        assert!(domains.contains(&"simple-tracker.io"));

        // telemetry.example.org is hosts format → Full match
        let telemetry = result.iter().find(|d| d.value == "telemetry.example.org").unwrap();
        assert_eq!(telemetry.match_type, DomainMatchType::Full);

        // Should NOT include:
        assert!(!domains.contains(&"pagead2.googlesyndication.com")); // $third-party
        assert!(!domains.contains(&"googleadservices.com")); // @@ exception
        assert!(!domains.contains(&"cdn.example.com")); // has path
        assert!(!domains.contains(&"tracking.pixel.io")); // exact URL rule
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
        let result = parse_adguard_rules(input);
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
        let result = parse_adguard_rules(input);
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
    fn parse_adguard_rejects_invalid_domain_rule_syntax() {
        let input = b"||*.example.com^
||example..com^
||-example.com^
||example-.com^
||example.com^foo
||example.com:443^
||valid.example.com^$important
";
        let result = parse_adguard_rules(input);
        let domains: Vec<&str> = result.iter().map(|d| d.value.as_str()).collect();

        assert_eq!(domains, vec!["valid.example.com"]);
    }

    #[test]
    fn parse_adguard_applies_exceptions_conservatively() {
        let input = b"||example.com^
@@||ads.example.com^
||safe.com^
0.0.0.0 exact.example.com
@@|https://exact.example.com/path
||parent.test^
@@||parent.test^$document
";
        let result = parse_adguard_rules(input);
        let domains: Vec<&str> = result.iter().map(|d| d.value.as_str()).collect();

        assert_eq!(domains, vec!["safe.com"]);
    }

    #[test]
    fn parse_adguard_badfilter_removes_overlapping_candidates() {
        let input = b"||bad.example.com^
||bad.example.com^$badfilter
||also-bad.example.com^
||also-bad.example.com^$image,badfilter
||ok.example.com^
";
        let result = parse_adguard_rules(input);
        let domains: Vec<&str> = result.iter().map(|d| d.value.as_str()).collect();

        assert_eq!(domains, vec!["ok.example.com"]);
    }

    #[test]
    fn parse_adguard_unscoped_exception_drops_all_candidates() {
        let input = b"||example.com^
@@/example\\.com/
||other.example.com^
";
        let result = parse_adguard_rules(input);

        assert!(result.is_empty());
    }

    #[test]
    fn parse_adguard_bare_domain_dedup_with_other_formats() {
        let input = b"||example.com^
0.0.0.0 example.com
example.com
|https://full.example.com|
full.example.com
";
        let result = parse_adguard_rules(input);

        // example.com appears as both Domain(||example.com^) and Full(0.0.0.0 example.com),
        // bare "example.com" de-duplicates with the Domain one.
        // Total: Domain("example.com"), Full("example.com"), Domain("full.example.com")
        assert_eq!(result.len(), 3);

        let domain_items: Vec<_> = result.iter().filter(|d| d.value == "example.com").collect();
        assert_eq!(domain_items.len(), 2);
        assert!(domain_items.iter().any(|d| d.match_type == DomainMatchType::Domain));
        assert!(domain_items.iter().any(|d| d.match_type == DomainMatchType::Full));

        let full_items: Vec<_> = result.iter().filter(|d| d.value == "full.example.com").collect();
        assert_eq!(full_items.len(), 1);
        assert!(full_items.iter().any(|d| d.match_type == DomainMatchType::Domain));
    }
}
