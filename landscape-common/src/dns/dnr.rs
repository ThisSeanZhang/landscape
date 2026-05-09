use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
};

pub const DHCPV4_DNR_OPTION_CODE: u8 = 162;
const SVC_PARAM_ALPN: u16 = 1;
const SVC_PARAM_PORT: u16 = 3;
const SVC_PARAM_DOHPATH: u16 = 7;

pub fn normalize_advertise_domain(domain: &str) -> Option<String> {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.contains('*')
        || !normalized.is_ascii()
    {
        return None;
    }

    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return None;
        }
    }

    Some(normalized.to_string())
}

pub fn normalize_advertise_domains(domains: impl IntoIterator<Item = String>) -> Vec<String> {
    domains
        .into_iter()
        .filter_map(|domain| normalize_advertise_domain(&domain))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn is_valid_dnr_ipv4_addr(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback())
}

pub fn is_valid_dnr_ipv6_addr(ip: Ipv6Addr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_loopback())
}

pub fn encode_dns_name(name: &str) -> Option<Vec<u8>> {
    let name = normalize_advertise_domain(name)?;
    let mut bytes = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    Some(bytes)
}

pub fn encode_doh_svc_params(port: u16, doh_path: &str) -> Option<Vec<u8>> {
    let doh_path = normalize_doh_path_template(doh_path)?;
    let mut params = Vec::new();
    append_svc_param(&mut params, SVC_PARAM_ALPN, &[2, b'h', b'2'])?;
    append_svc_param(&mut params, SVC_PARAM_PORT, &port.to_be_bytes())?;
    append_svc_param(&mut params, SVC_PARAM_DOHPATH, doh_path.as_bytes())?;
    Some(params)
}

pub fn normalize_doh_path_template(doh_path: &str) -> Option<String> {
    let doh_path = doh_path.trim();
    if doh_path.is_empty()
        || !doh_path.starts_with('/')
        || !doh_path.is_ascii()
        || doh_path.contains('#')
    {
        return None;
    }

    let mut matched_token = None;
    for token in ["{?dns}", "{&dns}", "{dns}"] {
        match doh_path.matches(token).count() {
            0 => {}
            1 if matched_token.is_none() => matched_token = Some(token),
            _ => return None,
        }
    }

    if let Some(token) = matched_token {
        let (before_template, _) = doh_path.split_once(token)?;
        let without_template = doh_path.replacen(token, "", 1);
        if without_template.contains('{') || without_template.contains('}') {
            return None;
        }
        if token == "{?dns}" && before_template.contains('?') {
            return None;
        }
        if token == "{&dns}" && !before_template.contains('?') {
            return None;
        }
        return Some(doh_path.to_string());
    }

    if doh_path.contains('?') || doh_path.contains('{') || doh_path.contains('}') {
        return None;
    }

    Some(format!("{doh_path}{{?dns}}"))
}

pub fn encode_unknown_svc_param_value(value: &[u8]) -> hickory_proto::rr::rdata::svcb::Unknown {
    hickory_proto::rr::rdata::svcb::Unknown(value.to_vec())
}

pub fn encode_dhcpv4_dnr_instance(
    domain: &str,
    ipv4_addrs: &[Ipv4Addr],
    port: u16,
    doh_path: &str,
) -> Option<Vec<u8>> {
    if ipv4_addrs.is_empty() {
        return None;
    }
    let adn = encode_dns_name(domain)?;
    let svc_params = encode_doh_svc_params(port, doh_path)?;
    let addr_len = ipv4_addrs.len().checked_mul(4)?;
    if adn.len() > u8::MAX as usize || addr_len > u8::MAX as usize {
        return None;
    }

    let instance_len = 2usize + 1 + adn.len() + 1 + addr_len + svc_params.len();
    if instance_len > u16::MAX as usize {
        return None;
    }
    let mut bytes = Vec::with_capacity(2 + instance_len);
    bytes.extend_from_slice(&(instance_len as u16).to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(adn.len() as u8);
    bytes.extend_from_slice(&adn);
    bytes.push(addr_len as u8);
    for ip in ipv4_addrs {
        bytes.extend_from_slice(&ip.octets());
    }
    bytes.extend_from_slice(&svc_params);
    Some(bytes)
}

pub fn encode_dhcpv4_dnr_payload_truncated(
    domains: &[String],
    ipv4_addrs: &[Ipv4Addr],
    port: u16,
    doh_path: &str,
    max_len: usize,
) -> Vec<u8> {
    let mut payload = Vec::new();
    for domain in domains {
        let Some(instance) = encode_dhcpv4_dnr_instance(domain, ipv4_addrs, port, doh_path) else {
            continue;
        };
        if payload.len() + instance.len() > max_len {
            tracing::warn!(
                "skip DNR domain {domain} because DHCPv4 option 162 exceeds {max_len} bytes"
            );
            continue;
        }
        payload.extend_from_slice(&instance);
    }
    payload
}

fn append_svc_param(params: &mut Vec<u8>, key: u16, value: &[u8]) -> Option<()> {
    if value.len() > u16::MAX as usize {
        return None;
    }
    params.extend_from_slice(&key.to_be_bytes());
    params.extend_from_slice(&(value.len() as u16).to_be_bytes());
    params.extend_from_slice(value);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wildcard_domains() {
        assert_eq!(normalize_advertise_domain("*.Example.COM."), None);
    }

    #[test]
    fn rejects_invalid_domains() {
        assert_eq!(normalize_advertise_domain("bad..example.com"), None);
        assert_eq!(normalize_advertise_domain("-bad.example.com"), None);
        assert_eq!(normalize_advertise_domain("bad_.example.com"), None);
    }

    #[test]
    fn encodes_dns_name_wire_format() {
        assert_eq!(
            encode_dns_name("doh.example.com").unwrap(),
            b"\x03doh\x07example\x03com\x00".to_vec()
        );
    }

    #[test]
    fn normalizes_doh_path_to_template() {
        assert_eq!(
            normalize_doh_path_template("/dns-query").unwrap(),
            "/dns-query{?dns}".to_string()
        );
        assert_eq!(
            normalize_doh_path_template("/dns-query{?dns}").unwrap(),
            "/dns-query{?dns}".to_string()
        );
        assert_eq!(normalize_doh_path_template("dns-query"), None);
        assert_eq!(normalize_doh_path_template("/dns-query?foo=bar"), None);
    }

    #[test]
    fn encodes_dohpath_template_svc_param() {
        let params = encode_doh_svc_params(6053, "/dns-query").unwrap();
        assert!(params.windows(b"/dns-query{?dns}".len()).any(|w| w == b"/dns-query{?dns}"));
    }

    #[test]
    fn truncates_dhcpv4_payload() {
        let domains = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        let payload = encode_dhcpv4_dnr_payload_truncated(
            &domains,
            &[Ipv4Addr::new(192, 168, 5, 1)],
            6053,
            "/dns-query",
            64,
        );
        assert!(!payload.is_empty());
        assert!(payload.len() <= 64);
        let second = encode_dhcpv4_dnr_instance(
            "b.example.com",
            &[Ipv4Addr::new(192, 168, 5, 1)],
            6053,
            "/dns-query",
        )
        .unwrap();
        assert!(payload.len() < second.len() * 2);
    }
}
