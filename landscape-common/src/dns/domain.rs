use super::error::DnsError;

pub fn normalize_domain_name(domain: &str) -> Result<String, DnsError> {
    let no_dot = domain.trim().trim_end_matches('.');
    if no_dot.is_empty() {
        return Err(DnsError::Invalid { domain: domain.to_string() });
    }
    let ascii = idna::domain_to_ascii(no_dot)
        .map_err(|_| DnsError::Invalid { domain: domain.to_string() })?;
    Ok(ascii.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::normalize_domain_name;

    #[test]
    fn normalizes_unicode_case_and_trailing_dot() {
        assert_eq!(normalize_domain_name(" BÜCHER.example. ").unwrap(), "xn--bcher-kva.example");
    }

    #[test]
    fn rejects_empty_domain() {
        assert!(normalize_domain_name(" . ").is_err());
    }
}
