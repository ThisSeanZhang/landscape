use std::borrow::Cow;

use super::error::DnsServiceError;

pub fn normalize_domain_name(domain: &str) -> Result<String, DnsServiceError> {
    let no_dot = domain.trim().trim_end_matches('.');
    if no_dot.is_empty() {
        return Err(DnsServiceError::Invalid { domain: domain.to_string() });
    }
    let ascii = idna::domain_to_ascii(no_dot)
        .map_err(|_| DnsServiceError::Invalid { domain: domain.to_string() })?;
    Ok(ascii.to_ascii_lowercase())
}

/// Trims trailing dots and lowercases ASCII uppercase bytes; `Cow` borrows
/// already-normalized input.
pub fn normalize_domain_text(domain: &str) -> Cow<'_, str> {
    let trimmed = domain.trim_end_matches('.');
    if trimmed.as_bytes().iter().any(u8::is_ascii_uppercase) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
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
