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

/// Owned counterpart of `normalize_domain_text`: consumes `value` and rewrites
/// it in place, always reusing its allocation.
pub fn normalize_domain_string(mut value: String) -> String {
    let trimmed_len = value.trim_end_matches('.').len();
    if trimmed_len != value.len() {
        value.truncate(trimmed_len);
    }
    value.make_ascii_lowercase();
    value
}

#[cfg(test)]
mod tests {
    use super::{normalize_domain_name, normalize_domain_string};

    #[test]
    fn normalizes_unicode_case_and_trailing_dot() {
        assert_eq!(normalize_domain_name(" BÜCHER.example. ").unwrap(), "xn--bcher-kva.example");
    }

    #[test]
    fn rejects_empty_domain() {
        assert!(normalize_domain_name(" . ").is_err());
    }

    #[test]
    fn normalize_domain_string_reuses_and_rewrites() {
        assert_eq!(normalize_domain_string("example.com".to_string()), "example.com");
        assert_eq!(normalize_domain_string("Example.COM.".to_string()), "example.com");
        assert_eq!(normalize_domain_string("foo..".to_string()), "foo");
        assert_eq!(normalize_domain_string("FOO..".to_string()), "foo");
        assert_eq!(normalize_domain_string("Foo..".to_string()), "foo");
        assert_eq!(normalize_domain_string("EXAMPLE.com".to_string()), "example.com");
    }
}
