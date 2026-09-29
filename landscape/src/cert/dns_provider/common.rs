use std::collections::HashMap;
use std::sync::Mutex;

use landscape_common::cert::CertError;

type RecordKey = (String, String);

pub struct RecordStore<T> {
    inner: Mutex<HashMap<RecordKey, T>>,
}

impl<T> RecordStore<T> {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    pub fn insert(&self, domain: &str, value: &str, record: T) {
        self.inner.lock().unwrap().insert((domain.to_string(), value.to_string()), record);
    }

    pub fn get_cloned(&self, domain: &str, value: &str) -> Option<T>
    where
        T: Clone,
    {
        self.inner.lock().unwrap().get(&(domain.to_string(), value.to_string())).cloned()
    }

    pub fn remove(&self, domain: &str, value: &str) -> Option<T> {
        self.inner.lock().unwrap().remove(&(domain.to_string(), value.to_string()))
    }
}

pub fn candidate_zones(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.split('.').filter(|label| !label.is_empty()).collect();
    if labels.len() < 2 {
        return Vec::new();
    }

    (0..labels.len().saturating_sub(1)).map(|i| labels[i..].join(".")).collect()
}

pub fn normalize_validation_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').trim_start_matches("*.").to_ascii_lowercase()
}

pub fn relative_record_name(domain: &str, zone: &str) -> Result<String, CertError> {
    if domain == zone {
        return Ok("_acme-challenge".to_string());
    }

    let suffix = format!(".{zone}");
    if let Some(prefix) = domain.strip_suffix(&suffix) {
        if prefix.is_empty() {
            return Ok("_acme-challenge".to_string());
        }
        return Ok(format!("_acme-challenge.{prefix}"));
    }

    Err(CertError::DnsChallengeSetupFailed(format!(
        "domain '{domain}' does not belong to DNS zone '{zone}'"
    )))
}

pub fn record_name(domain: &str) -> String {
    format!("_acme-challenge.{domain}")
}

pub fn fqdn(name: &str) -> String {
    if name.ends_with('.') { name.to_string() } else { format!("{name}.") }
}

pub fn quote_txt_value(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn unquote_txt_value(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_zones, fqdn, quote_txt_value, record_name, relative_record_name,
        unquote_txt_value,
    };

    #[test]
    fn candidate_zones_walks_from_full_name_to_base_zone() {
        assert_eq!(
            candidate_zones("a.b.example.com"),
            vec!["a.b.example.com", "b.example.com", "example.com"]
        );
        assert_eq!(candidate_zones("example.com"), vec!["example.com"]);
    }

    #[test]
    fn relative_record_name_matches_zone_depth() {
        assert_eq!(relative_record_name("example.com", "example.com").unwrap(), "_acme-challenge");
        assert_eq!(
            relative_record_name("a.b.example.com", "example.com").unwrap(),
            "_acme-challenge.a.b"
        );
    }

    #[test]
    fn record_name_and_quoting_helpers_are_stable() {
        assert_eq!(record_name("example.com"), "_acme-challenge.example.com");
        assert_eq!(fqdn("example.com"), "example.com.");
        assert_eq!(quote_txt_value("value"), "\"value\"");
        assert_eq!(unquote_txt_value("\"value\""), "value");
    }
}
