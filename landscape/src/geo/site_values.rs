use landscape_common::{
    config_service::geo::GeoSiteFileConfig,
    dns::{domain::normalize_domain_string, rule::DomainMatchType},
};
use sha2::{Digest, Sha256};

pub(crate) type GeoContentHash = [u8; 32];

pub(crate) fn geo_values_hash(values: &[GeoSiteFileConfig]) -> GeoContentHash {
    let mut hasher = Sha256::new();
    update_len_prefixed(&mut hasher, values.len());

    for value in values {
        hasher.update([domain_match_type_tag(&value.match_type)]);
        update_len_prefixed(&mut hasher, value.value.len());
        hasher.update(value.value.as_bytes());

        // HashSet iteration order is intentionally randomized. Sort only the
        // borrowed attribute names so equivalent Geo entries get the same hash.
        let mut attributes: Vec<&str> = value.attributes.iter().map(String::as_str).collect();
        attributes.sort_unstable();
        update_len_prefixed(&mut hasher, attributes.len());
        for attribute in attributes {
            update_len_prefixed(&mut hasher, attribute.len());
            hasher.update(attribute.as_bytes());
        }
    }

    hasher.finalize().into()
}

/// Hex content hash stored in the cache for skip-writes.
pub(crate) fn geo_values_hash_hex(values: &[GeoSiteFileConfig]) -> String {
    geo_values_hash(values).iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn domain_match_type_tag(match_type: &DomainMatchType) -> u8 {
    match match_type {
        DomainMatchType::Plain => 0,
        DomainMatchType::Regex => 1,
        DomainMatchType::Domain => 2,
        DomainMatchType::Full => 3,
    }
}

/// Domain-matching values are normalized for SQL candidate probing; Regex
/// values are patterns where case and trailing `.` are significant, stored
/// verbatim.
pub(crate) fn normalize_site_rule_value(match_type: &DomainMatchType, value: String) -> String {
    match match_type {
        DomainMatchType::Regex => value,
        _ => normalize_domain_string(value),
    }
}

fn update_len_prefixed(hasher: &mut Sha256, length: usize) {
    hasher.update((length as u64).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use landscape_common::{
        config_service::geo::GeoSiteFileConfig,
        dns::rule::{DomainConfig, DomainMatchType},
    };

    use super::{
        GeoContentHash, domain_match_type_tag, geo_values_hash, normalize_site_rule_value,
    };

    fn geo_value(value: &str, attributes: &[&str]) -> GeoSiteFileConfig {
        GeoSiteFileConfig {
            match_type: DomainMatchType::Domain,
            value: value.to_string(),
            attributes: attributes.iter().map(|attribute| (*attribute).to_string()).collect(),
        }
    }

    #[test]
    fn geo_hash_ignores_attribute_hashset_order() {
        let first = vec![geo_value("example.com", &["cn", "ads"])];
        let second = vec![geo_value("example.com", &["ads", "cn"])];

        assert_eq!(geo_values_hash(&first), geo_values_hash(&second));
    }

    #[test]
    fn geo_hash_changes_for_matching_content() {
        let first = vec![geo_value("example.com", &["cn"])];
        let changed_domain = vec![geo_value("changed.example.com", &["cn"])];
        let changed_attribute = vec![geo_value("example.com", &["ads"])];

        assert_ne!(geo_values_hash(&first), geo_values_hash(&changed_domain));
        assert_ne!(geo_values_hash(&first), geo_values_hash(&changed_attribute));
    }

    #[test]
    fn geo_hash_distinguishes_match_types() {
        assert_ne!(
            domain_match_type_tag(&DomainMatchType::Domain),
            domain_match_type_tag(&DomainMatchType::Full)
        );
    }

    #[test]
    fn geo_hash_is_a_fixed_size_digest() {
        let hash: GeoContentHash = geo_values_hash(&[]);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn storage_normalization_trims_and_lowercases_domain_types() {
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Domain, "Example.COM.".to_string()),
            "example.com"
        );
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Full, "WWW.Example.com..".to_string()),
            "www.example.com"
        );
        assert_eq!(normalize_site_rule_value(&DomainMatchType::Plain, "Foo.".to_string()), "foo");
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Domain, "example.com".to_string()),
            "example.com"
        );
    }

    #[test]
    fn storage_normalization_keeps_regex_verbatim() {
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Regex, "[A-Z]+\\.".to_string()),
            "[A-Z]+\\."
        );
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Regex, "^abc.".to_string()),
            "^abc."
        );
    }

    #[test]
    fn source_domain_conversion_does_not_include_attributes() {
        let value = geo_value("example.com", &["cn"]);
        let converted: DomainConfig = value.clone().into();
        assert_eq!(converted.value, value.value);
        assert_eq!(converted.match_type, value.match_type);
        assert_eq!(value.attributes, HashSet::from(["cn".to_string()]));
    }
}
