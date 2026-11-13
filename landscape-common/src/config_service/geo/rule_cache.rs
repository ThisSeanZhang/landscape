use std::collections::HashSet;

use regex::Regex;

use crate::dns::rule::DomainMatchType;

/// Regex rules only match when the pattern compiles; every other match type is
/// always valid. Shared so the cache and snapshot paths agree on validity.
pub fn site_pattern_is_valid(match_type: &DomainMatchType, value: &str) -> bool {
    !matches!(match_type, DomainMatchType::Regex) || Regex::new(value).is_ok()
}

/// Canonical JSON form of a site rule's attributes: sorted, deduplicated and
/// `None` when empty. Shared so the cache writer and snapshot builders persist
/// byte-identical values.
pub fn site_attributes_to_json<'a, I>(attributes: I) -> Result<Option<String>, serde_json::Error>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut names: Vec<&str> = attributes.into_iter().collect();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(&names).map(Some)
}

/// Inverse of [`site_attributes_to_json`]; malformed or missing values decode
/// to an empty set so a corrupt cache row degrades to "no attributes".
pub fn site_attributes_from_json(raw: Option<&str>) -> HashSet<String> {
    raw.and_then(|text| serde_json::from_str::<Vec<String>>(text).ok())
        .unwrap_or_default()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{site_attributes_from_json, site_attributes_to_json, site_pattern_is_valid};
    use crate::dns::rule::DomainMatchType;

    #[test]
    fn attributes_are_sorted_deduplicated_and_empty_is_none() {
        let json = site_attributes_to_json(["z", "a", "a"]).unwrap();
        assert_eq!(json.as_deref(), Some("[\"a\",\"z\"]"));
        assert_eq!(site_attributes_to_json(std::iter::empty()).unwrap(), None);
    }

    #[test]
    fn attributes_roundtrip() {
        let json = site_attributes_to_json(["cn", "ads", "cn"]).unwrap().unwrap();
        assert_eq!(
            site_attributes_from_json(Some(&json)),
            HashSet::from(["ads".to_string(), "cn".to_string()])
        );
        assert!(site_attributes_from_json(None).is_empty());
        assert!(site_attributes_from_json(Some("not json")).is_empty());
    }

    #[test]
    fn regex_is_only_valid_when_it_compiles() {
        assert!(site_pattern_is_valid(&DomainMatchType::Regex, "^[a-z]+$"));
        assert!(!site_pattern_is_valid(&DomainMatchType::Regex, "(invalid"));
        assert!(site_pattern_is_valid(&DomainMatchType::Domain, "(invalid"));
    }
}
