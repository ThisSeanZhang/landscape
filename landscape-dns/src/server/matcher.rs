use std::sync::Arc;

use landscape_common::dns::rule::DomainConfig;

use crate::domain::ParsedDomain;

pub use landscape_core::geo_cache::DomainMatcher;

#[derive(Debug)]
pub struct RuntimeRuleMatcher {
    manual: Option<DomainMatcher>,
    positive_geo: Vec<Arc<DomainMatcher>>,
    negative_geo: Vec<Arc<DomainMatcher>>,
    match_all: bool,
}

impl RuntimeRuleMatcher {
    pub fn new(
        manual: Vec<DomainConfig>,
        positive_geo: Vec<Arc<DomainMatcher>>,
        negative_geo: Vec<Arc<DomainMatcher>>,
        match_all: bool,
    ) -> Self {
        Self {
            manual: (!manual.is_empty()).then(|| DomainMatcher::new(manual)),
            positive_geo,
            negative_geo,
            match_all,
        }
    }

    /// Per-query hot path: no re-normalization, matching against the
    /// precomputed forms of [`crate::domain::ParsedDomain`].
    ///
    /// Intended semantics for inverse (negative) geo keys: an inverse key is
    /// no longer expanded at compile time into "the union of domains from all
    /// same-name keys except the excluded one". Instead it matches at runtime
    /// by "not in the excluded key", i.e. it matches every domain except those
    /// in the excluded key. Note: under this semantics an inverse rule behaves
    /// like a near match-all and may shadow later rules; this is expected.
    /// Also note: the builder never produces a matcher whose only source is an
    /// empty or missing inverse key — such a rule is skipped entirely (see
    /// `MatcherBuilder::build_rule_matcher`), so the "empty negative matches
    /// everything" behavior below only exists when this struct is constructed
    /// directly (e.g. in tests) and must not be reintroduced through the
    /// builder.
    pub fn is_match(&self, domain: &ParsedDomain) -> bool {
        if self.match_all {
            return true;
        }

        self.manual.as_ref().is_some_and(|matcher| matcher.is_match_normalized(domain.name()))
            || self.positive_geo.iter().any(|matcher| matcher.is_match_normalized(domain.name()))
            || (!self.negative_geo.is_empty()
                && !self
                    .negative_geo
                    .iter()
                    .any(|matcher| matcher.is_match_normalized(domain.name())))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use landscape_common::dns::rule::{DomainConfig, DomainMatchType};

    use super::{DomainMatcher, RuntimeRuleMatcher};
    use crate::domain::ParsedDomain;

    fn pd(name: &str) -> ParsedDomain {
        ParsedDomain::new(name).unwrap()
    }

    fn full(value: &str) -> DomainConfig {
        DomainConfig {
            match_type: DomainMatchType::Full,
            value: value.to_string(),
        }
    }

    #[test]
    fn runtime_rule_matcher_combines_manual_positive_and_negative_sources() {
        let matcher = RuntimeRuleMatcher::new(
            vec![full("manual.example")],
            vec![Arc::new(DomainMatcher::new(vec![full("positive.example")]))],
            vec![Arc::new(DomainMatcher::new(vec![full("excluded.example")]))],
            false,
        );

        assert!(matcher.is_match(&pd("manual.example")));
        assert!(matcher.is_match(&pd("positive.example")));
        assert!(matcher.is_match(&pd("other.example")));
        assert!(!matcher.is_match(&pd("excluded.example")));
    }

    #[test]
    fn positive_match_overrides_a_negative_geo_match() {
        let matcher = RuntimeRuleMatcher::new(
            vec![],
            vec![Arc::new(DomainMatcher::new(vec![full("shared.example")]))],
            vec![Arc::new(DomainMatcher::new(vec![full("shared.example")]))],
            false,
        );

        assert!(matcher.is_match(&pd("shared.example")));
    }

    #[test]
    fn empty_positive_and_negative_geo_matchers_keep_defined_semantics() {
        let positive_empty = RuntimeRuleMatcher::new(
            vec![],
            vec![Arc::new(DomainMatcher::new(vec![]))],
            vec![],
            false,
        );
        let negative_empty = RuntimeRuleMatcher::new(
            vec![],
            vec![],
            vec![Arc::new(DomainMatcher::new(vec![]))],
            false,
        );

        assert!(!positive_empty.is_match(&pd("example.com")));
        assert!(negative_empty.is_match(&pd("example.com")));
    }
}
