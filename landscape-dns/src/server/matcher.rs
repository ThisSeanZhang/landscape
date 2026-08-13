use ahash::AHashSet;
use aho_corasick::AhoCorasick;
use landscape_common::dns::rule::{DomainConfig, DomainMatchType};
use regex::{Regex, RegexSet};
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use zerotrie::ZeroTrieSimpleAscii;

use crate::domain::{normalize_domain_text, ParsedDomain};

#[derive(Debug)]
pub struct DomainMatcher {
    regex_set: RegexSet, // 正则匹配（RegexSet 单自动机，一次扫描全部 pattern）
    full_domains: AHashSet<String>, // full: 规则 + domain: 规则自身（精确命中免走 trie）
    keyword_ac: AhoCorasick, // Aho-Corasick 自动机，用于关键字匹配
    subdomain_trie: Option<ZeroTrieSimpleAscii<Vec<u8>>>, // 双数组 trie，用于子域名匹配
}

impl DomainMatcher {
    pub fn new(domains_config: Vec<DomainConfig>) -> Self {
        let timer = Instant::now();

        let mut full_domains = AHashSet::new();
        let mut regex_patterns = Vec::new();
        let mut keywords = Vec::new();
        let mut subdomain_map = BTreeMap::new();
        let mut skipped_non_ascii = Vec::new();

        let mut sum_count = 0;
        for each_config in domains_config {
            sum_count += 1;
            match each_config.match_type {
                DomainMatchType::Plain => {
                    // 将关键字添加到列表
                    keywords.push(normalize_domain_text(&each_config.value).into_owned());
                }
                DomainMatchType::Regex => {
                    // 先校验语法，非法规则跳过（与原有行为一致），最后统一编译
                    if Regex::new(&each_config.value).is_ok() {
                        regex_patterns.push(each_config.value);
                    }
                }
                DomainMatchType::Domain => {
                    // 子域名匹配（反转字节作为 key 构建双数组 trie）
                    let normalized = normalize_domain_text(&each_config.value);
                    if normalized.is_ascii() {
                        // BTreeMap 键去重，value 统一为 0（bool 语义）
                        let reversed: Vec<u8> =
                            normalized.as_bytes().iter().rev().copied().collect();
                        subdomain_map.insert(reversed, 0usize);
                        // 规则自身并入 full_domains：精确命中免走 trie
                        full_domains.insert(normalized.into_owned());
                    } else {
                        skipped_non_ascii.push(normalized.into_owned());
                    }
                }
                DomainMatchType::Full => {
                    // 完全匹配（存储在 HashSet 中）
                    full_domains.insert(normalize_domain_text(&each_config.value).into_owned());
                }
            }
        }

        // 构建子域名双数组 trie 和 Aho-Corasick 自动机
        let subdomain_trie = if subdomain_map.is_empty() {
            None
        } else {
            match ZeroTrieSimpleAscii::try_from(&subdomain_map) {
                Ok(trie) => Some(trie),
                Err(error) => {
                    tracing::error!(%error, "failed to build subdomain trie");
                    None
                }
            }
        };
        let keyword_ac = AhoCorasick::new(&keywords).unwrap();
        let regex_set = match RegexSet::new(&regex_patterns) {
            Ok(set) => set,
            Err(error) => {
                tracing::error!(%error, "failed to build regex set");
                RegexSet::empty()
            }
        };

        if !skipped_non_ascii.is_empty() {
            const MAX_SAMPLE: usize = 10;
            let sample = if skipped_non_ascii.len() > MAX_SAMPLE {
                let mut shown: Vec<String> = skipped_non_ascii[..MAX_SAMPLE].to_vec();
                shown.push(format!("... and {} more", skipped_non_ascii.len() - MAX_SAMPLE));
                shown.join(", ")
            } else {
                skipped_non_ascii.join(", ")
            };
            tracing::warn!(
                count = skipped_non_ascii.len(),
                rules = %sample,
                "skipped non-ascii domain rules"
            );
        }

        tracing::debug!("total {:?}", sum_count);
        tracing::debug!("full_domains {:?}", full_domains.len());
        tracing::debug!("regex_set {:?}", regex_set.len());
        tracing::debug!("subdomain_trie {:?}", subdomain_map.len());

        tracing::info!("dns match rule load time: {:?}s", timer.elapsed().as_secs());

        DomainMatcher {
            regex_set,
            full_domains,
            keyword_ac,
            subdomain_trie,
        }
    }

    /// Allocation-free match against a domain that is already normalized
    /// (lowercase, no trailing dot). This is the per-query hot path: no
    /// normalization, no reversed-string allocation.
    pub fn is_match_normalized(&self, normalized: &str) -> bool {
        // 完全匹配（含 domain: 规则自身，精确命中免走 trie）
        if self.full_domains.contains(normalized) {
            return true;
        }

        // 子域名匹配：倒序逐字节走查双数组 trie，命中规则时检查标签边界
        if let Some(trie) = &self.subdomain_trie {
            let bytes = normalized.as_bytes();
            let mut cursor = trie.cursor();
            for i in (0..bytes.len()).rev() {
                cursor.step(bytes[i]);
                if cursor.is_empty() {
                    // 死路，不可能有更长的规则命中
                    return false;
                }
                if cursor.take_value().is_some() {
                    let consumed = bytes.len() - i;
                    if consumed == bytes.len() || bytes[bytes.len() - consumed - 1] == b'.' {
                        return true;
                    }
                }
            }
        }

        // 关键字匹配
        if self.keyword_ac.is_match(normalized) {
            return true;
        }

        // 正则表达式匹配（RegexSet 一次扫描全部 pattern）
        if self.regex_set.is_match(normalized) {
            return true;
        }

        false
    }
}

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
    /// precomputed forms of [`ParsedDomain`].
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
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc, time::Instant};

    use jemalloc_ctl::{epoch, stats};

    use landscape_common::{
        config_service::geo::{GeoDomainConfig, GeoFileCacheKey},
        dns::rule::{DomainConfig, DomainMatchType},
        store::storev4::StoreFileManager,
        LANDSCAPE_GEO_CACHE_TMP_DIR,
    };

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

    #[test]
    fn domain_matcher() {
        let mut configs = vec![];
        configs.push(DomainConfig {
            match_type: DomainMatchType::Domain,
            value: "baidu.com".into(),
        });

        let matcher = DomainMatcher::new(configs);
        assert!(matcher.is_match_normalized(pd("baidu.com").name()));
        assert!(!matcher.is_match_normalized(pd("abaidu.com").name()));
    }

    fn test_memory_usage() {
        epoch::advance().unwrap();

        let allocated = stats::allocated::read().unwrap();
        let active = stats::active::read().unwrap();

        println!("Allocated memory: {} kbytes", allocated / 1024);
        println!("Active memory: {} kbytes", active / 1024);
    }

    #[test]
    pub fn mem_useage() {
        for _ in 0..3 {
            epoch::advance().unwrap(); // 预热几次
        }

        println!("==== start ====");
        test_memory_usage();

        let mut site_store: StoreFileManager<GeoFileCacheKey, GeoDomainConfig> =
            StoreFileManager::new(
                PathBuf::from("/root/.landscape-router").join(LANDSCAPE_GEO_CACHE_TMP_DIR),
                "site".to_string(),
            );

        println!("==== after StoreFileManager::new ====");
        test_memory_usage();

        let all = site_store.list();

        println!("all size: {}", all.len());
        println!("==== after list ====");
        test_memory_usage();

        let mut config: Vec<DomainConfig> = vec![];

        for each in all.iter() {
            config.extend(each.values.iter().map(|e| e.to_owned().into()));
        }

        println!("==== after config extend ====");
        test_memory_usage();

        let matcher = DomainMatcher::new(config);

        println!("==== after DomainMatcher::new ====");
        test_memory_usage();

        let time = Instant::now();
        if matcher.is_match_normalized(pd("google.com").name()) {
            println!("got it");
        }
        println!("elpase: {}", time.elapsed().as_micros());

        println!("==== after first matcher ====");
        test_memory_usage();
    }

    #[test]
    pub fn sub_domain_must_match_label_boundary() {
        let configs = vec![DomainConfig {
            match_type: DomainMatchType::Domain,
            value: "ab.com".to_string(),
        }];

        let matcher = DomainMatcher::new(configs);

        // ❌ 错误匹配：zab.com 不是 ab.com 的子域
        assert!(
            !matcher.is_match_normalized(pd("zab.com").name()),
            "Should not match zab.com as a subdomain of ab.com"
        );

        // ✅ 正确匹配：x.ab.com 是 ab.com 的子域
        assert!(
            matcher.is_match_normalized(pd("x.ab.com").name()),
            "Should match x.ab.com as subdomain of ab.com"
        );
    }

    #[test]
    fn sub_domain_match_exact_same_domain() {
        let configs = vec![DomainConfig {
            match_type: DomainMatchType::Domain,
            value: "example.com".to_string(),
        }];

        let matcher = DomainMatcher::new(configs);

        // ✅ 和规则完全一致的域名，也应匹配
        assert!(
            matcher.is_match_normalized(pd("example.com").name()),
            "Should match exact domain same as rule"
        );

        // ✅ 子域名应匹配
        assert!(
            matcher.is_match_normalized(pd("www.example.com").name()),
            "Should match subdomain of example.com"
        );

        // ❌ 错误匹配（子串但非子域）
        assert!(
            !matcher.is_match_normalized(pd("badexample.com").name()),
            "Should not match partial string like badexample.com"
        );
    }

    #[test]
    pub fn sub_domain_match_strict_boundary_test() {
        let configs = vec![
            DomainConfig {
                match_type: DomainMatchType::Domain,
                value: "bbb.com".to_string(), // 更短的匹配
            },
            DomainConfig {
                match_type: DomainMatchType::Domain,
                value: "aaa.bbb.com".to_string(), // 更精确的匹配
            },
        ];

        let matcher = DomainMatcher::new(configs);

        // 正例：应匹配 aaa.bbb.com，因为 test.aaa.bbb.com 是其子域
        assert!(
            matcher.is_match_normalized(pd("test.aaa.bbb.com").name()),
            "Should match subdomain of aaa.bbb.com"
        );

        // 反例：确保 example.bbb.com 只匹配 bbb.com，不误匹配 aaa.bbb.com
        assert!(matcher.is_match_normalized(pd("example.bbb.com").name()), "Should match bbb.com");

        // 反例：example.ccc.com 不应匹配任何
        assert!(
            !matcher.is_match_normalized(pd("example.ccc.com").name()),
            "Should not match ccc.com"
        );
    }

    #[test]
    pub fn sub_domain_match_test() {
        // 测试域名："news.google.com"
        // 我们提供的匹配规则是 "google.com"，类型为 DomainMatchType::Domain

        let configs = vec![DomainConfig {
            match_type: DomainMatchType::Domain,
            value: "google.com".to_string(),
        }];

        let matcher = DomainMatcher::new(configs);

        // ✅ 正向用例：应该匹配成功
        assert!(
            matcher.is_match_normalized(pd("news.google.com").name()),
            "Should match subdomain of google.com"
        );

        // ❌ 反向用例：不应该匹配
        assert!(
            !matcher.is_match_normalized(pd("example.com").name()),
            "Should not match unrelated domain"
        );
    }

    #[test]
    fn full_match_is_case_insensitive() {
        let configs = vec![DomainConfig {
            match_type: DomainMatchType::Full,
            value: "Example.COM".to_string(),
        }];

        let matcher = DomainMatcher::new(configs);

        assert!(matcher.is_match_normalized(pd("example.com").name()));
        assert!(matcher.is_match_normalized(pd("EXAMPLE.COM").name()));
        assert!(matcher.is_match_normalized(pd("example.com.").name()));
    }

    #[test]
    fn domain_match_is_case_insensitive_for_root_and_subdomain() {
        let configs = vec![DomainConfig {
            match_type: DomainMatchType::Domain,
            value: "Example.COM".to_string(),
        }];

        let matcher = DomainMatcher::new(configs);

        assert!(matcher.is_match_normalized(pd("example.com").name()));
        assert!(matcher.is_match_normalized(pd("WWW.EXAMPLE.COM").name()));
    }
}
