use aho_corasick::AhoCorasick;
use landscape_common::config::dns::{DomainConfig, DomainMatchType};
use regex::Regex;
use std::{collections::HashSet, time::Instant};
use tracing::debug;
use trie_rs::TrieBuilder;

#[derive(Debug)]
pub struct DomainMatcher {
    regex_domains: Vec<Regex>,         // 用于存储正则表达式规则
    full_domains: HashSet<String>,     // 用于存储完全匹配的域名
    keyword_ac: AhoCorasick,           // Aho-Corasick 自动机，用于关键字匹配
    subdomain_trie: trie_rs::Trie<u8>, // Trie，用于子域名匹配
}

impl DomainMatcher {
    pub fn new(domains_config: Vec<DomainConfig>) -> Self {
        let timer = Instant::now();

        let mut full_domains = HashSet::new();
        let mut regex_domains = Vec::new();
        let mut keywords = Vec::new();
        let mut trie_builder = TrieBuilder::new();

        let mut subdomain_trie_size = 0;

        let mut sum_count = 0;
        // 解析每个 GeoSite 的域名
        for each_config in domains_config {
            sum_count += 1;
            match each_config.match_type {
                DomainMatchType::Plain => {
                    // 将关键字添加到列表
                    keywords.push(each_config.value.to_string());
                }
                DomainMatchType::Regex => {
                    // 将正则表达式添加到 Vec 中
                    if let Ok(regex) = Regex::new(&each_config.value) {
                        regex_domains.push(regex);
                    }
                }
                DomainMatchType::Domain => {
                    // 子域名匹配（倒序存储以便构建 Trie）
                    subdomain_trie_size += 1;
                    let reversed_domain = each_config.value.chars().rev().collect::<String>();
                    trie_builder.push(reversed_domain);
                }
                DomainMatchType::Full => {
                    // 完全匹配（存储在 HashSet 中）
                    full_domains.insert(each_config.value);
                }
            }
        }

        // 构建 Trie 和 Aho-Corasick 自动机
        let subdomain_trie = trie_builder.build();
        let keyword_ac = AhoCorasick::new(&keywords).unwrap();

        debug!("total {:?}", sum_count);
        debug!("full_domains {:?}", full_domains.len());
        debug!("regex_domains {:?}", regex_domains.len());
        debug!("subdomain_trie {:?}", subdomain_trie_size);

        tracing::info!("dns match rule load time: {:?}s", timer.elapsed().as_secs());

        // 返回构建好的 DomainMatcher 实例
        DomainMatcher {
            regex_domains,
            full_domains,
            keyword_ac,
            subdomain_trie,
        }
    }

    // 执行匹配的主方法
    pub fn is_match(&self, domain: &str) -> bool {
        // 完全匹配
        if self.full_domains.contains(domain) {
            return true;
        }

        // 子域名匹配
        let reversed_domain = domain.chars().rev().collect::<String>();
        let reversed_bytes = reversed_domain.as_bytes();

        for result in
            self.subdomain_trie.common_prefix_search::<Vec<u8>, _>(reversed_domain.clone())
        {
            let prefix_len = result.len();
            if reversed_bytes.len() == prefix_len || reversed_bytes.get(prefix_len) == Some(&b'.') {
                return true;
            }
        }

        // 关键字匹配
        if self.keyword_ac.is_match(domain) {
            return true;
        }

        // 正则表达式匹配
        for regex in &self.regex_domains {
            if regex.is_match(domain) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Instant};

    use jemalloc_ctl::{epoch, stats};

    use landscape_common::{
        config::dns::{DomainConfig, DomainMatchType},
        config::geo::{GeoDomainConfig, GeoFileCacheKey},
        store::storev4::StoreFileManager,
        LANDSCAPE_GEO_CACHE_TMP_DIR,
    };

    use super::DomainMatcher;

    #[test]
    fn domain_matcher() {
        let mut configs = vec![];
        configs.push(DomainConfig {
            match_type: DomainMatchType::Domain,
            value: "baidu.com".into(),
        });

        let matcher = DomainMatcher::new(configs);
        assert!(matcher.is_match("baidu.com"));
        assert!(matcher.is_match("abaidu.com"));
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
        if matcher.is_match("google.com") {
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
        assert!(!matcher.is_match("zab.com"), "Should not match zab.com as a subdomain of ab.com");

        // ✅ 正确匹配：x.ab.com 是 ab.com 的子域
        assert!(matcher.is_match("x.ab.com"), "Should match x.ab.com as subdomain of ab.com");
    }

    #[test]
    fn sub_domain_match_exact_same_domain() {
        let configs = vec![DomainConfig {
            match_type: DomainMatchType::Domain,
            value: "example.com".to_string(),
        }];

        let matcher = DomainMatcher::new(configs);

        // ✅ 和规则完全一致的域名，也应匹配
        assert!(matcher.is_match("example.com"), "Should match exact domain same as rule");

        // ✅ 子域名应匹配
        assert!(matcher.is_match("www.example.com"), "Should match subdomain of example.com");

        // ❌ 错误匹配（子串但非子域）
        assert!(
            !matcher.is_match("badexample.com"),
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
        assert!(matcher.is_match("test.aaa.bbb.com"), "Should match subdomain of aaa.bbb.com");

        // 反例：确保 example.bbb.com 只匹配 bbb.com，不误匹配 aaa.bbb.com
        assert!(matcher.is_match("example.bbb.com"), "Should match bbb.com");

        // 反例：example.ccc.com 不应匹配任何
        assert!(!matcher.is_match("example.ccc.com"), "Should not match ccc.com");
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
        assert!(matcher.is_match("news.google.com"), "Should match subdomain of google.com");

        // ❌ 反向用例：不应该匹配
        assert!(!matcher.is_match("example.com"), "Should not match unrelated domain");
    }
}
