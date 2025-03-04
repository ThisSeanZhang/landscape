use aho_corasick::AhoCorasick;
use regex::Regex;
use std::collections::HashSet;
use tracing::debug;
use trie_rs::TrieBuilder;

use crate::rule::DomainMatchType;

use super::DomainConfig;

pub struct DomainMatcher {
    regex_domains: Vec<Regex>,         // 用于存储正则表达式规则
    full_domains: HashSet<String>,     // 用于存储完全匹配的域名
    keyword_ac: AhoCorasick,           // Aho-Corasick 自动机，用于关键字匹配
    subdomain_trie: trie_rs::Trie<u8>, // Trie，用于子域名匹配
}

impl DomainMatcher {
    pub fn new(domains_config: Vec<DomainConfig>) -> Self {
        let mut full_domains = HashSet::new();
        let mut regex_domains = Vec::new();
        let mut keywords = Vec::new();
        let mut trie_builder = TrieBuilder::new();

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
        let size = subdomain_trie.iter::<Vec<u8>, _>().count();
        // 返回构建好的 DomainMatcher 实例

        debug!("total {:?}", sum_count);
        debug!("full_domains {:?}", full_domains.len());
        debug!("subdomain_trie {:?}", size);
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
        if self.subdomain_trie.common_prefix_search::<Vec<u8>, _>(reversed_domain).next().is_some()
        {
            return true;
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
mod tests {
    use crate::rule::{DomainConfig, DomainMatchType};

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
}
