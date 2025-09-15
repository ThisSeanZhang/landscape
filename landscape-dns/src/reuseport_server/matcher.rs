use aho_corasick::AhoCorasick;
use landscape_common::config::dns::{DomainConfig, DomainMatchType};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Instant;
use trie_rs::{Trie, TrieBuilder};

#[derive(Debug)]
pub struct DomainMatcher<T> {
    regex_domains: Vec<(Regex, Arc<T>)>,    // Regex -> value
    full_domains: HashMap<String, Arc<T>>,  // Full -> value
    keyword_ac: AhoCorasick,                // Aho-Corasick 自动机
    keyword_map: HashMap<String, Arc<T>>,   // keyword -> value
    subdomain_trie: Trie<u8>,               // Trie 用于子域名
    subdomain_map: HashMap<String, Arc<T>>, // reversed_domain -> value
}

impl<T> DomainMatcher<T> {
    pub fn new(domains_config: HashMap<DomainConfig, Arc<T>>) -> Self {
        let timer = Instant::now();

        let mut full_domains = HashMap::new();
        let mut regex_domains = Vec::new();
        let mut keywords = Vec::new();
        let mut keyword_map = HashMap::new();
        let mut trie_builder = TrieBuilder::new();
        let mut subdomain_map = HashMap::new();

        let mut subdomain_trie_size = 0;

        for (each_config, rule_value) in domains_config {
            match each_config.match_type {
                DomainMatchType::Plain => {
                    keywords.push(each_config.value.clone());
                    keyword_map.insert(each_config.value, rule_value);
                }
                DomainMatchType::Regex => {
                    if let Ok(regex) = Regex::new(&each_config.value) {
                        regex_domains.push((regex, rule_value));
                    }
                }
                DomainMatchType::Domain => {
                    subdomain_trie_size += 1;
                    let reversed_domain = each_config.value.chars().rev().collect::<String>();
                    trie_builder.push(&reversed_domain);
                    subdomain_map.insert(reversed_domain, rule_value);
                }
                DomainMatchType::Full => {
                    full_domains.insert(each_config.value, rule_value);
                }
            }
        }

        let subdomain_trie = trie_builder.build();
        let keyword_ac = AhoCorasick::new(&keywords).unwrap();

        tracing::debug!("full_domains {:?}", full_domains.len());
        tracing::debug!("regex_domains {:?}", regex_domains.len());
        tracing::debug!("subdomain_trie {:?}", subdomain_trie_size);

        tracing::info!("dns match rule load time: {:?}s", timer.elapsed().as_secs());

        DomainMatcher {
            regex_domains,
            full_domains,
            keyword_ac,
            keyword_map,
            subdomain_trie,
            subdomain_map,
        }
    }

    pub fn match_value(&self, domain: &str) -> Option<&T> {
        let domain = if let Some(stripped) = domain.strip_suffix('.') { stripped } else { domain };

        // 1. 完全匹配
        if let Some(val) = self.full_domains.get(domain) {
            return Some(val);
        }

        // 2. 子域名匹配
        let reversed_domain = domain.chars().rev().collect::<String>();
        let reversed_bytes = reversed_domain.as_bytes();

        for result in
            self.subdomain_trie.common_prefix_search::<Vec<u8>, _>(reversed_domain.clone())
        {
            let prefix_len = result.len();
            if reversed_bytes.len() == prefix_len || reversed_bytes.get(prefix_len) == Some(&b'.') {
                if let Some(val) = self.subdomain_map.get(&reversed_domain[..prefix_len]) {
                    return Some(val);
                }
            }
        }

        // 3. 关键字匹配
        for mat in self.keyword_ac.find_iter(domain) {
            let keyword = &domain[mat.start()..mat.end()];
            if let Some(val) = self.keyword_map.get(keyword) {
                return Some(val);
            }
        }

        // 4. 正则匹配
        for (regex, val) in &self.regex_domains {
            if regex.is_match(domain) {
                return Some(val);
            }
        }

        None
    }
}
