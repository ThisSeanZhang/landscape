use ahash::AHashSet;
use aho_corasick::AhoCorasick;
use landscape_common::dns::domain::normalize_domain_text;
use landscape_common::dns::rule::{DomainConfig, DomainMatchType};
use regex::{Regex, RegexSet};
use std::{collections::BTreeMap, time::Instant};
use zerotrie::ZeroTrieSimpleAscii;

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
                    // 死路，不可能有更长的 domain: 规则命中；继续检查
                    // keyword: 和 regexp: 规则。
                    break;
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
