//! Combined ground-truth tests for the geo site cache: the SQL lookup
//! semantics ([`SiteCacheRepository`]) and the compiled matcher semantics
//! ([`DomainMatcher`]) are mirror images of the same rule semantics; the
//! golden table below pins both engines to one truth. The SQL golden twin of
//! that table (written through the production normalization path) lives in
//! `landscape/src/geo/site_service.rs`.

use std::{collections::HashSet, sync::Arc, time::Duration};

use landscape_common::{
    config_service::geo::{GeoConfigKey, GeoFileCacheKey, GeoSiteFileConfig},
    dns::domain::normalize_domain_text,
    dns::rule::{DomainConfig, DomainMatchType},
};

use super::{
    CacheWriteOutcome, DomainMatcher, GeoCacheDatabase, SiteCacheRepository, SiteMatcherRegistry,
    SiteRuleRow, site::suffix_candidates,
};

// ---------------------------------------------------------------------------
// SiteCacheRepository (SQL)
// ---------------------------------------------------------------------------

fn rule(domain: &str, match_type: DomainMatchType, attributes: &[&str]) -> SiteRuleRow {
    SiteRuleRow::new(
        match_type,
        domain.to_string(),
        attributes.iter().map(|a| a.to_string()).collect(),
    )
}

async fn repo() -> SiteCacheRepository {
    SiteCacheRepository::new(GeoCacheDatabase::site_mem().await)
}

#[test]
fn suffix_candidates_walks_dot_boundaries() {
    assert_eq!(
        suffix_candidates("www.a.b.c"),
        vec!["www.a.b.c".to_string(), "a.b.c".to_string(), "b.c".to_string(), "c".to_string(),]
    );
}

#[tokio::test]
async fn replace_reports_inserted_unchanged_updated() {
    let repo = repo().await;
    let rules = vec![rule("example.com", DomainMatchType::Domain, &[])];

    assert_eq!(
        repo.replace_by_name("geosite", "CN", "hash-1", rules.clone()).await.unwrap(),
        CacheWriteOutcome::Inserted
    );
    assert_eq!(
        repo.replace_by_name("geosite", "CN", "hash-1", rules).await.unwrap(),
        CacheWriteOutcome::Unchanged
    );
    assert_eq!(
        repo.replace_by_name(
            "geosite",
            "CN",
            "hash-2",
            vec![rule("new.example", DomainMatchType::Domain, &[])]
        )
        .await
        .unwrap(),
        CacheWriteOutcome::Updated
    );

    let entry = repo.load_entry("geosite", "CN").await.unwrap().unwrap();
    assert_eq!(entry.values.len(), 1);
    assert_eq!(entry.values[0].value, "new.example");
    assert_eq!(entry.name, "geosite");
    assert_eq!(entry.key, "CN");
}

#[tokio::test]
async fn empty_rules_entry_is_some_with_no_values() {
    let repo = repo().await;
    repo.replace_by_name("geosite", "EMPTY", "hash-1", vec![]).await.unwrap();

    let entry = repo.load_entry("geosite", "EMPTY").await.unwrap().unwrap();
    assert!(entry.values.is_empty());
    assert!(repo.has_name("geosite").await.unwrap());
}

#[tokio::test]
async fn attributes_roundtrip_through_null_and_json() {
    let repo = repo().await;
    repo.replace_by_name(
        "geosite",
        "CN",
        "hash-1",
        vec![
            rule("a.com", DomainMatchType::Domain, &[]),
            rule("b.com", DomainMatchType::Domain, &["ads", "cn"]),
        ],
    )
    .await
    .unwrap();

    let entry = repo.load_entry("geosite", "CN").await.unwrap().unwrap();
    assert!(entry.values[0].attributes.is_empty());
    assert_eq!(
        entry.values[1].attributes,
        ["ads".to_string(), "cn".to_string()].into_iter().collect()
    );
}

#[tokio::test]
async fn lookup_returns_semantic_matches() {
    let repo = repo().await;
    repo.replace_by_name(
        "geosite",
        "CN",
        "hash-1",
        vec![
            rule("google.com", DomainMatchType::Domain, &[]),
            rule("www.google.com", DomainMatchType::Full, &[]),
            // Full is exact: a bare TLD does not match subdomains
            rule("com", DomainMatchType::Full, &[]),
            // Plain is substring: "cloud" is not inside "www.google.com"
            rule("cloud", DomainMatchType::Plain, &[]),
            rule("^www\\.", DomainMatchType::Regex, &[]),
            rule("unrelated.org", DomainMatchType::Domain, &[]),
        ],
    )
    .await
    .unwrap();

    let hits = repo.lookup_rules_by_domain("www.google.com").await.unwrap();
    let domains: Vec<&str> = hits.iter().map(|hit| hit.domain.as_str()).collect();
    assert_eq!(domains, vec!["google.com", "www.google.com", "^www\\."]);
    for hit in &hits {
        assert_eq!(hit.key.name, "geosite");
        assert_eq!(hit.key.key, "CN");
    }
}

#[tokio::test]
async fn plain_like_escaping_and_invalid_regex_rows() {
    let repo = repo().await;
    repo.replace_by_name(
        "geosite",
        "CN",
        "hash-1",
        vec![
            rule("gle.co", DomainMatchType::Plain, &[]),
            // literal "_" / "%" must not act as LIKE wildcards
            rule("goog_e", DomainMatchType::Plain, &[]),
            rule("goog%", DomainMatchType::Plain, &[]),
            // invalid patterns are flagged at write time: skipped, and
            // the REGEXP arm must not error the whole query
            rule("(invalid", DomainMatchType::Regex, &[]),
            rule("^ftp", DomainMatchType::Regex, &[]),
        ],
    )
    .await
    .unwrap();

    let hits = repo.lookup_rules_by_domain("www.google.com").await.unwrap();
    let domains: Vec<&str> = hits.iter().map(|hit| hit.domain.as_str()).collect();
    assert_eq!(domains, vec!["gle.co"]);
}

#[tokio::test]
async fn delete_cascades_rules_and_keys() {
    let repo = repo().await;
    repo.replace_by_name(
        "geosite",
        "CN",
        "hash-1",
        vec![rule("a.com", DomainMatchType::Domain, &[])],
    )
    .await
    .unwrap();
    repo.replace_by_name(
        "geosite",
        "US",
        "hash-1",
        vec![rule("b.com", DomainMatchType::Domain, &[])],
    )
    .await
    .unwrap();

    assert!(repo.delete_by_name("geosite", "CN").await.unwrap());
    assert!(!repo.delete_by_name("geosite", "CN").await.unwrap());

    assert!(repo.load_entry("geosite", "CN").await.unwrap().is_none());
    assert!(repo.load_entry("geosite", "US").await.unwrap().is_some());
    let keys = repo.keys_for_name("geosite").await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key, "US");

    let all = repo.list_keys().await.unwrap();
    assert_eq!(all.len(), 1);
}

// ---------------------------------------------------------------------------
// DomainMatcher (compiled)
// ---------------------------------------------------------------------------

/// Normalized form of a query name (lowercase, no trailing dot): the input
/// contract of `DomainMatcher::is_match_normalized`.
fn norm(name: &str) -> String {
    normalize_domain_text(name).into_owned()
}

fn domain_rule(match_type: DomainMatchType, value: &str) -> DomainConfig {
    DomainConfig { match_type, value: value.to_string() }
}

#[test]
fn domain_matcher() {
    let configs = vec![DomainConfig {
        match_type: DomainMatchType::Domain,
        value: "baidu.com".into(),
    }];

    let matcher = DomainMatcher::new(configs);
    assert!(matcher.is_match_normalized(&norm("baidu.com")));
    assert!(!matcher.is_match_normalized(&norm("abaidu.com")));
}

#[test]
fn trie_misses_fall_through_to_keyword_and_regex() {
    let matcher = DomainMatcher::new(vec![
        domain_rule(DomainMatchType::Domain, "example.com"),
        domain_rule(DomainMatchType::Plain, "keyword"),
        domain_rule(DomainMatchType::Plain, "notexample"),
        domain_rule(DomainMatchType::Regex, r"^api\d+\.other\.net$"),
    ]);

    // The reversed trie cannot consume the first byte, but keyword and
    // regex rules must still be evaluated.
    assert!(matcher.is_match_normalized(&norm("keyword.other.net")));
    assert!(matcher.is_match_normalized(&norm("api42.other.net")));

    // The trie reaches example.com but the preceding byte is not a label
    // boundary, so a later keyword rule must still be allowed to match.
    assert!(matcher.is_match_normalized(&norm("notexample.com")));
    assert!(!matcher.is_match_normalized(&norm("unrelated.other.net")));
}

#[test]
fn plain_keyword_rules_match_substrings_case_insensitively() {
    let matcher = DomainMatcher::new(vec![
        domain_rule(DomainMatchType::Plain, "Example"),
        domain_rule(DomainMatchType::Plain, "cdn"),
    ]);

    assert!(matcher.is_match_normalized(&norm("example.com")));
    assert!(matcher.is_match_normalized(&norm("EXAMPLE.COM")));
    assert!(matcher.is_match_normalized(&norm("cdn.example.net")));
    assert!(matcher.is_match_normalized(&norm("unrelated.example.org")));
    assert!(!matcher.is_match_normalized(&norm("other.org")));
}

#[test]
fn regex_rules_match_on_normalized_input() {
    let matcher =
        DomainMatcher::new(vec![domain_rule(DomainMatchType::Regex, r"^node\d+\.example\.org$")]);

    assert!(matcher.is_match_normalized(&norm("node42.example.org")));
    assert!(!matcher.is_match_normalized(&norm("node42.example.com")));
    assert!(matcher.is_match_normalized(&norm("NODE42.Example.Org")));
}

/// Golden semantics table shared with the SQL ground-truth test
/// (landscape/src/geo/site_service.rs) — keep both copies in sync.
fn golden_semantics_cases() -> Vec<(DomainMatchType, &'static str, &'static str, bool)> {
    vec![
        // Domain: self, dot-suffix, and the dot-boundary negative;
        // rule side is normalized (case, trailing dot)
        (DomainMatchType::Domain, "example.com", "example.com", true),
        (DomainMatchType::Domain, "example.com", "www.example.com", true),
        (DomainMatchType::Domain, "ogle.com", "www.google.com", false),
        (DomainMatchType::Domain, "Example.COM.", "www.example.com", true),
        // Full: exact only, rule side normalized
        (DomainMatchType::Full, "sub.example.com", "sub.example.com", true),
        (DomainMatchType::Full, "example.com", "www.example.com", false),
        (DomainMatchType::Full, "Sub.Example.COM.", "sub.example.com", true),
        // Plain: substring; literal "_" / "%" are not wildcards
        (DomainMatchType::Plain, "cloud", "www.cloudflare.com", true),
        (DomainMatchType::Plain, "Foo.", "www.foo.com", true),
        (DomainMatchType::Plain, "cloud", "example.com", false),
        (DomainMatchType::Plain, "goog_e", "www.google.com", false),
        (DomainMatchType::Plain, "100%", "www.google.com", false),
        // Regex: case-sensitive engine, invalid patterns never match
        (DomainMatchType::Regex, "^[a-z]+\\.", "www.example.com", true),
        (DomainMatchType::Regex, "[A-Z]+", "www.example.com", false),
        (DomainMatchType::Regex, "(invalid", "anything.com", false),
        // non-ASCII Domain rules never match: this side skips them at
        // build time (ASCII-only trie); the SQL side has no guard, but
        // punycoded queries can never equal non-ASCII rule text
        (DomainMatchType::Domain, "例子.com", "www.xn--fsqu00a.com", false),
    ]
}

#[test]
fn matcher_semantics_ground_truth() {
    for (match_type, value, query, expected) in golden_semantics_cases() {
        let runtime = DomainMatcher::new(vec![domain_rule(match_type.clone(), value)]);
        let domain = norm(query);
        assert_eq!(
            runtime.is_match_normalized(&domain),
            expected,
            "rule {value:?} ({match_type:?}) vs query {query:?}"
        );
    }
}

#[test]
fn non_ascii_domain_rules_are_skipped_without_breaking_ascii_ones() {
    let matcher = DomainMatcher::new(vec![
        domain_rule(DomainMatchType::Domain, "例子.com"),
        domain_rule(DomainMatchType::Domain, "example.org"),
    ]);

    assert!(!matcher.is_match_normalized(&norm("xn--fsqu00a.com")));
    assert!(matcher.is_match_normalized(&norm("example.org")));
    assert!(matcher.is_match_normalized(&norm("www.example.org")));
    assert!(!matcher.is_match_normalized(&norm("example.com")));
}

#[test]
fn empty_and_single_label_domains_do_not_panic() {
    let matcher = DomainMatcher::new(vec![domain_rule(DomainMatchType::Domain, "example.org")]);

    assert!(!matcher.is_match_normalized(""));
    assert!(!matcher.is_match_normalized(&norm("localhost")));
    assert!(matcher.is_match_normalized(&norm("www.example.org")));
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
        !matcher.is_match_normalized(&norm("zab.com")),
        "Should not match zab.com as a subdomain of ab.com"
    );

    // ✅ 正确匹配：x.ab.com 是 ab.com 的子域
    assert!(
        matcher.is_match_normalized(&norm("x.ab.com")),
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
        matcher.is_match_normalized(&norm("example.com")),
        "Should match exact domain same as rule"
    );

    // ✅ 子域名应匹配
    assert!(
        matcher.is_match_normalized(&norm("www.example.com")),
        "Should match subdomain of example.com"
    );

    // ❌ 错误匹配（子串但非子域）
    assert!(
        !matcher.is_match_normalized(&norm("badexample.com")),
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
        matcher.is_match_normalized(&norm("test.aaa.bbb.com")),
        "Should match subdomain of aaa.bbb.com"
    );

    // 反例：确保 example.bbb.com 只匹配 bbb.com，不误匹配 aaa.bbb.com
    assert!(matcher.is_match_normalized(&norm("example.bbb.com")), "Should match bbb.com");

    // 反例：example.ccc.com 不应匹配任何
    assert!(!matcher.is_match_normalized(&norm("example.ccc.com")), "Should not match ccc.com");
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
        matcher.is_match_normalized(&norm("news.google.com")),
        "Should match subdomain of google.com"
    );

    // ❌ 反向用例：不应该匹配
    assert!(
        !matcher.is_match_normalized(&norm("example.com")),
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

    assert!(matcher.is_match_normalized(&norm("example.com")));
    assert!(matcher.is_match_normalized(&norm("EXAMPLE.COM")));
    assert!(matcher.is_match_normalized(&norm("example.com.")));
}

#[test]
fn domain_match_is_case_insensitive_for_root_and_subdomain() {
    let configs = vec![DomainConfig {
        match_type: DomainMatchType::Domain,
        value: "Example.COM".to_string(),
    }];

    let matcher = DomainMatcher::new(configs);

    assert!(matcher.is_match_normalized(&norm("example.com")));
    assert!(matcher.is_match_normalized(&norm("WWW.EXAMPLE.COM")));
}

// ---------------------------------------------------------------------------
// SiteMatcherRegistry
// ---------------------------------------------------------------------------

fn geo_value(value: &str, attributes: &[&str]) -> GeoSiteFileConfig {
    GeoSiteFileConfig {
        match_type: DomainMatchType::Full,
        value: value.to_string(),
        attributes: attributes.iter().map(|attribute| (*attribute).to_string()).collect(),
    }
}

fn keyed(name: &str, attribute_key: Option<&str>) -> GeoConfigKey {
    GeoConfigKey {
        name: "geosite".to_string(),
        key: name.to_string(),
        inverse: false,
        attribute_key: attribute_key.map(str::to_string),
    }
}

fn geo_key(attribute_key: Option<&str>) -> GeoConfigKey {
    keyed("TEST", attribute_key)
}

async fn write_entry(
    repo: &SiteCacheRepository,
    geo_key: &str,
    content_hash: &str,
    values: Vec<GeoSiteFileConfig>,
) {
    let rules = values
        .into_iter()
        .map(|value| SiteRuleRow::new(value.match_type, value.value, value.attributes))
        .collect();
    repo.replace_by_name("geosite", geo_key, content_hash, rules).await.unwrap();
}

fn source_key(key: &str) -> GeoFileCacheKey {
    GeoFileCacheKey { name: "geosite".to_string(), key: key.to_string() }
}

fn changed_test_key() -> HashSet<GeoFileCacheKey> {
    HashSet::from([source_key("TEST")])
}

#[tokio::test]
async fn get_or_build_shares_matchers_by_name_key_and_attribute() {
    let repo = repo().await;
    write_entry(
        &repo,
        "TEST",
        "hash-1",
        vec![geo_value("all.example", &[]), geo_value("tagged.example", &["tagged"])],
    )
    .await;
    let registry = SiteMatcherRegistry::new(repo);

    let first = registry.get_or_build(&geo_key(None)).await.unwrap();
    let same = registry.get_or_build(&geo_key(None)).await.unwrap();
    let tagged = registry.get_or_build(&geo_key(Some("tagged"))).await.unwrap();

    assert!(Arc::ptr_eq(&first, &same));
    assert!(!Arc::ptr_eq(&first, &tagged));
    assert_eq!(registry.materialized_len().await, 2);
    assert!(first.is_match_normalized(&norm("all.example")));
    assert!(!tagged.is_match_normalized(&norm("all.example")));
    assert!(tagged.is_match_normalized(&norm("tagged.example")));
}

#[tokio::test]
async fn reconcile_rebuilds_all_attribute_variants() {
    let repo = repo().await;
    write_entry(
        &repo,
        "TEST",
        "hash-1",
        vec![geo_value("all.example", &[]), geo_value("tagged.example", &["tagged"])],
    )
    .await;
    let registry = SiteMatcherRegistry::new(repo.clone());
    // hold both Arcs: referenced entries survive the GC segment
    let first = registry.get_or_build(&geo_key(None)).await.unwrap();
    let tagged = registry.get_or_build(&geo_key(Some("tagged"))).await.unwrap();

    write_entry(&repo, "TEST", "hash-2", vec![geo_value("renamed.example", &[])]).await;
    let drift = registry.reconcile().await;
    // both definite outcomes (fresh swap + absent removal) report the key
    assert_eq!(drift, changed_test_key());

    let rebuilt = registry.get_or_build(&geo_key(None)).await.unwrap();
    assert!(!Arc::ptr_eq(&first, &rebuilt));
    assert!(rebuilt.is_match_normalized(&norm("renamed.example")));
    assert!(!rebuilt.is_match_normalized(&norm("all.example")));

    // the tagged variant became empty after the rewrite: removed instead of
    // kept stale, and not re-materialized until requested again
    assert!(registry.get_or_build(&geo_key(Some("tagged"))).await.is_none());
    assert!(tagged.is_match_normalized(&norm("tagged.example")));
    assert_eq!(registry.materialized_len().await, 1);
}

#[tokio::test]
async fn missing_and_empty_keys_yield_none_without_caching() {
    let repo = repo().await;
    write_entry(&repo, "EMPTY", "hash-1", vec![]).await;
    let registry = SiteMatcherRegistry::new(repo.clone());

    assert!(registry.get_or_build(&keyed("MISSING", None)).await.is_none());
    assert!(registry.get_or_build(&keyed("EMPTY", None)).await.is_none());
    // neither missing nor empty keys are cached, so a later update that
    // populates the key is picked up by the next build
    assert_eq!(registry.materialized_len().await, 0);

    write_entry(&repo, "MISSING", "hash-1", vec![geo_value("late.example", &[])]).await;
    let late = registry.get_or_build(&keyed("MISSING", None)).await.unwrap();
    assert!(late.is_match_normalized(&norm("late.example")));
}

#[tokio::test]
async fn unreadable_repo_yields_none() {
    let pool = GeoCacheDatabase::site_mem().await;
    let repo = SiteCacheRepository::new(pool.clone());
    write_entry(&repo, "TEST", "hash-1", vec![geo_value("all.example", &[])]).await;
    let registry = SiteMatcherRegistry::new(repo);

    pool.close().await;

    assert!(registry.get_or_build(&geo_key(None)).await.is_none());
}

#[tokio::test]
async fn failed_reconcile_keeps_previous_matcher() {
    let pool = GeoCacheDatabase::site_mem().await;
    let repo = SiteCacheRepository::new(pool.clone());
    write_entry(&repo, "TEST", "hash-1", vec![geo_value("all.example", &[])]).await;
    let registry = SiteMatcherRegistry::new(repo);
    let first = registry.get_or_build(&geo_key(None)).await.unwrap();

    // environmental read failure after a (hypothetical) data change
    pool.close().await;
    let drift = registry.reconcile().await;

    // the previous matcher keeps serving; the next reconcile re-examines
    assert!(drift.is_empty());
    let kept = registry.get_or_build(&geo_key(None)).await.unwrap();
    assert!(Arc::ptr_eq(&first, &kept));
    assert!(kept.is_match_normalized(&norm("all.example")));
    assert_eq!(registry.materialized_len().await, 1);
}

#[tokio::test]
async fn reconcile_silently_gcs_unreferenced_matchers() {
    let repo = repo().await;
    write_entry(&repo, "TEST", "hash-1", vec![geo_value("all.example", &[])]).await;
    // zero grace: no young-orphan protection here (that branch is covered
    // by fresh_swap_survives_the_immediately_following_heartbeat)
    let registry = SiteMatcherRegistry::with_gc_grace(repo, Duration::ZERO);

    // drop the only consumer reference: the registry's Arc is the last one
    drop(registry.get_or_build(&geo_key(None)).await.unwrap());

    // unreferenced entries are collected without a change event — no
    // engine depends on them
    assert!(registry.reconcile().await.is_empty());
    assert_eq!(registry.materialized_len().await, 0);

    // a later build re-materializes the entry on demand
    let rebuilt = registry.get_or_build(&geo_key(None)).await.unwrap();
    assert!(rebuilt.is_match_normalized(&norm("all.example")));
    assert_eq!(registry.materialized_len().await, 1);
}

#[tokio::test]
async fn fresh_swap_survives_the_immediately_following_heartbeat() {
    let repo = repo().await;
    write_entry(&repo, "TEST", "hash-1", vec![geo_value("all.example", &[])]).await;
    let registry = SiteMatcherRegistry::new(repo.clone());
    let first = registry.get_or_build(&geo_key(None)).await.unwrap();

    // a notify swaps in a new matcher; its consumer hasn't taken the Arc
    // yet (the event is still in flight)
    write_entry(&repo, "TEST", "hash-2", vec![geo_value("renamed.example", &[])]).await;
    let resolved = registry.reconcile_sources(&changed_test_key()).await;
    assert_eq!(resolved, changed_test_key());

    // the heartbeat right after must not collect the fresh swap
    assert!(registry.reconcile().await.is_empty());
    assert_eq!(registry.materialized_len().await, 1);

    // the consumer's pickup finds the ready matcher — no recompile
    let picked = registry.get_or_build(&geo_key(None)).await.unwrap();
    assert!(!Arc::ptr_eq(&first, &picked));
    assert!(picked.is_match_normalized(&norm("renamed.example")));
    assert!(!picked.is_match_normalized(&norm("all.example")));
}

#[tokio::test]
async fn reconcile_keeps_referenced_matchers_and_reports_drift() {
    let repo = repo().await;
    write_entry(&repo, "TEST", "hash-1", vec![geo_value("all.example", &[])]).await;
    let registry = SiteMatcherRegistry::new(repo.clone());
    let held = registry.get_or_build(&geo_key(None)).await.unwrap();

    // external rewrite, e.g. a change whose event was missed
    write_entry(&repo, "TEST", "hash-2", vec![geo_value("renamed.example", &[])]).await;
    let drift = registry.reconcile().await;

    // the held Arc survives the GC segment; the hash probe reports the drift
    assert_eq!(drift, changed_test_key());
    let rebuilt = registry.get_or_build(&geo_key(None)).await.unwrap();
    assert!(!Arc::ptr_eq(&held, &rebuilt));
    assert!(rebuilt.is_match_normalized(&norm("renamed.example")));
    // the old generation keeps serving its holder (snapshot semantics)
    assert!(held.is_match_normalized(&norm("all.example")));
    assert_eq!(registry.materialized_len().await, 1);
}

#[tokio::test]
async fn reconcile_without_changes_is_idempotent() {
    let repo = repo().await;
    write_entry(
        &repo,
        "TEST",
        "hash-1",
        vec![geo_value("all.example", &[]), geo_value("tagged.example", &["tagged"])],
    )
    .await;
    let registry = SiteMatcherRegistry::new(repo);
    let first = registry.get_or_build(&geo_key(None)).await.unwrap();
    let tagged = registry.get_or_build(&geo_key(Some("tagged"))).await.unwrap();

    // a pass over unchanged data: no GC, no rebuild, no event
    assert!(registry.reconcile().await.is_empty());

    let again = registry.get_or_build(&geo_key(None)).await.unwrap();
    assert!(Arc::ptr_eq(&first, &again));
    let tagged_again = registry.get_or_build(&geo_key(Some("tagged"))).await.unwrap();
    assert!(Arc::ptr_eq(&tagged, &tagged_again));
    assert_eq!(registry.materialized_len().await, 2);
}

#[tokio::test]
async fn scoped_reconcile_only_touches_target_sources() {
    let repo = repo().await;
    write_entry(&repo, "A", "hash-a1", vec![geo_value("a.example", &[])]).await;
    write_entry(&repo, "B", "hash-b1", vec![geo_value("b.example", &[])]).await;
    let registry = SiteMatcherRegistry::new(repo.clone());
    let a = registry.get_or_build(&keyed("A", None)).await.unwrap();
    let b = registry.get_or_build(&keyed("B", None)).await.unwrap();

    // both sources drift, but only A's change is announced
    write_entry(&repo, "A", "hash-a2", vec![geo_value("renamed-a.example", &[])]).await;
    write_entry(&repo, "B", "hash-b2", vec![geo_value("renamed-b.example", &[])]).await;
    let reported = registry.reconcile_sources(&HashSet::from([source_key("A")])).await;
    assert_eq!(reported, HashSet::from([source_key("A")]));

    // A rebuilt, B untouched by the scoped pass
    let rebuilt_a = registry.get_or_build(&keyed("A", None)).await.unwrap();
    assert!(!Arc::ptr_eq(&a, &rebuilt_a));
    assert!(rebuilt_a.is_match_normalized(&norm("renamed-a.example")));
    let kept_b = registry.get_or_build(&keyed("B", None)).await.unwrap();
    assert!(Arc::ptr_eq(&b, &kept_b));
    assert!(!kept_b.is_match_normalized(&norm("renamed-b.example")));

    // the full heartbeat still catches B's drift
    let drift = registry.reconcile().await;
    assert_eq!(drift, HashSet::from([source_key("B")]));
    let rebuilt_b = registry.get_or_build(&keyed("B", None)).await.unwrap();
    assert!(rebuilt_b.is_match_normalized(&norm("renamed-b.example")));
}
