use std::collections::HashSet;

use landscape_common::dns::rule::DomainMatchType;
use landscape_core::geo_cache::{GeoCacheDatabase, SiteCacheRepository, SiteRuleRow};
use landscape_protobuf::{SiteSnapshotReader, SiteSnapshotWriter};
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::super::site_values::normalize_site_rule_value;
use super::snapshot_pipeline::stream_snapshot_cache_events;

#[tokio::test]
async fn sql_semantics_ground_truth() {
    // Golden semantics table shared with the DomainMatcher ground truth
    // (landscape-core/src/geo_cache/tests.rs) — keep both copies in sync.
    // Non-ASCII Domain rules never match on this side without an
    // explicit guard: queries arrive punycoded ASCII, so suffix
    // candidates can never equal non-ASCII rule text.
    let cases: Vec<(DomainMatchType, &'static str, &'static str, bool)> = vec![
        (DomainMatchType::Domain, "example.com", "example.com", true),
        (DomainMatchType::Domain, "example.com", "www.example.com", true),
        (DomainMatchType::Domain, "ogle.com", "www.google.com", false),
        (DomainMatchType::Domain, "Example.COM.", "www.example.com", true),
        (DomainMatchType::Full, "sub.example.com", "sub.example.com", true),
        (DomainMatchType::Full, "example.com", "www.example.com", false),
        (DomainMatchType::Full, "Sub.Example.COM.", "sub.example.com", true),
        (DomainMatchType::Plain, "cloud", "www.cloudflare.com", true),
        (DomainMatchType::Plain, "Foo.", "www.foo.com", true),
        (DomainMatchType::Plain, "cloud", "example.com", false),
        (DomainMatchType::Plain, "goog_e", "www.google.com", false),
        (DomainMatchType::Plain, "100%", "www.google.com", false),
        (DomainMatchType::Regex, "^[a-z]+\\.", "www.example.com", true),
        (DomainMatchType::Regex, "[A-Z]+", "www.example.com", false),
        (DomainMatchType::Regex, "(invalid", "anything.com", false),
        (DomainMatchType::Domain, "例子.com", "www.xn--fsqu00a.com", false),
    ];

    let dir = tempfile::tempdir().unwrap();
    let repo = SiteCacheRepository::new(GeoCacheDatabase::open_site(dir.path()).await.unwrap());

    // one key per case (rule-per-key mirrors the matcher side's
    // rule-per-matcher), written through the production path: storage
    // normalization + write-time pattern validation
    for (index, (match_type, value, _query, _expected)) in cases.iter().enumerate() {
        let row = SiteRuleRow::new(
            match_type.clone(),
            normalize_site_rule_value(match_type, value.to_string()),
            HashSet::new(),
        );
        repo.replace_by_name("geosite", &format!("R{index}"), "hash", vec![row]).await.unwrap();
    }

    for (index, (match_type, value, query, expected)) in cases.iter().enumerate() {
        let hits = repo.lookup_rules_by_domain(query).await.unwrap();
        let hit = hits.iter().find(|hit| hit.key.key == format!("R{index}"));
        assert_eq!(hit.is_some(), *expected, "rule {value:?} ({match_type:?}) vs query {query:?}");
        if *expected {
            let hit = hit.expect("checked above");
            assert_eq!(hit.match_type, *match_type);
            assert_eq!(hit.domain, normalize_site_rule_value(match_type, value.to_string()));
        }
    }

    // a multi-rule key pins grouping and within-key seq order
    repo.replace_by_name(
        "geosite",
        "PRIVATE",
        "hash",
        vec![
            SiteRuleRow::new(DomainMatchType::Domain, "lan".into(), HashSet::new()),
            SiteRuleRow::new(DomainMatchType::Full, "router.lan".into(), HashSet::new()),
        ],
    )
    .await
    .unwrap();

    let hits = repo.lookup_rules_by_domain("router.lan").await.unwrap();
    let private: Vec<&str> =
        hits.iter().filter(|hit| hit.key.key == "PRIVATE").map(|hit| hit.domain.as_str()).collect();
    assert_eq!(private, vec!["lan", "router.lan"]);
    let myhost = repo.lookup_rules_by_domain("myhost.lan").await.unwrap();
    assert!(myhost.iter().any(|hit| hit.key.key == "PRIVATE" && hit.domain == "lan"));
}
#[tokio::test]
async fn snapshot_stream_rebuilds_cache_without_loading_all_rules() {
    let dir = tempdir().unwrap();
    let snapshot_path = dir.path().join("site.snap");
    let mut writer = SiteSnapshotWriter::create(&snapshot_path, Uuid::new_v4()).unwrap();
    writer.start_key("CN").unwrap();
    writer.write_rule_iter(DomainMatchType::Domain, "Example.COM.", ["cn", "ads"]).unwrap();
    writer.write_rule_iter(DomainMatchType::Full, "www.example.com", []).unwrap();
    writer.end_key().unwrap();
    writer.start_key("EMPTY").unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let repo = SiteCacheRepository::new(GeoCacheDatabase::site_mem().await);
    let reader = SiteSnapshotReader::open(&snapshot_path).unwrap();
    let changed = reader.index().content_hashes_hex();
    let (tx, rx) = mpsc::channel(8);
    let producer = tokio::task::spawn_blocking(move || {
        stream_snapshot_cache_events(reader, changed, tx, CancellationToken::new())
    });
    let outcomes = repo.replace_stream("geosite", rx).await.unwrap();
    producer.await.unwrap().unwrap();
    assert_eq!(outcomes.len(), 2);

    let entry = repo.load_entry("geosite", "CN").await.unwrap().unwrap();
    assert_eq!(
        entry.values.iter().map(|value| value.value.as_str()).collect::<Vec<_>>(),
        vec!["example.com", "www.example.com"]
    );
    assert_eq!(entry.values[0].attributes, HashSet::from(["ads".to_string(), "cn".to_string()]));
    assert!(repo.load_entry("geosite", "EMPTY").await.unwrap().unwrap().values.is_empty());
    assert_eq!(
        repo.entry_hashes_for_name("geosite").await.unwrap(),
        SiteSnapshotReader::open(&snapshot_path).unwrap().index().content_hashes_hex()
    );
}
