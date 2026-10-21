use std::{collections::HashMap, net::IpAddr};

use landscape_core::geo_cache::{GeoCacheDatabase, IpCacheRepository};
use landscape_protobuf::{IpSnapshotReader, IpSnapshotWriter};
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use landscape_common::flow::{ip_mark::IpConfig, mark::FlowMark, runtime::IpMarkInfo};

use super::finalize_runtime_rules;
use super::snapshot_pipeline::stream_snapshot_cache_events;

#[tokio::test]
async fn snapshot_events_stream_into_ip_cache() {
    let dir = tempdir().unwrap();
    let snapshot_path = dir.path().join("ip.snap");
    let mut writer = IpSnapshotWriter::create(&snapshot_path, Uuid::new_v4()).unwrap();
    writer.start_key("cn").unwrap();
    writer.write_cidr("10.1.2.3".parse().unwrap(), 8).unwrap();
    writer.write_cidr("2001:db8::1".parse().unwrap(), 32).unwrap();
    writer.end_key().unwrap();
    writer.start_key("EMPTY").unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let reader = IpSnapshotReader::open(&snapshot_path).unwrap();
    let changed: HashMap<String, String> = reader.index().content_hashes_hex();
    let repo = IpCacheRepository::new(GeoCacheDatabase::ip_mem().await);
    let (tx, rx) = mpsc::channel(4);
    let producer = tokio::task::spawn_blocking(move || {
        stream_snapshot_cache_events(reader, changed, tx, CancellationToken::new())
    });

    let outcomes = repo.replace_stream("geoip", rx).await.unwrap();
    producer.await.unwrap().unwrap();

    assert_eq!(outcomes.len(), 2);
    let entry = repo.load_entry("geoip", "CN").await.unwrap().unwrap();
    assert_eq!(entry.values.len(), 2);
    assert_eq!(entry.values[0].ip, "10.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(entry.values[0].prefix, 8);
    assert_eq!(entry.values[1].prefix, 32);
    assert!(repo.load_entry("geoip", "EMPTY").await.unwrap().unwrap().values.is_empty());
}

#[test]
fn runtime_dedup_keeps_lowest_priority_number() {
    let cidr = IpConfig { ip: "10.0.0.0".parse().unwrap(), prefix: 8 };
    let rules = vec![
        IpMarkInfo {
            mark: FlowMark::default(),
            cidr: cidr.clone(),
            priority: 20,
        },
        IpMarkInfo {
            mark: FlowMark::default(),
            cidr: cidr.clone(),
            priority: 5,
        },
        IpMarkInfo {
            mark: FlowMark::default(),
            cidr: IpConfig { ip: "2001:db8::".parse().unwrap(), prefix: 32 },
            priority: 10,
        },
    ];

    let rules = finalize_runtime_rules(rules);
    assert_eq!(rules.len(), 2);
    let ipv4 = rules.iter().find(|rule| rule.cidr == cidr).unwrap();
    assert_eq!(ipv4.priority, 5);
}
