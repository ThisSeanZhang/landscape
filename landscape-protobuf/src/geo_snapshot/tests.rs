use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

use landscape_common::dns::rule::DomainMatchType;
use tempfile::tempdir;
use uuid::Uuid;

use super::{
    GeoSnapshotError, GeoSnapshotReader, GeoSnapshotRule, GeoSnapshotSourceKind, IpSnapshotCidr,
    IpSnapshotReader, IpSnapshotWriter, SiteSnapshotReader, SiteSnapshotWriter,
};

fn create_writer(path: &std::path::Path) -> SiteSnapshotWriter {
    SiteSnapshotWriter::create(path, Uuid::new_v4()).unwrap()
}

fn read_site_key(
    reader: &SiteSnapshotReader,
    key: &str,
) -> Result<Vec<GeoSnapshotRule>, GeoSnapshotError> {
    let mut key_reader = reader.open_key(key)?;
    let mut rules = Vec::new();
    while let Some(rule) = key_reader.next_rule()? {
        rules.push(rule);
    }
    Ok(rules)
}

#[test]
fn snapshot_roundtrip_preserves_rules_and_metadata() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("site-test.snap");
    let source_id = Uuid::new_v4();

    let mut writer = SiteSnapshotWriter::create(&path, source_id).unwrap();
    writer.start_key("cn").unwrap();
    writer.write_rule_iter(DomainMatchType::Domain, "Example.COM.", ["z", "a", "a"]).unwrap();
    writer.write_rule_iter(DomainMatchType::Full, "WWW.Example.com", []).unwrap();
    writer.end_key().unwrap();
    writer.start_key("ads").unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let reader = SiteSnapshotReader::open(&path).unwrap();
    assert_eq!(reader.metadata().source_kind, GeoSnapshotSourceKind::Site);
    assert_eq!(reader.metadata().source_id, source_id);
    assert_eq!(reader.index().len(), 2);
    assert_eq!(
        reader.index().iter().map(|entry| entry.key.as_str()).collect::<Vec<_>>(),
        vec!["ADS", "CN"]
    );

    assert_eq!(
        read_site_key(&reader, "CN").unwrap(),
        vec![
            GeoSnapshotRule {
                match_type: DomainMatchType::Domain,
                value: "example.com".to_string(),
                attributes: vec!["a".to_string(), "z".to_string()],
            },
            GeoSnapshotRule {
                match_type: DomainMatchType::Full,
                value: "www.example.com".to_string(),
                attributes: Vec::new(),
            },
        ]
    );
    assert!(read_site_key(&reader, "ADS").unwrap().is_empty());
}

#[test]
fn empty_snapshot_is_valid() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("empty.snap");
    create_writer(&path).finish().unwrap();
    let reader = SiteSnapshotReader::open(&path).unwrap();
    assert!(reader.index().is_empty());
}

#[test]
fn identical_rules_produce_identical_hashes() {
    let dir = tempdir().unwrap();
    let first_path = dir.path().join("first.snap");
    let second_path = dir.path().join("second.snap");

    let mut first = create_writer(&first_path);
    first.start_key("CN").unwrap();
    first.write_rule_iter(DomainMatchType::Domain, "Example.com", ["b", "a"]).unwrap();
    first.end_key().unwrap();
    first.finish().unwrap();

    let mut second = create_writer(&second_path);
    second.start_key("cn").unwrap();
    second.write_rule_iter(DomainMatchType::Domain, "example.com.", ["a", "b", "a"]).unwrap();
    second.end_key().unwrap();
    second.finish().unwrap();

    let first_reader = SiteSnapshotReader::open(&first_path).unwrap();
    let second_reader = SiteSnapshotReader::open(&second_path).unwrap();
    assert_eq!(
        first_reader.index().get("CN").unwrap().hash,
        second_reader.index().get("CN").unwrap().hash
    );
}

#[test]
fn duplicate_keys_use_last_payload() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("site-test.snap");
    let mut writer = create_writer(&path);
    writer.start_key("CN").unwrap();
    writer.write_rule_iter(DomainMatchType::Domain, "first.example", []).unwrap();
    writer.end_key().unwrap();
    writer.start_key("cn").unwrap();
    writer.write_rule_iter(DomainMatchType::Domain, "second.example", []).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let reader = SiteSnapshotReader::open(&path).unwrap();
    let rules = read_site_key(&reader, "CN").unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].value, "second.example");
}

#[test]
fn dropping_writer_keeps_previous_snapshot() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("site-test.snap");
    let mut writer = create_writer(&path);
    writer.start_key("CN").unwrap();
    writer.write_rule_iter(DomainMatchType::Domain, "old.example", []).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();
    let old_bytes = fs::read(&path).unwrap();

    {
        let mut pending = create_writer(&path);
        pending.start_key("CN").unwrap();
        pending.write_rule_iter(DomainMatchType::Domain, "new.example", []).unwrap();
    }

    assert_eq!(fs::read(&path).unwrap(), old_bytes);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn payload_corruption_is_detected_by_hash() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("site-test.snap");
    let mut writer = create_writer(&path);
    writer.start_key("CN").unwrap();
    writer.write_rule_iter(DomainMatchType::Domain, "example.com", []).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let reader = SiteSnapshotReader::open(&path).unwrap();
    let entry = reader.index().get("CN").unwrap().clone();
    drop(reader);

    let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(entry.payload_offset)).unwrap();
    file.write_all(&[3]).unwrap();
    drop(file);

    let reader = SiteSnapshotReader::open(&path).unwrap();
    let mut key_reader = reader.open_key("CN").unwrap();
    let mut result = Ok(());
    loop {
        match key_reader.next_rule() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }
    assert!(matches!(result, Err(GeoSnapshotError::KeyHashMismatch)));
}

#[test]
fn truncated_snapshot_is_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("site-test.snap");
    let truncated_path = dir.path().join("truncated.snap");
    let mut writer = create_writer(&path);
    writer.start_key("CN").unwrap();
    writer.write_rule_iter(DomainMatchType::Domain, "example.com", []).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let bytes = fs::read(&path).unwrap();
    fs::write(&truncated_path, &bytes[..bytes.len() - 8]).unwrap();
    assert!(SiteSnapshotReader::open(&truncated_path).is_err());
}

#[test]
fn index_checksum_mismatch_is_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("site-test.snap");
    let mut writer = create_writer(&path);
    writer.start_key("CN").unwrap();
    writer.write_rule_iter(DomainMatchType::Domain, "example.com", []).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let mut bytes = fs::read(&path).unwrap();
    let trailer_start = bytes.len() - 64;
    let index_offset =
        u64::from_le_bytes(bytes[trailer_start..trailer_start + 8].try_into().unwrap()) as usize;
    bytes[index_offset + 8] ^= 0xFF;
    fs::write(&path, bytes).unwrap();

    assert!(matches!(
        SiteSnapshotReader::open(&path),
        Err(GeoSnapshotError::IndexChecksumMismatch)
    ));
}

#[test]
fn generic_payload_roundtrip_and_item_count_validation() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("generic.snap");
    let source_id = Uuid::new_v4();
    let mut writer =
        super::GeoSnapshotWriter::create(&path, GeoSnapshotSourceKind::Ip, source_id).unwrap();
    writer.start_key("CN").unwrap();
    writer.write_item(b"first").unwrap();
    writer.write_item(b"second").unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let reader = GeoSnapshotReader::open(&path).unwrap();
    assert_eq!(reader.metadata().source_kind, GeoSnapshotSourceKind::Ip);
    assert_eq!(reader.index().get("CN").unwrap().item_count, 2);
    let mut payload = reader.open_key("CN").unwrap();
    let mut bytes = Vec::new();
    payload.read_to_end(&mut bytes).unwrap();
    payload.record_item();
    payload.record_item();
    payload.finish().unwrap();
    assert_eq!(bytes, b"firstsecond");

    assert!(matches!(
        SiteSnapshotReader::open(&path),
        Err(GeoSnapshotError::UnsupportedSourceKind(2))
    ));
}

#[test]
fn ip_snapshot_roundtrip_normalizes_networks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ip.snap");
    let source_id = Uuid::new_v4();

    let mut writer = IpSnapshotWriter::create(&path, source_id).unwrap();
    writer.start_key("cn").unwrap();
    writer.write_cidr("10.1.2.3".parse().unwrap(), 8).unwrap();
    writer.write_cidr("2001:db8::1".parse().unwrap(), 32).unwrap();
    writer.end_key().unwrap();
    writer.start_key("EMPTY").unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let reader = IpSnapshotReader::open(&path).unwrap();
    assert_eq!(reader.index().len(), 2);
    assert_eq!(reader.index().get("CN").unwrap().item_count, 2);

    let mut key_reader = reader.open_key("CN").unwrap();
    assert_eq!(
        key_reader.next_cidr().unwrap(),
        Some(IpSnapshotCidr { ip: "10.0.0.0".parse().unwrap(), prefix: 8 })
    );
    assert_eq!(
        key_reader.next_cidr().unwrap(),
        Some(IpSnapshotCidr { ip: "2001:db8::".parse().unwrap(), prefix: 32 })
    );
    assert!(key_reader.next_cidr().unwrap().is_none());
    assert!(reader.open_key("EMPTY").unwrap().next_cidr().unwrap().is_none());
}

#[test]
fn ip_snapshot_rejects_invalid_prefix() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ip.snap");
    let mut writer = IpSnapshotWriter::create(&path, Uuid::new_v4()).unwrap();
    writer.start_key("CN").unwrap();
    assert!(matches!(
        writer.write_cidr("10.0.0.0".parse().unwrap(), 33),
        Err(GeoSnapshotError::InvalidPayload(_))
    ));
}
