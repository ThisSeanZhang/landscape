use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

use landscape_common::dns::rule::DomainMatchType;
use tempfile::tempdir;
use uuid::Uuid;

use super::{
    GeoSnapshotError, GeoSnapshotReader, GeoSnapshotRule, GeoSnapshotSourceKind, GeoSnapshotWriter,
    IpSnapshotCidr, IpSnapshotPreparedCidr, IpSnapshotReader, IpSnapshotWriter, SiteSnapshotReader,
    SiteSnapshotWriter,
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

#[test]
fn site_snapshot_prepares_cache_rows() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("site-prepared.snap");
    let mut writer = SiteSnapshotWriter::create(&path, Uuid::new_v4()).unwrap();
    writer.start_key("cn").unwrap();
    writer.write_rule_iter(DomainMatchType::Regex, "^[a-z]+$", ["z", "a", "a"]).unwrap();
    writer.write_rule_iter(DomainMatchType::Regex, "(invalid", []).unwrap();
    writer.write_rule_iter(DomainMatchType::Domain, "Example.COM.", []).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let reader = SiteSnapshotReader::open(&path).unwrap();
    assert_eq!(reader.metadata().format_version, super::FORMAT_VERSION);
    let mut key_reader = reader.open_key("CN").unwrap();

    let regex = key_reader.next_prepared().unwrap().unwrap();
    assert_eq!(regex.match_type, DomainMatchType::Regex);
    assert!(regex.pattern_valid);
    assert_eq!(regex.value, "^[a-z]+$");
    assert_eq!(regex.attributes_json.as_deref(), Some("[\"a\",\"z\"]"));

    let invalid = key_reader.next_prepared().unwrap().unwrap();
    assert_eq!(invalid.match_type, DomainMatchType::Regex);
    assert!(!invalid.pattern_valid);

    let domain = key_reader.next_prepared().unwrap().unwrap();
    assert_eq!(domain.match_type, DomainMatchType::Domain);
    assert!(domain.pattern_valid);
    assert_eq!(domain.value, "example.com");
    assert_eq!(domain.attributes_json, None);
    assert!(key_reader.next_prepared().unwrap().is_none());
}

#[test]
fn ip_snapshot_prepares_masked_rows() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ip-prepared.snap");
    let mut writer = IpSnapshotWriter::create(&path, Uuid::new_v4()).unwrap();
    writer.start_key("cn").unwrap();
    writer.write_cidr("10.1.2.3".parse().unwrap(), 8).unwrap();
    writer.write_cidr("2001:db8::1".parse().unwrap(), 32).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let reader = IpSnapshotReader::open(&path).unwrap();
    assert_eq!(reader.metadata().format_version, super::FORMAT_VERSION);
    let mut key_reader = reader.open_key("CN").unwrap();

    let v4 = key_reader.next_prepared().unwrap().unwrap();
    assert_eq!((v4.family, v4.prefix_len), (4, 8));
    assert_eq!(&v4.network[..4], &[10, 0, 0, 0]);

    let v6 = key_reader.next_prepared().unwrap().unwrap();
    assert_eq!((v6.family, v6.prefix_len), (6, 32));
    assert_eq!(&v6.network[..4], &[0x20, 0x01, 0x0d, 0xb8]);
    assert!(key_reader.next_prepared().unwrap().is_none());
}

#[test]
fn prepared_cidr_clamps_prefix_to_family_maximum() {
    let v4 = IpSnapshotPreparedCidr::from_ip("10.1.2.3".parse().unwrap(), 40);
    assert_eq!((v4.family, v4.prefix_len), (4, 32));
    assert_eq!(&v4.network[..4], &[10, 1, 2, 3]);

    let v6 = IpSnapshotPreparedCidr::from_ip("2001:db8::1".parse().unwrap(), 200);
    assert_eq!((v6.family, v6.prefix_len), (6, 128));
}

#[test]
fn v2_ip_snapshot_rejects_unmasked_network() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ip-unmasked.snap");
    let mut writer =
        GeoSnapshotWriter::create(&path, GeoSnapshotSourceKind::Ip, Uuid::new_v4()).unwrap();
    writer.start_key("cn").unwrap();
    let mut item = vec![4, 8];
    item.extend_from_slice(&[10, 1, 2, 3]);
    writer.write_item(&item).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();

    let reader = IpSnapshotReader::open(&path).unwrap();
    let mut key_reader = reader.open_key("CN").unwrap();
    assert!(matches!(key_reader.next_prepared(), Err(GeoSnapshotError::InvalidPayload(_))));
}

fn downgrade_to_v1(path: &std::path::Path) {
    let mut bytes = fs::read(path).unwrap();
    assert_eq!(&bytes[8..10], &super::FORMAT_VERSION.to_le_bytes());
    bytes[8..10].copy_from_slice(&super::FORMAT_VERSION_V1.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn push_v1_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn v1_site_item(match_type: u8, value: &str, attrs: &[&str]) -> Vec<u8> {
    let mut item = vec![match_type];
    push_v1_u32(&mut item, value.len() as u32);
    item.extend_from_slice(value.as_bytes());
    push_v1_u32(&mut item, attrs.len() as u32);
    for attribute in attrs {
        push_v1_u32(&mut item, attribute.len() as u32);
        item.extend_from_slice(attribute.as_bytes());
    }
    item
}

#[test]
fn v1_site_snapshot_still_reads_as_prepared() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("site-v1.snap");
    let mut writer =
        GeoSnapshotWriter::create(&path, GeoSnapshotSourceKind::Site, Uuid::new_v4()).unwrap();
    writer.start_key("cn").unwrap();
    writer.write_item(&v1_site_item(1, "(invalid", &["z", "a"])).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();
    downgrade_to_v1(&path);

    let reader = SiteSnapshotReader::open(&path).unwrap();
    assert_eq!(reader.metadata().format_version, super::FORMAT_VERSION_V1);
    let prepared = reader.open_key("CN").unwrap().next_prepared().unwrap().unwrap();
    assert_eq!(prepared.match_type, DomainMatchType::Regex);
    assert!(!prepared.pattern_valid);
    assert_eq!(prepared.value, "(invalid");
    assert_eq!(prepared.attributes_json.as_deref(), Some("[\"a\",\"z\"]"));
}

#[test]
fn v1_ip_snapshot_still_reads_as_prepared() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ip-v1.snap");
    let mut writer =
        GeoSnapshotWriter::create(&path, GeoSnapshotSourceKind::Ip, Uuid::new_v4()).unwrap();
    writer.start_key("cn").unwrap();
    let mut item = vec![4];
    item.extend_from_slice(&[10, 1, 2, 3]);
    push_v1_u32(&mut item, 8);
    writer.write_item(&item).unwrap();
    writer.end_key().unwrap();
    writer.finish().unwrap();
    downgrade_to_v1(&path);

    let reader = IpSnapshotReader::open(&path).unwrap();
    assert_eq!(reader.metadata().format_version, super::FORMAT_VERSION_V1);
    let prepared = reader.open_key("CN").unwrap().next_prepared().unwrap().unwrap();
    assert_eq!((prepared.family, prepared.prefix_len), (4, 8));
    assert_eq!(&prepared.network[..4], &[10, 0, 0, 0]);
}
