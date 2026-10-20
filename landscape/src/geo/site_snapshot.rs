use std::{
    fs::File,
    io::{BufReader, Cursor, Read},
    path::Path,
};

use landscape_common::config_service::geo::{GeoError, normalize_adguard_key};
use landscape_protobuf::{
    GeoSiteStream, GeoSiteStreamEvent, GeoSnapshotError, SiteSnapshotWriter,
    parse_adguard_negative_rules, stream_adguard_rules,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default)]
pub struct SiteSnapshotBuildSummary {
    pub entries: usize,
}

pub fn build_dat_snapshot_reader<R: Read>(
    reader: R,
    final_path: &Path,
    source_id: Uuid,
    cancel: &CancellationToken,
) -> Result<SiteSnapshotBuildSummary, GeoError> {
    let mut writer = SiteSnapshotWriter::create(final_path, source_id)
        .map_err(|error| snapshot_error("create site snapshot", error))?;
    let mut current_key = false;
    let mut entries = 0usize;

    for event in GeoSiteStream::new(reader) {
        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        match event? {
            GeoSiteStreamEvent::EntryStart { country_code } => {
                if current_key {
                    return Err(GeoError::SiteDatDecodeError);
                }
                writer
                    .start_key(&country_code)
                    .map_err(|error| snapshot_error("start snapshot key", error))?;
                current_key = true;
            }
            GeoSiteStreamEvent::Domain { match_type, value, attributes } => {
                if !current_key {
                    return Err(GeoError::SiteDatDecodeError);
                }
                writer
                    .write_rule_iter(match_type, &value, attributes.iter().map(String::as_str))
                    .map_err(|error| snapshot_error("write site snapshot rule", error))?;
            }
            GeoSiteStreamEvent::EntryEnd => {
                if !current_key {
                    return Err(GeoError::SiteDatDecodeError);
                }
                writer.end_key().map_err(|error| snapshot_error("finish snapshot key", error))?;
                current_key = false;
                entries += 1;
            }
        }
    }

    if current_key {
        return Err(GeoError::SiteDatDecodeError);
    }
    writer.finish().map_err(|error| snapshot_error("finish site snapshot", error))?;
    Ok(SiteSnapshotBuildSummary { entries })
}

pub fn build_dat_snapshot_bytes(
    bytes: &[u8],
    final_path: &Path,
    source_id: Uuid,
    cancel: &CancellationToken,
) -> Result<SiteSnapshotBuildSummary, GeoError> {
    build_dat_snapshot_reader(Cursor::new(bytes), final_path, source_id, cancel)
}

pub fn build_adguard_snapshot_file(
    source_path: &Path,
    final_path: &Path,
    source_id: Uuid,
    key: &str,
    cancel: &CancellationToken,
) -> Result<SiteSnapshotBuildSummary, GeoError> {
    let key = normalize_adguard_key(key);
    let negative_reader =
        BufReader::new(File::open(source_path).map_err(|error| {
            GeoError::RawDatReadFailed(format!("open AdGuard source: {error}"))
        })?);
    let negatives = parse_adguard_negative_rules(negative_reader, || cancel.is_cancelled())?;

    let reader =
        BufReader::new(File::open(source_path).map_err(|error| {
            GeoError::RawDatReadFailed(format!("open AdGuard source: {error}"))
        })?);
    let rules = stream_adguard_rules(reader, negatives, || cancel.is_cancelled());

    let mut writer = SiteSnapshotWriter::create(final_path, source_id)
        .map_err(|error| snapshot_error("create AdGuard snapshot", error))?;
    writer.start_key(&key).map_err(|error| snapshot_error("start AdGuard snapshot key", error))?;
    for rule in rules {
        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        let rule = rule?;
        writer
            .write_rule_iter(
                rule.match_type,
                &rule.value,
                rule.attributes.iter().map(String::as_str),
            )
            .map_err(|error| snapshot_error("write AdGuard snapshot rule", error))?;
    }
    writer.end_key().map_err(|error| snapshot_error("finish AdGuard snapshot key", error))?;
    writer.finish().map_err(|error| snapshot_error("finish AdGuard snapshot", error))?;
    Ok(SiteSnapshotBuildSummary { entries: 1 })
}

fn snapshot_error(context: &str, error: GeoSnapshotError) -> GeoError {
    GeoError::RawDatReadFailed(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use landscape_common::dns::rule::DomainMatchType;
    use landscape_protobuf::{GeoSnapshotRule, SiteSnapshotReader};
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::{build_adguard_snapshot_file, build_dat_snapshot_bytes};

    fn push_varint(output: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn push_len_field(output: &mut Vec<u8>, field: u8, bytes: &[u8]) {
        push_varint(output, u64::from(field << 3 | 2));
        push_varint(output, bytes.len() as u64);
        output.extend_from_slice(bytes);
    }

    fn encode_domain(match_type: DomainMatchType, value: &str, attributes: &[&str]) -> Vec<u8> {
        let mut domain = Vec::new();
        push_varint(&mut domain, 1 << 3);
        push_varint(
            &mut domain,
            match match_type {
                DomainMatchType::Plain => 0,
                DomainMatchType::Regex => 1,
                DomainMatchType::Domain => 2,
                DomainMatchType::Full => 3,
            },
        );
        push_len_field(&mut domain, 2, value.as_bytes());
        for attribute in attributes {
            let mut encoded_attribute = Vec::new();
            push_len_field(&mut encoded_attribute, 1, attribute.as_bytes());
            push_len_field(&mut domain, 3, &encoded_attribute);
        }
        domain
    }

    fn encode_geosite(country_code: &str, domains: &[(DomainMatchType, &str, &[&str])]) -> Vec<u8> {
        let mut entry = Vec::new();
        push_len_field(&mut entry, 1, country_code.as_bytes());
        for (match_type, value, attributes) in domains {
            let domain = encode_domain(match_type.clone(), value, attributes);
            push_len_field(&mut entry, 2, &domain);
        }
        entry
    }

    fn read_all(path: &std::path::Path) -> Vec<(String, Vec<GeoSnapshotRule>)> {
        let reader = SiteSnapshotReader::open(path).unwrap();
        reader
            .index()
            .iter()
            .map(|entry| {
                let mut key_reader = reader.open_key(&entry.key).unwrap();
                let mut rules = Vec::new();
                while let Some(rule) = key_reader.next_rule().unwrap() {
                    rules.push(rule);
                }
                (entry.key.clone(), rules)
            })
            .collect()
    }

    #[test]
    fn dat_bytes_become_a_site_snapshot() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("site.snap");
        let source_id = Uuid::new_v4();
        let mut dat = Vec::new();
        let entry = encode_geosite(
            "CN",
            &[
                (DomainMatchType::Domain, "Example.COM.", &["z", "a"]),
                (DomainMatchType::Full, "WWW.Example.com", &[]),
            ],
        );
        push_len_field(&mut dat, 1, &entry);

        let cancel = tokio_util::sync::CancellationToken::new();
        let summary = build_dat_snapshot_bytes(&dat, &path, source_id, &cancel).unwrap();
        assert_eq!(summary.entries, 1);

        let reader = SiteSnapshotReader::open(&path).unwrap();
        assert_eq!(reader.metadata().source_id, source_id);
        let values = read_all(&path);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, "CN");
        assert_eq!(
            values[0].1,
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
    }

    #[test]
    fn adguard_file_applies_negatives_and_deduplicates() {
        let dir = tempdir().unwrap();
        let source_path = dir.path().join("adguard.txt");
        let snapshot_path = dir.path().join("adguard.snap");
        fs::write(
            &source_path,
            b"||ads.example.com^\n@@||allowed.example.com^\n||safe.example^\nsafe.example\n",
        )
        .unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        build_adguard_snapshot_file(
            &source_path,
            &snapshot_path,
            Uuid::new_v4(),
            "my-list",
            &cancel,
        )
        .unwrap();

        let values = read_all(&snapshot_path);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, "MY-LIST");
        assert_eq!(
            values[0].1.iter().map(|rule| rule.value.as_str()).collect::<Vec<_>>(),
            vec!["ads.example.com", "safe.example"]
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_stream_bridge_feeds_the_streaming_dat_parser() {
        use bytes::Bytes;
        use futures::stream;
        use tokio_util::io::{StreamReader, SyncIoBridge};

        let dir = tempdir().unwrap();
        let path = dir.path().join("bridged.snap");
        let mut dat = Vec::new();
        push_len_field(
            &mut dat,
            1,
            &encode_geosite("CN", &[(DomainMatchType::Domain, "example.com", &[])]),
        );
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            dat.chunks(3).map(|chunk| Ok(Bytes::copy_from_slice(chunk))).collect();
        let async_reader = StreamReader::new(stream::iter(chunks));
        let bridge = SyncIoBridge::new(async_reader);
        let snapshot_path = path.clone();
        let cancel = tokio_util::sync::CancellationToken::new();
        let summary = tokio::task::spawn_blocking(move || {
            super::build_dat_snapshot_reader(bridge, &snapshot_path, Uuid::new_v4(), &cancel)
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(summary.entries, 1);
        assert_eq!(read_all(&path)[0].1[0].value, "example.com");
    }
}
