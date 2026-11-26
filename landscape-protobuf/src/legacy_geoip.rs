//! Read-only migration of the v0.24.2 `geo_tmp/ip/<era>.ip` journal.
//! Keep these serde layouts independent of the current configuration types.

use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::{self, BufRead, BufReader},
    net::IpAddr,
    path::Path,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{GeoSnapshotError, IpSnapshotWriter};

#[derive(Debug, thiserror::Error)]
pub enum LegacyGeoIpError {
    #[error("legacy GeoIP restore cancelled")]
    Cancelled,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid legacy GeoIP journal: {0}")]
    Journal(String),
    #[error(transparent)]
    Snapshot(#[from] GeoSnapshotError),
}

#[derive(Serialize, Deserialize)]
enum SaveUnit {
    Data(LegacyEntry),
    Del(LegacyKey),
}

#[derive(Serialize, Deserialize)]
struct LegacyKey {
    name: String,
    key: String,
}

#[derive(Serialize, Deserialize)]
struct LegacyEntry {
    name: String,
    key: String,
    values: Vec<LegacyCidr>,
}

#[derive(Serialize, Deserialize)]
struct LegacyCidr {
    ip: IpAddr,
    prefix: u32,
}

/// Replay complete journals in numeric era order and atomically publish one
/// source's snapshot. Never modify the journals or replace an existing snapshot.
/// Missing sources return false; corruption fails closed, including a partial
/// final record (which might otherwise hide a deletion).
pub fn restore_legacy_geoip_snapshot(
    directory: &Path,
    name: &str,
    snapshot: &Path,
    source_id: Uuid,
    should_stop: impl Fn() -> bool,
) -> Result<bool, LegacyGeoIpError> {
    if snapshot.exists() {
        return Ok(false);
    }
    let directory = match fs::read_dir(directory) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut files = BTreeMap::new();
    for entry in directory {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("ip") {
            continue;
        }
        let era = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| LegacyGeoIpError::Journal(format!("invalid era: {path:?}")))?;
        if files.insert(era, path).is_some() {
            return Err(LegacyGeoIpError::Journal(format!("duplicate era: {era}")));
        }
    }

    let mut entries = BTreeMap::new();
    for path in files.values() {
        let mut reader = BufReader::new(File::open(path)?);
        while !reader.fill_buf()?.is_empty() {
            if should_stop() {
                return Err(LegacyGeoIpError::Cancelled);
            }
            // Bound a single decoded record, rather than the whole journal.
            let unit: SaveUnit = bincode::serde::decode_from_std_read(
                &mut reader,
                bincode::config::standard().with_limit::<268_435_456>(),
            )
            .map_err(|error| LegacyGeoIpError::Journal(format!("{path:?}: {error}")))?;
            match unit {
                SaveUnit::Data(entry) if entry.name == name => {
                    entries.insert(entry.key, entry.values);
                }
                SaveUnit::Del(key) if key.name == name => {
                    entries.remove(&key.key);
                }
                _ => {}
            }
        }
    }
    if entries.is_empty() {
        return Ok(false);
    }

    let mut writer = IpSnapshotWriter::create(snapshot, source_id)?;
    let mut normalized_keys = HashSet::new();
    for (key, values) in entries {
        if !normalized_keys.insert(key.trim().to_ascii_uppercase()) {
            return Err(LegacyGeoIpError::Journal(format!("duplicate normalized key: {key}")));
        }
        writer.start_key(&key)?;
        for cidr in values {
            if should_stop() {
                return Err(LegacyGeoIpError::Cancelled);
            }
            writer.write_cidr(cidr.ip, cidr.prefix)?;
        }
        writer.end_key()?;
    }
    if should_stop() {
        return Err(LegacyGeoIpError::Cancelled);
    }
    writer.finish()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpSnapshotReader;
    use tempfile::tempdir;

    // v0.24.2 SaveUnit::Data: name=L, key=CN, one IPv4 CIDR.
    const OLD_CN: &[u8] = &[0, 1, b'L', 2, b'C', b'N', 1, 0, 192, 0, 2, 0, 24];

    fn encode(unit: SaveUnit) -> Vec<u8> {
        bincode::serde::encode_to_vec(unit, bincode::config::standard()).unwrap()
    }

    fn data(name: &str, key: &str, ip: &str, prefix: u32) -> SaveUnit {
        SaveUnit::Data(LegacyEntry {
            name: name.into(),
            key: key.into(),
            values: vec![LegacyCidr { ip: ip.parse().unwrap(), prefix }],
        })
    }

    #[test]
    fn replays_numeric_eras_updates_deletes_and_source_names() {
        assert_eq!(encode(data("L", "CN", "192.0.2.0", 24)), OLD_CN);
        let dir = tempdir().unwrap();
        let mut first = OLD_CN.to_vec();
        first.extend(encode(data("L", "DELETED", "192.0.2.0", 24)));
        fs::write(dir.path().join("9.ip"), &first).unwrap();
        let mut next = encode(data("L", "CN", "198.51.100.0", 24));
        next.extend(encode(data("L", "V6", "2001:db8::", 32)));
        next.extend(encode(data("OTHER", "CN", "203.0.113.0", 24)));
        next.extend(encode(SaveUnit::Del(LegacyKey { name: "L".into(), key: "DELETED".into() })));
        fs::write(dir.path().join("10.ip"), next).unwrap();
        let snapshot = dir.path().join("out.snap");
        let id = Uuid::new_v4();
        assert!(restore_legacy_geoip_snapshot(dir.path(), "L", &snapshot, id, || false).unwrap());
        let reader = IpSnapshotReader::open(&snapshot).unwrap();
        let keys = reader.index().content_hashes_hex();
        assert_eq!(keys.len(), 2);
        assert!(!keys.contains_key("DELETED"));
        let mut cn = reader.open_key("CN").unwrap();
        assert_eq!(
            cn.next_prepared().unwrap().unwrap().ip(),
            "198.51.100.0".parse::<IpAddr>().unwrap()
        );
        assert!(cn.next_prepared().unwrap().is_none());
        let mut v6 = reader.open_key("V6").unwrap();
        assert_eq!(
            v6.next_prepared().unwrap().unwrap().ip(),
            "2001:db8::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(fs::read(dir.path().join("9.ip")).unwrap(), first);
        let saved = fs::read(&snapshot).unwrap();
        fs::write(dir.path().join("11.ip"), [255]).unwrap();
        assert!(!restore_legacy_geoip_snapshot(dir.path(), "L", &snapshot, id, || false).unwrap());
        assert_eq!(fs::read(&snapshot).unwrap(), saved);
    }

    #[test]
    fn rejects_partial_records_without_publishing_snapshot() {
        let dir = tempdir().unwrap();
        let mut bytes = OLD_CN.to_vec();
        bytes.extend([1, 1, b'L', 2, b'C']); // truncated deletion
        fs::write(dir.path().join("1.ip"), bytes).unwrap();
        let snapshot = dir.path().join("out.snap");
        assert!(
            restore_legacy_geoip_snapshot(dir.path(), "L", &snapshot, Uuid::new_v4(), || false)
                .is_err()
        );
        assert!(!snapshot.exists());
        assert!(!dir.path().join("out.snap.tmp").exists());
    }

    #[test]
    fn missing_or_deleted_source_does_not_publish() {
        let dir = tempdir().unwrap();
        let snapshot = dir.path().join("out.snap");
        assert!(
            !restore_legacy_geoip_snapshot(
                &dir.path().join("missing"),
                "L",
                &snapshot,
                Uuid::new_v4(),
                || false
            )
            .unwrap()
        );
        let mut bytes = OLD_CN.to_vec();
        bytes.extend(encode(SaveUnit::Del(LegacyKey { name: "L".into(), key: "CN".into() })));
        fs::write(dir.path().join("1.ip"), bytes).unwrap();
        assert!(
            !restore_legacy_geoip_snapshot(dir.path(), "L", &snapshot, Uuid::new_v4(), || false)
                .unwrap()
        );
        assert!(!snapshot.exists());
    }

    #[test]
    fn invalid_cidr_does_not_publish_or_leave_temporary_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("1.ip"), encode(data("L", "CN", "192.0.2.0", 33))).unwrap();
        let snapshot = dir.path().join("out.snap");
        assert!(
            restore_legacy_geoip_snapshot(dir.path(), "L", &snapshot, Uuid::new_v4(), || false)
                .is_err()
        );
        assert!(!snapshot.exists());
        assert!(!dir.path().join("out.snap.tmp").exists());
    }

    #[test]
    fn cancellation_before_publish_preserves_journal() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("1.ip"), OLD_CN).unwrap();
        let snapshot = dir.path().join("out.snap");
        let calls = std::cell::Cell::new(0);
        let result =
            restore_legacy_geoip_snapshot(dir.path(), "L", &snapshot, Uuid::new_v4(), || {
                calls.set(calls.get() + 1);
                calls.get() >= 3 // cancel after the record and CIDR have been read
            });
        assert!(matches!(result, Err(LegacyGeoIpError::Cancelled)));
        assert!(!snapshot.exists());
        assert!(!dir.path().join("out.snap.tmp").exists());
        assert_eq!(fs::read(dir.path().join("1.ip")).unwrap(), OLD_CN);
    }
}
