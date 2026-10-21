use std::{io::Read, path::Path};

use landscape_common::config_service::geo::{GeoError, GeoIpFileFormat};
use landscape_protobuf::{
    GeoIpDatStream, GeoIpStreamEvent, GeoIpTxtStream, GeoSnapshotError, IpSnapshotWriter,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default)]
pub struct IpSnapshotBuildSummary {
    pub entries: usize,
    pub valid_lines: usize,
    pub skipped_lines: usize,
}

pub fn build_ip_snapshot_reader<R: Read>(
    reader: R,
    final_path: &Path,
    source_id: Uuid,
    format: &GeoIpFileFormat,
    txt_key: Option<&str>,
    cancel: &CancellationToken,
) -> Result<IpSnapshotBuildSummary, GeoError> {
    match format {
        GeoIpFileFormat::Dat => build_ip_snapshot_dat(reader, final_path, source_id, cancel),
        GeoIpFileFormat::Txt => {
            build_ip_snapshot_txt(reader, final_path, source_id, txt_key, cancel)
        }
    }
}

fn build_ip_snapshot_dat<R: Read>(
    reader: R,
    final_path: &Path,
    source_id: Uuid,
    cancel: &CancellationToken,
) -> Result<IpSnapshotBuildSummary, GeoError> {
    let mut writer = IpSnapshotWriter::create(final_path, source_id)
        .map_err(|error| snapshot_error("create ip snapshot", error))?;
    let entries = write_events(GeoIpDatStream::new(reader), &mut writer, cancel)?;
    writer.finish().map_err(|error| snapshot_error("finish ip snapshot", error))?;
    Ok(IpSnapshotBuildSummary { entries, ..Default::default() })
}

fn build_ip_snapshot_txt<R: Read>(
    reader: R,
    final_path: &Path,
    source_id: Uuid,
    txt_key: Option<&str>,
    cancel: &CancellationToken,
) -> Result<IpSnapshotBuildSummary, GeoError> {
    let mut writer = IpSnapshotWriter::create(final_path, source_id)
        .map_err(|error| snapshot_error("create ip snapshot", error))?;
    let mut stream = GeoIpTxtStream::new(reader, txt_key);
    let entries = write_events(&mut stream, &mut writer, cancel)?;
    writer.finish().map_err(|error| snapshot_error("finish ip snapshot", error))?;
    Ok(IpSnapshotBuildSummary {
        entries,
        valid_lines: stream.valid_lines(),
        skipped_lines: stream.skipped_lines(),
    })
}

fn write_events<I>(
    events: I,
    writer: &mut IpSnapshotWriter,
    cancel: &CancellationToken,
) -> Result<usize, GeoError>
where
    I: IntoIterator<Item = Result<GeoIpStreamEvent, GeoError>>,
{
    let mut current_key = false;
    let mut entries = 0usize;
    for event in events {
        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        match event? {
            GeoIpStreamEvent::EntryStart { country_code } => {
                if current_key {
                    return Err(GeoError::IpDatDecodeError);
                }
                writer
                    .start_key(&country_code)
                    .map_err(|error| snapshot_error("start ip snapshot key", error))?;
                current_key = true;
            }
            GeoIpStreamEvent::Cidr(cidr) => {
                if !current_key {
                    return Err(GeoError::IpDatDecodeError);
                }
                writer
                    .write_cidr(cidr.ip, cidr.prefix)
                    .map_err(|error| snapshot_error("write ip snapshot cidr", error))?;
            }
            GeoIpStreamEvent::EntryEnd => {
                if !current_key {
                    return Err(GeoError::IpDatDecodeError);
                }
                writer
                    .end_key()
                    .map_err(|error| snapshot_error("finish ip snapshot key", error))?;
                current_key = false;
                entries += 1;
            }
        }
    }

    if current_key {
        return Err(GeoError::IpDatDecodeError);
    }
    Ok(entries)
}

fn snapshot_error(context: &str, error: GeoSnapshotError) -> GeoError {
    GeoError::RawDatReadFailed(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, net::IpAddr};

    use landscape_common::config_service::geo::GeoIpFileFormat;
    use landscape_protobuf::{IpSnapshotCidr, IpSnapshotReader};
    use tempfile::tempdir;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::build_ip_snapshot_reader;

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

    fn encode_dat(entries: &[(&str, &[(&str, u32)])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (key, cidrs) in entries {
            let mut entry = Vec::new();
            push_len_field(&mut entry, 1, key.as_bytes());
            for (ip, prefix) in *cidrs {
                let ip: IpAddr = ip.parse().unwrap();
                let ip_bytes = match ip {
                    IpAddr::V4(addr) => addr.octets().to_vec(),
                    IpAddr::V6(addr) => addr.octets().to_vec(),
                };
                let mut cidr = Vec::new();
                push_len_field(&mut cidr, 1, &ip_bytes);
                push_varint(&mut cidr, 2 << 3);
                push_varint(&mut cidr, u64::from(*prefix));
                push_len_field(&mut entry, 2, &cidr);
            }
            push_len_field(&mut list, 1, &entry);
        }
        list
    }

    fn read_all(path: &std::path::Path) -> Vec<(String, Vec<IpSnapshotCidr>)> {
        let reader = IpSnapshotReader::open(path).unwrap();
        reader
            .index()
            .iter()
            .map(|entry| {
                let mut key_reader = reader.open_key(&entry.key).unwrap();
                let mut cidrs = Vec::new();
                while let Some(cidr) = key_reader.next_cidr().unwrap() {
                    cidrs.push(cidr);
                }
                (entry.key.clone(), cidrs)
            })
            .collect()
    }

    #[test]
    fn builds_dat_ip_snapshot_without_full_parse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ip.snap");
        let bytes = encode_dat(&[
            ("CN", &[("10.1.2.3", 8), ("2001:db8::1", 32)]),
            ("US", &[("192.0.2.1", 24)]),
        ]);

        let summary = build_ip_snapshot_reader(
            Cursor::new(bytes),
            &path,
            Uuid::new_v4(),
            &GeoIpFileFormat::Dat,
            None,
            &CancellationToken::new(),
        )
        .unwrap();

        assert_eq!(summary.entries, 2);
        assert_eq!(
            read_all(&path),
            vec![
                (
                    "CN".to_string(),
                    vec![
                        IpSnapshotCidr { ip: "10.0.0.0".parse().unwrap(), prefix: 8 },
                        IpSnapshotCidr { ip: "2001:db8::".parse().unwrap(), prefix: 32 },
                    ]
                ),
                (
                    "US".to_string(),
                    vec![IpSnapshotCidr { ip: "192.0.2.0".parse().unwrap(), prefix: 24 }]
                ),
            ]
        );
    }

    #[test]
    fn builds_txt_ip_snapshot_and_reports_line_counts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ip.snap");
        let bytes = b"# comment\n10.1.2.3/8\ninvalid\n2001:db8::1/32\n";

        let summary = build_ip_snapshot_reader(
            Cursor::new(bytes),
            &path,
            Uuid::new_v4(),
            &GeoIpFileFormat::Txt,
            Some("cn"),
            &CancellationToken::new(),
        )
        .unwrap();

        assert_eq!(summary.entries, 1);
        assert_eq!(summary.valid_lines, 2);
        assert_eq!(summary.skipped_lines, 1);
        assert_eq!(
            read_all(&path),
            vec![(
                "CN".to_string(),
                vec![
                    IpSnapshotCidr { ip: "10.0.0.0".parse().unwrap(), prefix: 8 },
                    IpSnapshotCidr { ip: "2001:db8::".parse().unwrap(), prefix: 32 },
                ]
            )]
        );
    }
}
