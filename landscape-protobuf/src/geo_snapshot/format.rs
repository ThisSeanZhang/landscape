use std::{
    fs::File,
    io::{self, Cursor, Read},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    FORMAT_VERSION, GeoSnapshotError, GeoSnapshotHash, GeoSnapshotIndex, GeoSnapshotIndexEntry,
    GeoSnapshotMetadata, GeoSnapshotSourceKind, HASH_ALGO_SHA256_PAYLOAD, HEADER_LEN, HEADER_MAGIC,
    MAX_KEY_BYTES, MIN_INDEX_ENTRY_BYTES, TRAILER_LEN, TRAILER_MAGIC,
};

pub fn geo_snapshot_hash_hex(hash: &GeoSnapshotHash) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn encode_header(
    source_kind: GeoSnapshotSourceKind,
    source_id: Uuid,
    created_at_ms: u64,
) -> [u8; HEADER_LEN as usize] {
    let mut header = [0u8; HEADER_LEN as usize];
    header[0..8].copy_from_slice(&HEADER_MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[10] = source_kind as u8;
    header[11] = HASH_ALGO_SHA256_PAYLOAD;
    header[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    header[16..32].copy_from_slice(source_id.as_bytes());
    header[32..40].copy_from_slice(&created_at_ms.to_le_bytes());
    header
}

pub(super) fn decode_header(
    header: &[u8; HEADER_LEN as usize],
) -> Result<GeoSnapshotMetadata, GeoSnapshotError> {
    if header[0..8] != HEADER_MAGIC {
        return Err(GeoSnapshotError::InvalidMagic);
    }
    let format_version = u16::from_le_bytes([header[8], header[9]]);
    if format_version != FORMAT_VERSION {
        return Err(GeoSnapshotError::UnsupportedFormatVersion(format_version));
    }
    let source_kind = GeoSnapshotSourceKind::from_u8(header[10])
        .ok_or(GeoSnapshotError::UnsupportedSourceKind(header[10]))?;
    let hash_algo = header[11];
    if hash_algo != HASH_ALGO_SHA256_PAYLOAD {
        return Err(GeoSnapshotError::UnsupportedHashAlgorithm(hash_algo));
    }
    let header_len = u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as u64;
    if header_len != HEADER_LEN {
        return Err(GeoSnapshotError::InvalidHeader("unexpected header length"));
    }
    let source_id = Uuid::from_slice(&header[16..32])
        .map_err(|_| GeoSnapshotError::InvalidHeader("invalid source UUID"))?;
    let created_at_ms =
        u64::from_le_bytes(header[32..40].try_into().expect("fixed header timestamp range"));
    Ok(GeoSnapshotMetadata {
        format_version,
        source_kind,
        hash_algo,
        source_id,
        created_at_ms,
    })
}

pub(super) fn decode_trailer(
    trailer: &[u8; TRAILER_LEN as usize],
) -> Result<(u64, u64, u64, GeoSnapshotHash), GeoSnapshotError> {
    if trailer[56..64] != TRAILER_MAGIC {
        return Err(GeoSnapshotError::InvalidTrailer("invalid trailer magic"));
    }
    let index_offset = u64::from_le_bytes(trailer[0..8].try_into().expect("trailer offset range"));
    let index_len = u64::from_le_bytes(trailer[8..16].try_into().expect("trailer length range"));
    let entry_count = u64::from_le_bytes(trailer[16..24].try_into().expect("trailer count range"));
    let index_sha256: GeoSnapshotHash = trailer[24..56].try_into().expect("trailer hash range");
    Ok((index_offset, index_len, entry_count, index_sha256))
}

pub(super) fn decode_index(
    bytes: &[u8],
    expected_entry_count: u64,
    index_offset: u64,
) -> Result<GeoSnapshotIndex, GeoSnapshotError> {
    let mut cursor = Cursor::new(bytes);
    let entry_count = read_index_u64(&mut cursor)?;
    if entry_count != expected_entry_count {
        return Err(GeoSnapshotError::InvalidIndex("entry count does not match trailer"));
    }
    let max_entries =
        bytes.len().saturating_sub(8).checked_div(MIN_INDEX_ENTRY_BYTES as usize).unwrap_or(0)
            as u64;
    if entry_count > max_entries {
        return Err(GeoSnapshotError::InvalidIndex("too many index entries for index size"));
    }

    let mut entries = Vec::with_capacity(entry_count as usize);
    let mut positions = std::collections::HashMap::with_capacity(entry_count as usize);
    let mut previous_key: Option<String> = None;
    for _ in 0..entry_count {
        let key_len = read_index_u32(&mut cursor)?;
        if key_len == 0 || key_len > MAX_KEY_BYTES {
            return Err(GeoSnapshotError::InvalidIndex("invalid key length"));
        }
        let key = read_index_string(&mut cursor, key_len as usize)?;
        if let Some(previous) = previous_key.as_ref()
            && previous >= &key
        {
            return Err(GeoSnapshotError::InvalidIndex("index keys are not strictly sorted"));
        }
        previous_key = Some(key.clone());

        let mut hash = [0u8; 32];
        read_index_exact(&mut cursor, &mut hash)?;
        let payload_offset = read_index_u64(&mut cursor)?;
        let payload_len = read_index_u64(&mut cursor)?;
        let item_count = read_index_u64(&mut cursor)?;
        let payload_end = payload_offset
            .checked_add(payload_len)
            .ok_or(GeoSnapshotError::InvalidIndex("payload range overflow"))?;
        if payload_offset < HEADER_LEN || payload_end > index_offset {
            return Err(GeoSnapshotError::InvalidIndex("payload range is out of bounds"));
        }
        if positions.insert(key.clone(), entries.len()).is_some() {
            return Err(GeoSnapshotError::DuplicateKey(key));
        }
        entries.push(GeoSnapshotIndexEntry { key, hash, payload_offset, payload_len, item_count });
    }
    if cursor.position() != bytes.len() as u64 {
        return Err(GeoSnapshotError::InvalidIndex("trailing bytes in index"));
    }
    Ok(GeoSnapshotIndex { entries, positions })
}

pub(super) fn read_file_exact(file: &mut File, buffer: &mut [u8]) -> Result<(), GeoSnapshotError> {
    file.read_exact(buffer).map_err(|error| match error.kind() {
        io::ErrorKind::UnexpectedEof => GeoSnapshotError::InvalidHeader("truncated snapshot"),
        _ => GeoSnapshotError::Io(error),
    })
}

pub(super) fn hash_index(bytes: &[u8]) -> GeoSnapshotHash {
    Sha256::digest(bytes).into()
}

fn read_index_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, GeoSnapshotError> {
    let mut bytes = [0u8; 4];
    read_index_exact(cursor, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_index_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, GeoSnapshotError> {
    let mut bytes = [0u8; 8];
    read_index_exact(cursor, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_index_string(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<String, GeoSnapshotError> {
    let mut bytes = vec![0u8; len];
    read_index_exact(cursor, &mut bytes)?;
    String::from_utf8(bytes).map_err(|_| GeoSnapshotError::InvalidUtf8("index key"))
}

fn read_index_exact(cursor: &mut Cursor<&[u8]>, buffer: &mut [u8]) -> Result<(), GeoSnapshotError> {
    cursor.read_exact(buffer).map_err(|_| GeoSnapshotError::InvalidIndex("truncated index"))
}
