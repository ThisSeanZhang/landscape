mod format;
mod ip;
mod reader;
mod site;
mod writer;

use std::{collections::HashMap, io};

use uuid::Uuid;

pub use format::geo_snapshot_hash_hex;
pub use ip::{IpSnapshotCidr, IpSnapshotKeyReader, IpSnapshotReader, IpSnapshotWriter};
pub use reader::{GeoSnapshotPayloadReader, GeoSnapshotReader};
pub use site::{GeoSnapshotRule, SiteSnapshotKeyReader, SiteSnapshotReader, SiteSnapshotWriter};
pub use writer::GeoSnapshotWriter;

pub type GeoSnapshotHash = [u8; 32];

pub(super) const HEADER_MAGIC: [u8; 8] = *b"LGSNAP01";
pub(super) const TRAILER_MAGIC: [u8; 8] = *b"LGSNAPEN";
pub(super) const HEADER_LEN: u64 = 64;
pub(super) const TRAILER_LEN: u64 = 64;
pub(super) const FORMAT_VERSION: u16 = 1;
pub(super) const HASH_ALGO_SHA256_PAYLOAD: u8 = 1;

pub(super) const MAX_KEY_BYTES: u32 = 4096;
pub(super) const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MIN_INDEX_ENTRY_BYTES: u64 = 4 + 1 + 32 + 8 + 8 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GeoSnapshotSourceKind {
    Site = 1,
    Ip = 2,
}

impl GeoSnapshotSourceKind {
    pub(super) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Site),
            2 => Some(Self::Ip),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoSnapshotMetadata {
    pub format_version: u16,
    pub source_kind: GeoSnapshotSourceKind,
    pub hash_algo: u8,
    pub source_id: Uuid,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoSnapshotIndexEntry {
    pub key: String,
    pub hash: GeoSnapshotHash,
    pub payload_offset: u64,
    pub payload_len: u64,
    pub item_count: u64,
}

#[derive(Debug, Clone, Default)]
pub struct GeoSnapshotIndex {
    entries: Vec<GeoSnapshotIndexEntry>,
    positions: HashMap<String, usize>,
}

impl GeoSnapshotIndex {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &GeoSnapshotIndexEntry> {
        self.entries.iter()
    }

    pub fn get(&self, key: &str) -> Option<&GeoSnapshotIndexEntry> {
        self.positions.get(key).and_then(|position| self.entries.get(*position))
    }

    pub fn content_hashes(&self) -> HashMap<String, GeoSnapshotHash> {
        self.entries.iter().map(|entry| (entry.key.clone(), entry.hash)).collect()
    }

    pub fn content_hashes_hex(&self) -> HashMap<String, String> {
        self.entries
            .iter()
            .map(|entry| (entry.key.clone(), geo_snapshot_hash_hex(&entry.hash)))
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GeoSnapshotError {
    #[error("snapshot I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid snapshot magic")]
    InvalidMagic,
    #[error("unsupported snapshot format version: {0}")]
    UnsupportedFormatVersion(u16),
    #[error("unsupported snapshot source kind: {0}")]
    UnsupportedSourceKind(u8),
    #[error("unsupported snapshot hash algorithm: {0}")]
    UnsupportedHashAlgorithm(u8),
    #[error("invalid snapshot header: {0}")]
    InvalidHeader(&'static str),
    #[error("invalid snapshot trailer: {0}")]
    InvalidTrailer(&'static str),
    #[error("invalid snapshot index: {0}")]
    InvalidIndex(&'static str),
    #[error("invalid snapshot payload: {0}")]
    InvalidPayload(&'static str),
    #[error("snapshot index checksum mismatch")]
    IndexChecksumMismatch,
    #[error("snapshot key is empty")]
    EmptyKey,
    #[error("snapshot key is too long")]
    KeyTooLong,
    #[error("snapshot index contains duplicate key: {0}")]
    DuplicateKey(String),
    #[error("snapshot contains invalid UTF-8: {0}")]
    InvalidUtf8(&'static str),
    #[error("snapshot payload is truncated")]
    TruncatedPayload,
    #[error("snapshot payload length mismatch")]
    PayloadLengthMismatch,
    #[error("snapshot item count mismatch: expected {expected}, got {actual}")]
    ItemCountMismatch { expected: u64, actual: u64 },
    #[error("snapshot key hash mismatch")]
    KeyHashMismatch,
    #[error("snapshot key not found: {0}")]
    KeyNotFound(String),
    #[error("snapshot writer has an open key")]
    OpenKey,
    #[error("snapshot writer has no open key")]
    NoOpenKey,
    #[error("snapshot writer is already finished")]
    AlreadyFinished,
    #[error("snapshot length overflow")]
    LengthOverflow,
}

#[cfg(test)]
mod tests;
