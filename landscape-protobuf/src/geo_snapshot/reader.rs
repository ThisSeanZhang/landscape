use std::{
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
    path::PathBuf,
};

use sha2::{Digest, Sha256};

use super::{
    GeoSnapshotError, GeoSnapshotHash, GeoSnapshotIndex, GeoSnapshotMetadata, HEADER_LEN,
    MAX_INDEX_BYTES, TRAILER_LEN,
    format::{decode_header, decode_index, decode_trailer, hash_index, read_file_exact},
};

pub struct GeoSnapshotReader {
    path: PathBuf,
    metadata: GeoSnapshotMetadata,
    index: GeoSnapshotIndex,
}

impl GeoSnapshotReader {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GeoSnapshotError> {
        let path = path.into();
        let mut file = File::open(&path)?;
        let file_len = file.metadata()?.len();
        if file_len < HEADER_LEN + TRAILER_LEN {
            return Err(GeoSnapshotError::InvalidHeader("file is too short"));
        }

        let mut header = [0u8; HEADER_LEN as usize];
        read_file_exact(&mut file, &mut header)?;
        let metadata = decode_header(&header)?;

        file.seek(SeekFrom::End(-(TRAILER_LEN as i64)))?;
        let mut trailer = [0u8; TRAILER_LEN as usize];
        read_file_exact(&mut file, &mut trailer)?;
        let (index_offset, index_len, index_entry_count, index_sha256) = decode_trailer(&trailer)?;

        if index_offset < HEADER_LEN {
            return Err(GeoSnapshotError::InvalidTrailer("index overlaps header"));
        }
        if index_len > MAX_INDEX_BYTES {
            return Err(GeoSnapshotError::InvalidIndex("index is too large"));
        }
        let expected_end = index_offset
            .checked_add(index_len)
            .and_then(|value| value.checked_add(TRAILER_LEN))
            .ok_or(GeoSnapshotError::LengthOverflow)?;
        if expected_end != file_len {
            return Err(GeoSnapshotError::InvalidTrailer(
                "index/trailer bounds do not match file size",
            ));
        }

        file.seek(SeekFrom::Start(index_offset))?;
        let mut index_bytes = vec![
            0u8;
            usize::try_from(index_len).map_err(|_| {
                GeoSnapshotError::InvalidIndex("index length does not fit in memory")
            })?
        ];
        read_file_exact(&mut file, &mut index_bytes)?;
        let actual_index_sha256 = hash_index(&index_bytes);
        if actual_index_sha256 != index_sha256 {
            return Err(GeoSnapshotError::IndexChecksumMismatch);
        }

        let index = decode_index(&index_bytes, index_entry_count, index_offset)?;
        if index.len() as u64 != index_entry_count {
            return Err(GeoSnapshotError::InvalidIndex("index entry count mismatch"));
        }

        Ok(Self { path, metadata, index })
    }

    pub fn metadata(&self) -> &GeoSnapshotMetadata {
        &self.metadata
    }

    pub fn index(&self) -> &GeoSnapshotIndex {
        &self.index
    }

    pub fn open_key(&self, key: &str) -> Result<GeoSnapshotPayloadReader, GeoSnapshotError> {
        let key = key.trim().to_ascii_uppercase();
        let entry =
            self.index.get(&key).ok_or_else(|| GeoSnapshotError::KeyNotFound(key.to_string()))?;
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(entry.payload_offset))?;
        Ok(GeoSnapshotPayloadReader {
            reader: HashingReader::new(BufReader::new(file).take(entry.payload_len)),
            expected_hash: entry.hash,
            expected_items: entry.item_count,
            expected_payload_len: entry.payload_len,
            items_read: 0,
            finished: false,
        })
    }
}

/// Reads exactly one key's payload while tracking its hash and item count.
/// Callers parse items through the `Read` impl, call [`record_item`] once for
/// each successfully decoded item, and finish with [`finish`].
pub struct GeoSnapshotPayloadReader {
    reader: HashingReader<io::Take<BufReader<File>>>,
    expected_hash: GeoSnapshotHash,
    expected_items: u64,
    expected_payload_len: u64,
    items_read: u64,
    finished: bool,
}

impl GeoSnapshotPayloadReader {
    pub fn remaining_len(&self) -> u64 {
        self.reader.inner.limit()
    }

    pub fn record_item(&mut self) {
        self.items_read += 1;
    }

    pub fn finish(&mut self) -> Result<(), GeoSnapshotError> {
        if self.finished {
            return Ok(());
        }
        if self.reader.inner.limit() != 0 || self.reader.bytes_read != self.expected_payload_len {
            return Err(GeoSnapshotError::PayloadLengthMismatch);
        }
        if self.items_read != self.expected_items {
            return Err(GeoSnapshotError::ItemCountMismatch {
                expected: self.expected_items,
                actual: self.items_read,
            });
        }
        if self.reader.finish_hash() != self.expected_hash {
            return Err(GeoSnapshotError::KeyHashMismatch);
        }
        self.finished = true;
        Ok(())
    }
}

impl Read for GeoSnapshotPayloadReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buffer)
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: Option<Sha256>,
    bytes_read: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, hasher: Some(Sha256::new()), bytes_read: 0 }
    }

    fn finish_hash(&mut self) -> GeoSnapshotHash {
        self.hasher.take().expect("snapshot hash finalized once").finalize().into()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read > 0 {
            if let Some(hasher) = self.hasher.as_mut() {
                hasher.update(&buffer[..read]);
            }
            self.bytes_read = self.bytes_read.saturating_add(read as u64);
        }
        Ok(read)
    }
}
