use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    GeoSnapshotError, GeoSnapshotHash, GeoSnapshotIndexEntry, GeoSnapshotSourceKind, HEADER_LEN,
    MAX_KEY_BYTES, TRAILER_LEN, TRAILER_MAGIC,
    format::{encode_header, hash_index},
};

pub struct GeoSnapshotWriter {
    final_path: PathBuf,
    tmp_path: PathBuf,
    inner: Option<BufWriter<File>>,
    position: u64,
    index: HashMap<String, GeoSnapshotIndexEntry>,
    current: Option<OpenKey>,
    finished: bool,
}

struct OpenKey {
    key: String,
    payload_offset: u64,
    hasher: Sha256,
    item_count: u64,
}

impl GeoSnapshotWriter {
    pub fn create(
        final_path: impl Into<PathBuf>,
        source_kind: GeoSnapshotSourceKind,
        source_id: Uuid,
    ) -> Result<Self, GeoSnapshotError> {
        let final_path = final_path.into();
        let tmp_path = tmp_path_for(&final_path);
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let created = (|| {
            let file =
                OpenOptions::new().write(true).create(true).truncate(true).open(&tmp_path)?;
            let mut inner = BufWriter::new(file);
            inner.write_all(&encode_header(source_kind, source_id, now_ms()))?;
            Ok(Self {
                final_path,
                tmp_path: tmp_path.clone(),
                inner: Some(inner),
                position: HEADER_LEN,
                index: HashMap::new(),
                current: None,
                finished: false,
            })
        })();

        if created.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        created
    }

    pub fn start_key(&mut self, key: &str) -> Result<(), GeoSnapshotError> {
        self.ensure_open()?;
        if self.current.is_some() {
            return Err(GeoSnapshotError::OpenKey);
        }
        let key = key.trim().to_ascii_uppercase();
        if key.is_empty() {
            return Err(GeoSnapshotError::EmptyKey);
        }
        if key.len() > MAX_KEY_BYTES as usize {
            return Err(GeoSnapshotError::KeyTooLong);
        }
        self.current = Some(OpenKey {
            key,
            payload_offset: self.position,
            hasher: Sha256::new(),
            item_count: 0,
        });
        Ok(())
    }

    /// Append one opaque item payload. Each call increments the key's item
    /// count stored in the index. Callers are responsible for encoding and
    /// framing items themselves.
    pub fn write_item(&mut self, item: &[u8]) -> Result<(), GeoSnapshotError> {
        self.ensure_open()?;
        if self.current.is_none() {
            return Err(GeoSnapshotError::NoOpenKey);
        }
        self.write_payload(item)?;
        if let Some(current) = self.current.as_mut() {
            current.item_count += 1;
        }
        Ok(())
    }

    pub fn end_key(&mut self) -> Result<(), GeoSnapshotError> {
        self.ensure_open()?;
        let current = self.current.take().ok_or(GeoSnapshotError::NoOpenKey)?;
        let hash: GeoSnapshotHash = current.hasher.finalize().into();
        let payload_len = self
            .position
            .checked_sub(current.payload_offset)
            .ok_or(GeoSnapshotError::LengthOverflow)?;
        self.index.insert(
            current.key.clone(),
            GeoSnapshotIndexEntry {
                key: current.key,
                hash,
                payload_offset: current.payload_offset,
                payload_len,
                item_count: current.item_count,
            },
        );
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), GeoSnapshotError> {
        self.ensure_open()?;
        if self.current.is_some() {
            return Err(GeoSnapshotError::OpenKey);
        }

        let mut entries: Vec<GeoSnapshotIndexEntry> =
            std::mem::take(&mut self.index).into_values().collect();
        entries.sort_unstable_by(|left, right| left.key.cmp(&right.key));

        let mut index_bytes = Vec::new();
        index_bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for entry in &entries {
            let key_len =
                u32::try_from(entry.key.len()).map_err(|_| GeoSnapshotError::LengthOverflow)?;
            index_bytes.extend_from_slice(&key_len.to_le_bytes());
            index_bytes.extend_from_slice(entry.key.as_bytes());
            index_bytes.extend_from_slice(&entry.hash);
            index_bytes.extend_from_slice(&entry.payload_offset.to_le_bytes());
            index_bytes.extend_from_slice(&entry.payload_len.to_le_bytes());
            index_bytes.extend_from_slice(&entry.item_count.to_le_bytes());
        }

        let index_offset = self.position;
        let index_len =
            u64::try_from(index_bytes.len()).map_err(|_| GeoSnapshotError::LengthOverflow)?;
        let index_sha256 = hash_index(&index_bytes);
        self.write_payload(&index_bytes)?;

        let mut trailer = [0u8; TRAILER_LEN as usize];
        trailer[0..8].copy_from_slice(&index_offset.to_le_bytes());
        trailer[8..16].copy_from_slice(&index_len.to_le_bytes());
        trailer[16..24].copy_from_slice(&(entries.len() as u64).to_le_bytes());
        trailer[24..56].copy_from_slice(&index_sha256);
        trailer[56..64].copy_from_slice(&TRAILER_MAGIC);
        self.write_payload(&trailer)?;

        let mut inner = self.inner.take().ok_or(GeoSnapshotError::AlreadyFinished)?;
        inner.flush()?;
        inner.get_ref().sync_all()?;
        drop(inner);

        fs::rename(&self.tmp_path, &self.final_path)?;
        if let Some(parent) = self.final_path.parent()
            && let Ok(dir) = File::open(parent)
        {
            let _ = dir.sync_all();
        }
        self.finished = true;
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), GeoSnapshotError> {
        if self.finished || self.inner.is_none() {
            Err(GeoSnapshotError::AlreadyFinished)
        } else {
            Ok(())
        }
    }

    fn write_payload(&mut self, bytes: &[u8]) -> Result<(), GeoSnapshotError> {
        let inner = self.inner.as_mut().ok_or(GeoSnapshotError::AlreadyFinished)?;
        inner.write_all(bytes)?;
        self.position = self
            .position
            .checked_add(u64::try_from(bytes.len()).map_err(|_| GeoSnapshotError::LengthOverflow)?)
            .ok_or(GeoSnapshotError::LengthOverflow)?;
        if let Some(current) = self.current.as_mut() {
            current.hasher.update(bytes);
        }
        Ok(())
    }
}

impl Drop for GeoSnapshotWriter {
    fn drop(&mut self) {
        if !self.finished {
            if let Some(mut inner) = self.inner.take() {
                let _ = inner.flush();
            }
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

fn tmp_path_for(final_path: &Path) -> PathBuf {
    let mut path = final_path.as_os_str().to_os_string();
    path.push(".tmp");
    PathBuf::from(path)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
