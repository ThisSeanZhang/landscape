use std::{
    fs,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use uuid::Uuid;

use landscape_common::{LANDSCAPE_GEO_RAW_DIR, args::LAND_HOME_PATH};

pub fn raw_dat_path(kind: &str, id: Uuid) -> PathBuf {
    LAND_HOME_PATH.join(LANDSCAPE_GEO_RAW_DIR).join(format!("{kind}-{id}.raw"))
}

fn tmp_path_of(final_path: &Path) -> PathBuf {
    let mut tmp_os = final_path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    PathBuf::from(tmp_os)
}

/// Unverified bytes being streamed to `{final}.tmp`; dropped without
/// [`Self::seal`] the tmp file is removed.
pub struct RawTmpFile {
    final_path: PathBuf,
    tmp_path: Option<PathBuf>,
    writer: BufWriter<fs::File>,
}

impl RawTmpFile {
    pub fn create(final_path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = tmp_path_of(final_path);
        let file = fs::File::create(&tmp_path)?;
        Ok(Self {
            final_path: final_path.to_path_buf(),
            tmp_path: Some(tmp_path),
            writer: BufWriter::new(file),
        })
    }

    pub fn write_chunk(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(chunk)
    }

    /// Flush and fsync, then hand over to [`SealedRawFile`] for
    /// verify-then-commit.
    pub fn seal(mut self) -> std::io::Result<SealedRawFile> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        let tmp_path = self.tmp_path.take().expect("tmp path already taken");
        Ok(SealedRawFile {
            final_path: std::mem::take(&mut self.final_path),
            tmp_path,
        })
    }
}

impl Drop for RawTmpFile {
    fn drop(&mut self) {
        if let Some(tmp_path) = &self.tmp_path {
            let _ = fs::remove_file(tmp_path);
        }
    }
}

/// Fsynced tmp awaiting format verification; `commit` atomically renames it
/// to the final `.raw` path, anything else drops the tmp file.
pub struct SealedRawFile {
    final_path: PathBuf,
    tmp_path: PathBuf,
}

impl SealedRawFile {
    pub fn read_back(&self) -> std::io::Result<Vec<u8>> {
        fs::read(&self.tmp_path)
    }

    pub fn commit(self) -> std::io::Result<()> {
        fs::rename(&self.tmp_path, &self.final_path)
    }

    pub fn abort(self) {
        let _ = fs::remove_file(&self.tmp_path);
    }
}

impl Drop for SealedRawFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.tmp_path);
    }
}

/// Stream download chunks straight into `{final}.tmp`, then fsync.
pub async fn stream_to_tmp<S, C, E>(
    mut stream: S,
    final_path: &Path,
) -> std::io::Result<SealedRawFile>
where
    S: futures::Stream<Item = Result<C, E>> + Unpin,
    C: AsRef<[u8]>,
    E: std::error::Error + Send + Sync + 'static,
{
    use futures::StreamExt;
    let mut tmp = RawTmpFile::create(final_path)?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(std::io::Error::other)?;
        tmp.write_chunk(chunk.as_ref())?;
    }
    tmp.seal()
}

/// Buffer already-in-memory bytes through the same tmp + fsync path.
pub fn write_bytes_to_tmp(final_path: &Path, bytes: &[u8]) -> std::io::Result<SealedRawFile> {
    let mut tmp = RawTmpFile::create(final_path)?;
    tmp.write_chunk(bytes)?;
    tmp.seal()
}

pub fn remove_raw_dat(kind: &str, id: Uuid) {
    let path = raw_dat_path(kind, id);
    if let Err(e) = fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("remove raw geo file {:?} failed: {}", path, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_and_seal(path: &Path, bytes: &[u8]) -> SealedRawFile {
        let mut tmp = RawTmpFile::create(path).unwrap();
        for chunk in bytes.chunks(3) {
            tmp.write_chunk(chunk).unwrap();
        }
        tmp.seal().unwrap()
    }

    #[test]
    fn commit_replaces_existing_file_and_leaves_no_tmp() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ip-00000000-0000-0000-0000-000000000000.raw");

        let sealed = write_and_seal(&path, b"v1");
        assert_eq!(sealed.read_back().unwrap(), b"v1");
        sealed.commit().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"v1");

        let sealed = write_and_seal(&path, b"v2");
        sealed.commit().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"v2");

        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn abort_drops_tmp_and_keeps_previous_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("site-00000000-0000-0000-0000-000000000000.raw");

        write_and_seal(&path, b"good").commit().unwrap();

        let sealed = write_and_seal(&path, b"broken");
        sealed.abort();

        assert_eq!(fs::read(&path).unwrap(), b"good");
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn unsealed_tmp_file_is_removed_on_drop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ip-00000000-0000-0000-0000-000000000000.raw");

        {
            let mut tmp = RawTmpFile::create(&path).unwrap();
            tmp.write_chunk(b"partial").unwrap();
        }

        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();
        assert!(entries.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn create_builds_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("geo/raw").join("site-00000000-0000-0000-0000-000000000000.raw");

        write_and_seal(&path, b"data").commit().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"data");
    }

    #[test]
    fn raw_dat_path_points_into_geo_raw_dir() {
        let path = raw_dat_path("ip", Uuid::nil());
        assert!(path.to_string_lossy().contains("geo/raw"));
        assert!(path.ends_with(format!("ip-{}.raw", Uuid::nil())));
    }

    #[test]
    fn remove_missing_file_is_silent() {
        remove_raw_dat("ip", Uuid::nil());
    }
}
