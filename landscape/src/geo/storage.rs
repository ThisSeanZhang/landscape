use std::{
    fs,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use landscape_common::{LANDSCAPE_GEO_SNAPSHOT_DIR, args::LAND_HOME_PATH};
use uuid::Uuid;

pub fn geo_snapshot_path(kind: &str, id: Uuid) -> PathBuf {
    LAND_HOME_PATH.join(LANDSCAPE_GEO_SNAPSHOT_DIR).join(format!("{kind}-{id}.snap"))
}

pub fn geo_snapshot_source_path(kind: &str, id: Uuid) -> PathBuf {
    LAND_HOME_PATH.join(LANDSCAPE_GEO_SNAPSHOT_DIR).join(format!("{kind}-{id}.source.tmp"))
}

fn tmp_path_of(final_path: &Path) -> PathBuf {
    let mut tmp_os = final_path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    PathBuf::from(tmp_os)
}

/// Unverified bytes being streamed to `{final}.tmp`; dropped without
/// [`Self::seal`] the tmp file is removed.
pub struct GeoTmpFile {
    final_path: PathBuf,
    tmp_path: Option<PathBuf>,
    writer: BufWriter<fs::File>,
}

impl GeoTmpFile {
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

    /// Flush and fsync, then hand over to [`GeoSealedFile`] for
    /// verify-then-commit.
    pub fn seal(mut self) -> std::io::Result<GeoSealedFile> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        let tmp_path = self.tmp_path.take().expect("tmp path already taken");
        Ok(GeoSealedFile {
            final_path: std::mem::take(&mut self.final_path),
            tmp_path,
        })
    }
}

impl Drop for GeoTmpFile {
    fn drop(&mut self) {
        if let Some(tmp_path) = &self.tmp_path {
            let _ = fs::remove_file(tmp_path);
        }
    }
}

/// Fsynced tmp awaiting format verification; `commit` atomically renames it
/// to the final path, anything else drops the tmp file.
pub struct GeoSealedFile {
    final_path: PathBuf,
    tmp_path: PathBuf,
}

impl GeoSealedFile {
    pub fn read_back(&self) -> std::io::Result<Vec<u8>> {
        fs::read(&self.tmp_path)
    }

    pub fn path(&self) -> &Path {
        &self.tmp_path
    }

    pub fn commit(self) -> std::io::Result<()> {
        fs::rename(&self.tmp_path, &self.final_path)
    }

    pub fn abort(self) {
        let _ = fs::remove_file(&self.tmp_path);
    }
}

impl Drop for GeoSealedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.tmp_path);
    }
}

#[derive(Debug)]
pub enum StreamToSealedError {
    Cancelled,
    Io(std::io::Error),
}

/// Stream download chunks straight into `{final}.tmp`, then fsync.
///
/// `should_stop` is polled before every chunk; `on_progress` receives the
/// cumulative number of bytes written.
pub async fn stream_to_sealed<S, C, E>(
    mut stream: S,
    final_path: &Path,
    should_stop: &(dyn Fn() -> bool + Send + Sync),
    on_progress: &mut (dyn FnMut(u64) + Send + Sync),
) -> Result<GeoSealedFile, StreamToSealedError>
where
    S: futures::Stream<Item = Result<C, E>> + Unpin,
    C: AsRef<[u8]>,
    E: std::error::Error + Send + Sync + 'static,
{
    use futures::StreamExt;
    let mut tmp = GeoTmpFile::create(final_path).map_err(StreamToSealedError::Io)?;
    let mut written = 0u64;
    while let Some(chunk) = stream.next().await {
        if should_stop() {
            return Err(StreamToSealedError::Cancelled);
        }
        let chunk = chunk.map_err(|e| StreamToSealedError::Io(std::io::Error::other(e)))?;
        tmp.write_chunk(chunk.as_ref()).map_err(StreamToSealedError::Io)?;
        written += chunk.as_ref().len() as u64;
        on_progress(written);
    }
    if should_stop() {
        return Err(StreamToSealedError::Cancelled);
    }
    tmp.seal().map_err(StreamToSealedError::Io)
}

/// Buffer already-in-memory bytes through the same tmp + fsync path.
pub fn write_bytes_to_sealed(final_path: &Path, bytes: &[u8]) -> std::io::Result<GeoSealedFile> {
    let mut tmp = GeoTmpFile::create(final_path)?;
    tmp.write_chunk(bytes)?;
    tmp.seal()
}

pub fn remove_geo_snapshot(kind: &str, id: Uuid) {
    let snapshot_path = geo_snapshot_path(kind, id);
    remove_file_if_exists(&snapshot_path, "geo snapshot");
    remove_file_if_exists(&tmp_path_of(&snapshot_path), "geo snapshot temp");

    let source_path = geo_snapshot_source_path(kind, id);
    remove_file_if_exists(&source_path, "geo snapshot source");
    remove_file_if_exists(&tmp_path_of(&source_path), "geo snapshot source temp");
}

pub fn sweep_orphan_geo_snapshots(
    kind: &str,
    live_ids: &std::collections::HashSet<Uuid>,
) -> Vec<PathBuf> {
    sweep_orphan_geo_snapshots_in(&LAND_HOME_PATH.join(LANDSCAPE_GEO_SNAPSHOT_DIR), kind, live_ids)
}

fn sweep_orphan_geo_snapshots_in(
    dir: &Path,
    kind: &str,
    live_ids: &std::collections::HashSet<Uuid>,
) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let prefix = format!("{kind}-");
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else { continue };
        let Some(stem) = name
            .strip_suffix(".snap")
            .or_else(|| name.strip_suffix(".snap.tmp"))
            .or_else(|| name.strip_suffix(".source.tmp"))
            .or_else(|| name.strip_suffix(".source.tmp.tmp"))
        else {
            continue;
        };
        let Some(id_str) = stem.strip_prefix(&prefix) else { continue };
        let Ok(id) = Uuid::parse_str(id_str) else { continue };
        if live_ids.contains(&id) {
            continue;
        }
        let path = entry.path();
        match fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("sweep orphan geo snapshot {:?} failed: {}", path, e),
        }
    }
    removed
}

fn remove_file_if_exists(path: &Path, label: &str) {
    if let Err(e) = fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("remove {label} {:?} failed: {}", path, e);
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;

    fn write_and_seal(path: &Path, bytes: &[u8]) -> GeoSealedFile {
        let mut tmp = GeoTmpFile::create(path).unwrap();
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
            let mut tmp = GeoTmpFile::create(&path).unwrap();
            tmp.write_chunk(b"partial").unwrap();
        }
        assert!(!path.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn snapshot_sweep_keeps_live_files_and_removes_all_temp_variants() {
        let dir = tempdir().unwrap();
        let live = Uuid::new_v4();
        let dead = Uuid::new_v4();
        let keep_live = dir.path().join(format!("site-{live}.snap"));
        let keep_live_tmp = dir.path().join(format!("site-{live}.snap.tmp"));
        let drop_snapshot = dir.path().join(format!("site-{dead}.snap"));
        let drop_snapshot_tmp = dir.path().join(format!("site-{dead}.snap.tmp"));
        let drop_source_tmp = dir.path().join(format!("site-{dead}.source.tmp"));
        let drop_source_tmp_tmp = dir.path().join(format!("site-{dead}.source.tmp.tmp"));
        for path in [
            &keep_live,
            &keep_live_tmp,
            &drop_snapshot,
            &drop_snapshot_tmp,
            &drop_source_tmp,
            &drop_source_tmp_tmp,
        ] {
            fs::write(path, b"x").unwrap();
        }

        let mut live_ids = HashSet::new();
        live_ids.insert(live);
        let mut removed = sweep_orphan_geo_snapshots_in(dir.path(), "site", &live_ids);
        let mut expected =
            vec![drop_snapshot, drop_snapshot_tmp, drop_source_tmp, drop_source_tmp_tmp];
        removed.sort();
        expected.sort();
        assert_eq!(removed, expected);
        assert!(keep_live.exists());
        assert!(keep_live_tmp.exists());
    }
    #[test]
    fn create_builds_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("deeper").join("file.tmp");
        let mut tmp = GeoTmpFile::create(&path).unwrap();
        tmp.write_chunk(b"x").unwrap();
        tmp.seal().unwrap().commit().unwrap();
        assert!(path.exists());
    }

    #[tokio::test]
    async fn stream_to_sealed_reports_cumulative_progress_and_seals() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("download.bin");
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
            vec![Ok(vec![1u8; 4]), Ok(vec![2u8; 5]), Ok(vec![3u8; 9])];
        let stream = futures::stream::iter(chunks);
        let mut seen = Vec::new();

        let sealed = stream_to_sealed(stream, &path, &|| false, &mut |written| seen.push(written))
            .await
            .unwrap();

        assert_eq!(seen, vec![4, 9, 18]);
        assert_eq!(sealed.read_back().unwrap().len(), 18);
    }

    #[tokio::test]
    async fn stream_to_sealed_cancelled_midway_leaves_no_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("download.bin");
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
            vec![Ok(vec![1u8; 4]), Ok(vec![2u8; 4]), Ok(vec![3u8; 4])];
        let stream = futures::stream::iter(chunks);

        let result = stream_to_sealed(stream, &path, &|| true, &mut |_| {}).await;

        assert!(matches!(result, Err(StreamToSealedError::Cancelled)));
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();
        assert!(entries.is_empty());
        assert!(!path.exists());
    }
}
