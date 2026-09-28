use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use uuid::Uuid;

use landscape_common::{args::LAND_HOME_PATH, LANDSCAPE_GEO_RAW_DIR};

pub fn raw_dat_path(kind: &str, id: Uuid) -> PathBuf {
    LAND_HOME_PATH.join(LANDSCAPE_GEO_RAW_DIR).join(format!("{kind}-{id}.raw"))
}

/// Write bytes to `{path}.tmp`, fsync, then atomically rename to `path`,
/// so a partial write can never replace the previous good file.
pub fn persist_raw_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, path)
}

pub fn remove_raw_dat(kind: &str, id: Uuid) {
    let path = raw_dat_path(kind, id);
    if let Err(e) = fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("remove raw geo file {:?} failed: {}", path, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn persist_replaces_existing_file_and_leaves_no_tmp() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ip-00000000-0000-0000-0000-000000000000.raw");

        persist_raw_bytes(&path, b"v1").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"v1");

        persist_raw_bytes(&path, b"v2").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"v2");

        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn persist_creates_parent_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("geo/raw").join("site-00000000-0000-0000-0000-000000000000.raw");

        persist_raw_bytes(&path, b"data").unwrap();
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
