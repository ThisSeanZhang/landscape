use std::{
    fs,
    path::{Path, PathBuf},
};

use landscape_common::{LANDSCAPE_GEO_RAW_DIR, args::LAND_HOME_PATH};
use uuid::Uuid;

pub fn raw_dat_path(kind: &str, id: Uuid) -> PathBuf {
    LAND_HOME_PATH.join(LANDSCAPE_GEO_RAW_DIR).join(format!("{kind}-{id}.raw"))
}

pub fn remove_raw_dat(kind: &str, id: Uuid) {
    remove_file_if_exists(&raw_dat_path(kind, id), "raw geo file");
}

fn remove_file_if_exists(path: &Path, label: &str) {
    if let Err(e) = fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("remove {label} {:?} failed: {}", path, e);
    }
}

/// Remove raw dat files (and leftover `.tmp` siblings) whose source config no
/// longer exists. Files whose id belongs to a live config — including an
/// in-flight `.tmp` write — are left untouched. Returns the removed paths so
/// callers can log the sweep outcome.
pub fn sweep_orphan_raw_files(
    kind: &str,
    live_ids: &std::collections::HashSet<Uuid>,
) -> Vec<PathBuf> {
    sweep_orphan_raw_files_in(&LAND_HOME_PATH.join(LANDSCAPE_GEO_RAW_DIR), kind, live_ids)
}

fn sweep_orphan_raw_files_in(
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
        let Some(stem) = name.strip_suffix(".raw").or_else(|| name.strip_suffix(".raw.tmp")) else {
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
            Err(e) => tracing::warn!("sweep orphan raw geo file {:?} failed: {}", path, e),
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn raw_dat_path_points_into_geo_raw_dir() {
        let path = raw_dat_path("ip", Uuid::nil());
        assert!(path.ends_with(format!("ip-{}.raw", Uuid::nil())));
    }

    #[test]
    fn remove_missing_file_is_silent() {
        remove_raw_dat("ip", Uuid::nil());
    }

    #[test]
    fn sweep_removes_orphans_and_keeps_live_or_unknown_files() {
        use std::collections::HashSet;

        let dir = tempdir().unwrap();
        let live = Uuid::new_v4();
        let dead = Uuid::new_v4();

        let keep_live = dir.path().join(format!("ip-{live}.raw"));
        let keep_live_tmp = dir.path().join(format!("ip-{live}.raw.tmp"));
        let keep_other_kind = dir.path().join(format!("site-{dead}.raw"));
        let keep_unparseable = dir.path().join("ip-not-a-uuid.raw");
        let drop_dead = dir.path().join(format!("ip-{dead}.raw"));
        let drop_dead_tmp = dir.path().join(format!("ip-{dead}.raw.tmp"));
        for path in [
            &keep_live,
            &keep_live_tmp,
            &keep_other_kind,
            &keep_unparseable,
            &drop_dead,
            &drop_dead_tmp,
        ] {
            fs::write(path, b"x").unwrap();
        }

        let mut live_ids = HashSet::new();
        live_ids.insert(live);

        let mut removed = sweep_orphan_raw_files_in(dir.path(), "ip", &live_ids);
        let mut expected = vec![drop_dead, drop_dead_tmp];
        removed.sort();
        expected.sort();

        assert_eq!(removed, expected);
        assert!(keep_live.exists());
        assert!(keep_live_tmp.exists());
        assert!(keep_other_kind.exists());
        assert!(keep_unparseable.exists());
    }

    #[test]
    fn sweep_on_missing_dir_is_silent() {
        let removed = sweep_orphan_raw_files_in(
            Path::new("/nonexistent-landscape-geo-dir"),
            "ip",
            &std::collections::HashSet::new(),
        );
        assert!(removed.is_empty());
    }
}
