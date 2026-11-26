use std::path::Path;

use crate::LANDSCAPE_DB_SQLITE_NAME;

#[derive(Clone, Debug)]
pub struct StoreRuntimeConfig {
    pub database_path: String,
}

impl StoreRuntimeConfig {
    pub fn create_default_db_store(home_path: &Path) -> String {
        let path = home_path.join(LANDSCAPE_DB_SQLITE_NAME);
        if path.exists() {
            if path.is_dir() {
                tracing::error!(
                    path = %path.display(),
                    "expected a file path for database, but found a directory"
                );
            }
        } else {
            if let Some(parent) = path.parent()
                && !parent.exists()
                && let Err(error) = std::fs::create_dir_all(parent)
            {
                tracing::error!(
                    path = %parent.display(),
                    %error,
                    "failed to create database directory"
                );
            }
            if let Err(error) = std::fs::File::create(&path) {
                tracing::error!(path = %path.display(), %error, "failed to create database file");
            }
        }
        format!("sqlite://{}?mode=rwc", path.display())
    }
}
