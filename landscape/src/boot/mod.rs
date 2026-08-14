use std::{fs::OpenOptions, io::Write, path::Path};

use landscape_common::{
    config::{InitConfig, InitConfigError, LandscapeConfig},
    error::{LdError, LdResult},
    INIT_FILE_NAME, INIT_LOCK_FILE_NAME, LAND_CONFIG, VERSION,
};

pub mod log;

pub const INIT_LOCK_FILE_CONTENT: &str = r#"⚠ 警告 ⚠
如果您不知道删除这个文件的操作是否正确, 请不要删除这个文件.
此文件用于确定当前的 Landscape Router 是否已经初始化.
删除后将会依照 landscape_init.toml 中的配置进行初始化.
如果不存在 landscape_init.toml 则会清空已有的所有配置.

⚠ WARNING ⚠
If you don't know whether deleting this file is correct, please do not delete it.
This file is used to determine whether the current Landscape Router has been initialized.
After deletion, it will be initialized according to the configuration in landscape_init.toml.
If landscape_init.toml does not exist, all existing configurations will be cleared.
"#;

/// 返回是否进行初始化操作
/// Some: 需要清空并初始化
/// None: 无需进行初始化
/// Err: 出现错误退出
pub fn boot_check<P: AsRef<Path>>(home_path: P) -> LdResult<Option<InitConfig>> {
    let lock_path = home_path.as_ref().join(INIT_LOCK_FILE_NAME);

    if !lock_path.exists() {
        tracing::info!("init lock file not exist, do init");
        let config_path = home_path.as_ref().join(INIT_FILE_NAME);
        let config = if config_path.exists() && config_path.is_file() {
            let config_raw = std::fs::read_to_string(&config_path).map_err(|e| {
                LdError::Boot(format!("failed to read init config {}: {e}", config_path.display()))
            })?;
            let init_config: InitConfig = toml::from_str(&config_raw).map_err(|e| {
                LdError::Boot(format!("failed to parse init config {}: {e}", config_path.display()))
            })?;
            check_init_config_version(&init_config)?;
            init_config
        } else {
            InitConfig::default()
        };

        return Ok(Some(config));
    }

    if lock_path.is_file() {
        tracing::info!("init lock file is exist, skip init");
        return Ok(None);
    }

    Err(LdError::Boot("check boot lock file faile: is not a file".to_string()))
}

pub fn check_init_config_version(init_config: &InitConfig) -> LdResult<()> {
    validate_init_config_version(init_config).map_err(|e| LdError::Boot(e.to_string()))
}

pub fn write_init_lock<P: AsRef<Path>>(home_path: P) -> LdResult<()> {
    let lock_path = home_path.as_ref().join(INIT_LOCK_FILE_NAME);
    let mut file = OpenOptions::new().write(true).truncate(true).create(true).open(&lock_path)?;
    file.write_all(INIT_LOCK_FILE_CONTENT.as_bytes())?;
    Ok(())
}

/// Init config backups are intentionally version-locked.
/// Files exported by the current release are only supported by the same release.
/// Older backups are rejected instead of being migrated implicitly.
pub fn validate_init_config_version(init_config: &InitConfig) -> Result<(), InitConfigError> {
    if init_config.version != VERSION {
        return Err(InitConfigError::VersionMismatch {
            file_version: init_config.version.clone(),
            current_version: VERSION.to_string(),
        });
    }

    Ok(())
}

pub fn write_config_toml<P: AsRef<Path>>(home_path: P, config: LandscapeConfig) -> LdResult<()> {
    let config_path = home_path.as_ref().join(LAND_CONFIG);
    let temp_path = home_path.as_ref().join(format!(
        ".{LAND_CONFIG}.tmp.{}.{}",
        std::process::id(),
        landscape_common::utils::time::get_f64_timestamp()
    ));
    let write_result = (|| -> LdResult<()> {
        let mut file =
            OpenOptions::new().write(true).truncate(true).create_new(true).open(&temp_path)?;
        file.write_all(toml::to_string_pretty(&config).unwrap().as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temp_path, &config_path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    write_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use landscape_common::{INIT_FILE_NAME, INIT_LOCK_FILE_NAME, LAND_CONFIG, VERSION};

    use crate::boot::{boot_check, write_config_toml, write_init_lock};

    #[test]
    fn boot_check_reads_init_config_without_writing_files_when_version_matches() {
        let temp_dir = tempfile::tempdir().unwrap();
        let init_path = temp_dir.path().join(INIT_FILE_NAME);
        std::fs::write(&init_path, format!("version = \"{VERSION}\"\n")).unwrap();

        let result = boot_check(temp_dir.path()).unwrap();

        assert!(result.is_some());
        assert!(!temp_dir.path().join(LAND_CONFIG).exists());
        assert!(!temp_dir.path().join(INIT_LOCK_FILE_NAME).exists());
    }

    #[test]
    fn boot_check_rejects_mismatched_init_version_without_lock() {
        let temp_dir = tempfile::tempdir().unwrap();
        let init_path = temp_dir.path().join(INIT_FILE_NAME);
        std::fs::write(&init_path, "version = \"0.0.0\"\n").unwrap();

        let result = boot_check(temp_dir.path());

        assert!(result.is_err());
        assert!(!temp_dir.path().join(LAND_CONFIG).exists());
        assert!(!temp_dir.path().join(INIT_LOCK_FILE_NAME).exists());
    }

    #[test]
    fn boot_check_rejects_invalid_init_config_without_panic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let init_path = temp_dir.path().join(INIT_FILE_NAME);
        std::fs::write(&init_path, "version = [\n").unwrap();

        let result = boot_check(temp_dir.path());

        assert!(result.is_err());
        assert!(!temp_dir.path().join(LAND_CONFIG).exists());
        assert!(!temp_dir.path().join(INIT_LOCK_FILE_NAME).exists());
    }

    #[test]
    fn boot_check_default_init_without_lock() {
        let temp_dir = tempfile::tempdir().unwrap();

        let result = boot_check(temp_dir.path()).unwrap();

        assert!(result.is_some());
        assert!(!temp_dir.path().join(LAND_CONFIG).exists());
        assert!(!temp_dir.path().join(INIT_LOCK_FILE_NAME).exists());
    }

    #[test]
    fn write_init_lock_creates_lock_file() {
        let temp_dir = tempfile::tempdir().unwrap();

        write_init_lock(temp_dir.path()).unwrap();

        assert!(temp_dir.path().join(INIT_LOCK_FILE_NAME).exists());
    }

    #[test]
    fn write_config_toml_writes_config_file() {
        let temp_dir = tempfile::tempdir().unwrap();

        write_config_toml(temp_dir.path(), Default::default()).unwrap();

        assert!(temp_dir.path().join(LAND_CONFIG).exists());
    }
}
