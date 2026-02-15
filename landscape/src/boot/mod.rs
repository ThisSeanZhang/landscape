use std::{fs::OpenOptions, io::Write, path::Path};

use landscape_common::{
    config::{InitConfig, LandscapeConfig},
    error::{LdError, LdResult},
    INIT_FILE_NAME, INIT_LOCK_FILE_NAME, LAND_CONFIG,
};

pub mod log;

const INIT_LOCK_FILE_CONTENT: &'static str = r#"⚠ 警告 ⚠
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
        let mut file =
            OpenOptions::new().write(true).truncate(true).create(true).open(&lock_path)?;
        file.write_all(INIT_LOCK_FILE_CONTENT.as_bytes())?;

        drop(file);
        let config_path = home_path.as_ref().join(INIT_FILE_NAME);
        let config = if config_path.exists() && config_path.is_file() {
            let config_raw = std::fs::read_to_string(config_path).unwrap();
            let init_config: InitConfig = toml::from_str(&config_raw).unwrap();
            write_config_toml(home_path, init_config.config.clone())?;
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

fn write_config_toml<P: AsRef<Path>>(home_path: P, config: LandscapeConfig) -> LdResult<()> {
    let config_path = home_path.as_ref().join(LAND_CONFIG);
    let mut file = OpenOptions::new().write(true).truncate(true).create(true).open(&config_path)?;
    file.write_all(toml::to_string_pretty(&config).unwrap().as_bytes())?;
    Ok(())
}
