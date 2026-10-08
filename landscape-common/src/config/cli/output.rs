use std::{
    io::Write,
    path::{Path, PathBuf},
};

use crate::{INIT_FILE_NAME, config::InitConfig, utils::time::get_f64_timestamp};

use super::{ConfigCliArgs, ConfigCliError};

/// Where the generated init config should go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigOutput {
    Stdout,
    File(PathBuf),
}

impl ConfigCliArgs {
    pub fn resolve_output(&self) -> ConfigOutput {
        if self.stdout {
            return ConfigOutput::Stdout;
        }
        let dir = self.dir.clone().unwrap_or_else(|| crate::args::LAND_HOME_PATH.clone());
        ConfigOutput::File(dir.join(INIT_FILE_NAME))
    }
}

/// Render the init config as pretty TOML.
pub fn render_init_config(config: &InitConfig) -> Result<String, ConfigCliError> {
    Ok(toml::to_string_pretty(config)?)
}

/// Write the init config as TOML, refusing to overwrite unless `force` is set.
pub fn write_init_config_file(
    path: &Path,
    content: &str,
    force: bool,
) -> Result<(), ConfigCliError> {
    if path.exists() && !force {
        return Err(ConfigCliError::AlreadyExists(path.display().to_string()));
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;

    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or(INIT_FILE_NAME);
    let tmp_path =
        dir.join(format!(".{file_name}.tmp.{}.{}", std::process::id(), get_f64_timestamp()));

    let result = (|| -> Result<(), ConfigCliError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// Run the `config` subcommand: build, render and output the init config.
///
/// Returns the written path, or `None` when printing to stdout.
pub fn run_config_cli(args: &ConfigCliArgs) -> Result<Option<PathBuf>, ConfigCliError> {
    let init_config = args.build_init_config()?;
    let content = render_init_config(&init_config)?;

    match args.resolve_output() {
        ConfigOutput::Stdout => {
            print!("{content}");
            Ok(None)
        }
        ConfigOutput::File(path) => {
            write_init_config_file(&path, &content, args.force)?;
            println!("{}", path.display());
            Ok(Some(path))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VERSION, config::InitConfig};

    fn base_args() -> ConfigCliArgs {
        ConfigCliArgs {
            wan_iface: Some("eth0".to_string()),
            lan_iface: Some("br_lan".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn rendered_toml_round_trips_into_init_config() {
        let mut args = base_args();
        args.lan_member = vec!["eth1".to_string()];
        let init = args.build_init_config().unwrap();
        let rendered = render_init_config(&init).unwrap();
        let parsed: InitConfig = toml::from_str(&rendered).unwrap();

        assert_eq!(parsed.version, VERSION);
        assert_eq!(parsed.ifaces.len(), 3);
        assert_eq!(parsed.wan_links.len(), 1);
        assert_eq!(parsed.dhcpv4_services.len(), 1);
    }

    #[test]
    fn write_refuses_existing_file_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INIT_FILE_NAME);
        std::fs::write(&path, "old").unwrap();

        let err = write_init_config_file(&path, "new", false).unwrap_err();
        assert!(matches!(err, ConfigCliError::AlreadyExists(_)));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
    }

    #[test]
    fn write_force_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INIT_FILE_NAME);
        std::fs::write(&path, "old").unwrap();

        write_init_config_file(&path, "new", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn resolve_output_honors_stdout_and_dir() {
        let mut args = ConfigCliArgs { stdout: true, ..Default::default() };
        assert_eq!(args.resolve_output(), ConfigOutput::Stdout);

        args.stdout = false;
        args.dir = Some(PathBuf::from("/tmp/landscape-test"));
        assert_eq!(
            args.resolve_output(),
            ConfigOutput::File(PathBuf::from("/tmp/landscape-test").join(INIT_FILE_NAME))
        );
    }
}
