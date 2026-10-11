use std::{net::IpAddr, path::PathBuf};

use clap::{Parser, Subcommand};
use once_cell::sync::Lazy;

use crate::LANDSCAPE_CONFIG_DIR_NAME;

pub static LAND_HOSTNAME: Lazy<String> = Lazy::new(|| {
    let hostname = hostname::get().expect("无法获取主机名");
    hostname.to_string_lossy().to_string()
});

pub static LAND_ARGS: Lazy<WebCommArgs> = Lazy::new(|| {
    dotenvy::dotenv().ok();
    if std::env::var_os("LANDSCAPE_IGNORE_CLI_ARGS").is_some() || running_under_test_harness() {
        // Test/embedded use: ignore the real argv (test harness filters etc.)
        // and parse from nothing, so env vars and defaults still apply.
        WebCommArgs::try_parse_from(std::iter::empty::<String>()).unwrap_or_default()
    } else {
        WebCommArgs::parse()
    }
});

/// Cargo compiles unit/integration test binaries as `<crate>-<hash>` inside a
/// `deps/` directory, and their argv belongs to the libtest harness (test
/// filters like `geo::`, flags like `--nocapture`), not to [`WebCommArgs`];
/// parsing it would make clap abort the whole test run.
fn running_under_test_harness() -> bool {
    std::env::current_exe().map(|exe| looks_like_test_binary(&exe)).unwrap_or(false)
}

fn looks_like_test_binary(exe: &std::path::Path) -> bool {
    if exe.parent().and_then(|p| p.file_name()) != Some(std::ffi::OsStr::new("deps")) {
        return false;
    }
    let Some(name) = exe.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    match name.split_once('-') {
        Some((_, hash)) => hash.len() >= 8 && hash.chars().all(|c| c.is_ascii_hexdigit()),
        None => false,
    }
}

pub static LAND_HOME_PATH: Lazy<PathBuf> = Lazy::new(|| {
    if let Some(path) = &LAND_ARGS.config_dir {
        path.clone()
    } else {
        let Some(path) = homedir::my_home().unwrap() else {
            panic!("can not get home path");
        };
        path.join(LANDSCAPE_CONFIG_DIR_NAME)
    }
});

#[derive(Parser, Debug, Clone, Default)]
#[command(version, about, long_about = None)]
pub struct WebCommArgs {
    /// Static HTML location [default: /root/.landscape-router/static]
    #[arg(short, long, env = "LANDSCAPE_WEB_ROOT")]
    pub web: Option<PathBuf>,

    /// Listen HTTP port [default: 6300]
    #[arg(short, long, env = "LANDSCAPE_WEB_HTTP_PORT")]
    pub port: Option<u16>,

    /// Listen HTTPS port [default: 6443]
    #[arg(short = 's', long = "https", env = "LANDSCAPE_WEB_HTTPS_PORT")]
    pub https_port: Option<u16>,

    /// Listen address [default: 0.0.0.0]
    #[arg(short, long, env = "LANDSCAPE_WEB_ADDR")]
    pub address: Option<IpAddr>,

    /// Controls whether the WAN IP can be used to access the management interface [default: false]
    #[arg(short, long)]
    pub export_manager: bool,

    /// All Config DIR, Not file Path [default: /root/.landscape-router]
    #[clap(short, long, env = "LANDSCAPE_CONF_PATH")]
    pub config_dir: Option<PathBuf>,

    /// Log File location [default: /root/.landscape-router/logs]
    #[clap(long = "log_path", env = "LANDSCAPE_LOG_PATH")]
    pub log_path: Option<PathBuf>,

    /// Database URL, SQLite Connect Like Default
    /// sqlite://<path>
    /// [default: sqlite:///root/.landscape-router/landscape_db.sqlite]
    #[clap(long = "db_url", env = "DATABASE_URL")]
    pub database_path: Option<String>,

    /// ebpf map space
    /// [default: default]
    #[clap(long, env = "LANDSCAPE_EBPF_MAP_SPACE", default_value = "default")]
    pub ebpf_map_space: String,

    /// Manager user [default: root]
    #[clap(long = "user", env = "LANDSCAPE_ADMIN_USER")]
    pub admin_user: Option<String>,

    /// Manager pass [default: root]
    #[clap(long = "pass", env = "LANDSCAPE_ADMIN_PASS")]
    pub admin_pass: Option<String>,

    /// Debug mode [default: false]
    #[arg(long, env = "LANDSCAPE_DEBUG")]
    pub debug: Option<bool>,

    /// Try native XDP attach. By default, only TC (SKB) mode is used.
    /// If specified without values, attempts native XDP on all interfaces.
    /// Specify comma-separated ifindex list to try native XDP only on those interfaces (e.g., 3,5).
    #[arg(long = "try-xdp", visible_alias = "txdp", value_delimiter = ',', num_args = 0..)]
    pub try_native_xdp: Option<Vec<i32>>,

    /// Log output location [default: false]
    #[arg(short = 'o', long, env = "LANDSCAPE_LOG_TERMINAL")]
    pub log_output_in_terminal: Option<bool>,

    /// Max log files number
    /// [default: 7]
    #[arg(long, env = "LANDSCAPE_LOG_FILE_LIMIT")]
    pub max_log_files: Option<usize>,

    /// Log keyword filter: comma-separated list of keywords
    /// When specified, only ERROR/WARN logs and logs containing any keyword are shown
    /// [example: --log-filter dhcp,dns,firewall]
    #[arg(long, value_delimiter = ',', env = "LANDSCAPE_LOG_FILTER")]
    pub log_filter: Vec<String>,

    /// Auto init Default Net [default: false]
    #[arg(long, env = "LANDSCAPE_AUTO")]
    pub auto: bool,

    #[command(subcommand)]
    pub action: Option<LandscapeAction>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum LandscapeAction {
    /// Database-related operations
    Db {
        #[command(subcommand)]
        action: Option<DbAction>,

        #[arg(short, long, hide = true)]
        rollback: bool,

        #[clap(short = 't', long, hide = true)]
        times: Option<u32>,
    },

    /// Generate a landscape_init.toml from high-level deployment options
    Config(Box<crate::config::cli::ConfigCliArgs>),
}

#[derive(Subcommand, Debug, Clone)]
pub enum DbAction {
    /// Interactively roll back the database to a registered release boundary
    #[command(visible_alias = "rb")]
    Rollback,
}

#[derive(Debug, Clone)]
pub struct WebConfig {
    pub web_root: PathBuf,

    pub port: u16,

    pub address: IpAddr,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub log_path: PathBuf,
    pub debug: bool,
    pub log_output_in_terminal: bool,
    pub max_log_files: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_cargo_test_binaries() {
        assert!(looks_like_test_binary(Path::new(
            "/project/target/debug/deps/landscape-0808d1757e8bfc10"
        )));
        assert!(looks_like_test_binary(Path::new(
            "/project/target/release/deps/landscape_common-abcdef1234567890"
        )));
    }

    #[test]
    fn rejects_non_test_binaries() {
        assert!(!looks_like_test_binary(Path::new("/project/target/debug/landscape-webserver")));
        assert!(!looks_like_test_binary(Path::new(
            "/project/target/debug/examples/demo-0123456789abcdef"
        )));
        assert!(!looks_like_test_binary(Path::new(
            "/project/target/debug/deps/landscape-webserver"
        )));
        assert!(!looks_like_test_binary(Path::new("/project/target/debug/deps/landscape")));
    }
}
