use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use clap::{arg, Parser};
use once_cell::sync::Lazy;

use crate::LANDSCAPE_CONFIG_DIR_NAME;

pub static LAND_HOSTNAME: Lazy<String> = Lazy::new(|| {
    let hostname = hostname::get().expect("无法获取主机名");
    hostname.to_string_lossy().to_string()
});

pub static LAND_ARGS: Lazy<WebCommArgs> = Lazy::new(WebCommArgs::parse);

pub static LAND_HOME_PATH: Lazy<PathBuf> = Lazy::new(|| {
    if let Some(path) = &LAND_ARGS.config_path {
        path.clone()
    } else {
        let Some(path) = homedir::my_home().unwrap() else {
            panic!("can not get home path");
        };
        path.join(LANDSCAPE_CONFIG_DIR_NAME)
    }
});

pub static LAND_WEB_ARGS: Lazy<WebConfig> = Lazy::new(|| {
    let web_root = if let Some(web_root) = &LAND_ARGS.web {
        web_root.clone()
    } else {
        LAND_HOME_PATH.join("static")
    };

    println!("web root is: {web_root:?}");
    println!("listen at: {:?}:{:?}", LAND_ARGS.address, LAND_ARGS.port);

    WebConfig {
        web_root,
        port: LAND_ARGS.port,
        address: LAND_ARGS.address,
    }
});

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct WebCommArgs {
    /// static html location
    #[arg(short, long)]
    pub web: Option<PathBuf>,

    /// listen port
    #[arg(short, long, default_value = "6300")]
    pub port: u16,

    /// listen address
    #[arg(short, long, default_value = "0.0.0.0")]
    pub address: IpAddr,

    /// Controls whether the WAN IP can be used to access the management interface
    #[arg(short, long, default_value = "true")]
    pub export_manager: bool,

    /// Developer Model
    #[arg(long, default_value = "false")]
    pub dev: bool,

    /// config home path
    /// By default, "/root/.landscape-router" is used
    #[clap(short, long)]
    pub config_path: Option<PathBuf>,

    /// ebpf map space
    #[clap(long, env = "LANDSCAPE_EBPF_MAP_SPACE", default_value = "default")]
    pub ebpf_map_space: String,

    /// manager user
    #[clap(long = "user", env = "LANDSCAPE_ADMIN_USER", default_value = "root")]
    pub admin_user: String,

    /// manager pass
    #[clap(long = "pass", env = "LANDSCAPE_ADMIN_PASS", default_value = "root")]
    pub admin_pass: String,
}

impl WebCommArgs {
    pub fn get_ipv4_listen(&self) -> Option<(Ipv4Addr, u16)> {
        match self.address {
            IpAddr::V4(ipv4_addr) => Some((ipv4_addr, self.port)),
            IpAddr::V6(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebConfig {
    pub web_root: PathBuf,

    pub port: u16,

    pub address: IpAddr,
}
