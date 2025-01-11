use std::{net::IpAddr, path::PathBuf};

use clap::{arg, Parser};
use once_cell::sync::Lazy;

pub static LAND_ARGS: Lazy<WebCommArgs> = Lazy::new(WebCommArgs::parse);

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct WebCommArgs {
    /// static html location
    #[arg(short, long, default_value = "./static")]
    pub web: PathBuf,

    /// listen port
    #[arg(short, long, default_value = "6300")]
    pub port: u16,

    /// listen address
    #[arg(short, long, default_value = "0.0.0.0")]
    pub address: IpAddr,
}
