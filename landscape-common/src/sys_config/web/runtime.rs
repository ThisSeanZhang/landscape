use std::{net::IpAddr, path::PathBuf};

#[derive(Clone, Debug)]
pub struct WebRuntimeConfig {
    pub web_root: PathBuf,
    pub port: u16,
    pub https_port: u16,
    pub address: IpAddr,
}
