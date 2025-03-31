use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::net::MacAddr;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LandscapeDockerNetwork {
    // Name
    pub name: String,
    pub id: String,
    pub driver: Option<String>,
    pub containers: HashMap<String, LandscapeDockerNetworkContainer>,
    pub iface_name: String,
    pub options: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LandscapeDockerNetworkContainer {
    pub name: String,
    pub mac: Option<MacAddr>,
}
