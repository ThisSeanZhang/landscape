use std::path::PathBuf;
use std::{fs::OpenOptions, io::Write};

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::database::repository::LandscapeDBStore;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ppp.d.ts")]
pub struct PPPDServiceConfig {
    pub attach_iface_name: String,
    pub iface_name: String,
    pub enable: bool,
    pub pppd_config: PPPDConfig,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub update_at: f64,
}

impl LandscapeStore for PPPDServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for PPPDServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ppp.d.ts")]
pub struct PPPDConfig {
    pub default_route: bool,
    pub peer_id: String,
    pub password: String,
    pub ac: Option<String>,
}

impl PPPDConfig {
    pub fn delete_config(&self, ppp_iface_name: &str) {
        let _ = std::fs::remove_file(format!("/etc/ppp/peers/{}", ppp_iface_name));
    }

    pub fn write_config(&self, attach_iface_name: &str, ppp_iface_name: &str) -> Result<(), ()> {
        // 检查 PPP 文件目录是否存在, 不存在提示用户安装 ppp
        let path = PathBuf::from("/etc/ppp/peers");
        if !path.exists() {
            tracing::error!("The directory /etc/ppp/peers does not exist, please check whether ppp is installed");
            return Err(());
        }

        // 打开文件（如果文件不存在则创建）
        let Ok(mut file) = OpenOptions::new()
            .write(true) // 打开文件以进行写入
            .truncate(true) // 文件存在时会被截断
            .create(true) // 如果文件不存在，则会创建
            .open(format!("/etc/ppp/peers/{}", ppp_iface_name))
        else {
            tracing::error!("Error opening file handle");
            return Err(());
        };

        let ac_line = self
            .ac
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|ac| format!("pppoe-ac \"{}\"\n", ac))
            .unwrap_or_default();

        let config = format!(
            r#"
# 此文件每次启动 pppd 都会被复写, 所以修改此文件不会有任何效果, 仅作为检查启动配置
# This file is truncated each time pppd is started, so editing this file has no effect.
noipdefault
hide-password
lcp-echo-interval 30
lcp-echo-failure 4
noauth
persist
#mtu 1492
maxfail 1
#holdoff 20
plugin rp-pppoe.so
nic-{ifacename}
{ac_line}
user "{user}"
password "{pass}"
ifname {ppp_iface_name}
"#,
            ifacename = attach_iface_name,
            ac_line = ac_line,
            user = self.peer_id,
            pass = self.password,
            ppp_iface_name = ppp_iface_name
        );
        let Ok(_) = file.write_all(config.as_bytes()) else {
            tracing::error!("Error writing configuration file bytes");
            return Err(());
        };

        Ok(())
    }
}
