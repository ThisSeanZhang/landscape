// use std::path::PathBuf;
// use toml_edit::DocumentMut;

// use crate::{args::LAND_HOME_PATH, LAND_CONFIG};

// pub struct SysConfig {
//     pub geosite_url: String,
//     pub geoip_url: String,
// }
// pub fn read_geo_site_url() -> String {
//     let config_path = LAND_HOME_PATH.join(LAND_CONFIG);

//     let config = if config_path.exists() && config_path.is_file() {
//         let config_raw = std::fs::read_to_string(config_path).unwrap();
//         let doc = config_raw.parse::<DocumentMut>().expect("invalid doc");
//         doc["geosite_url"].to_string()
//     } else {
//         "".to_string()
//     };
//     todo!()
// }
