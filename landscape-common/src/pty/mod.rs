use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    On,
    Exited(u32),
    Error(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapePtySize {
    pub rows: u16,
    pub cols: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl Default for LandscapePtySize {
    fn default() -> Self {
        Self {
            rows: 80,
            cols: 20,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapePtyConfig {
    #[serde(flatten)]
    pub size: LandscapePtySize,
    pub shell: String,
}

impl Default for LandscapePtyConfig {
    fn default() -> Self {
        Self {
            shell: "bash".to_string(),
            size: Default::default(),
        }
    }
}

pub struct SessionChannel {
    pub out_events: broadcast::Receiver<PtyOutMessage>,
    pub input_events: mpsc::Sender<PtyInMessage>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum PtyInMessage {
    Size {
        size: LandscapePtySize,
    },
    Data {
        #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
        data: Box<Vec<u8>>,
    },
    Exit,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum PtyOutMessage {
    Data {
        #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
        data: Box<Vec<u8>>,
    },
    Exit {
        msg: String,
    },
}
