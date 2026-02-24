use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PullImageReq {
    pub image_name: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub tag: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PullImgTask {
    pub id: Uuid,
    pub img_name: String,
    pub complete: bool,
    pub layer_current_info: HashMap<String, PullImgTaskItem>,
}

#[derive(Default, Clone, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PullImgTaskItem {
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub current: Option<i64>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub total: Option<i64>,
}

#[derive(Clone, Serialize, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImgPullEvent {
    pub task_id: Uuid,
    pub img_name: String,
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub current: Option<i64>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub total: Option<i64>,
}
