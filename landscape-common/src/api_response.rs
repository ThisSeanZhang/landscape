use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

#[derive(Debug, Serialize, Deserialize, Default, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/api.d.ts")]
pub struct LandscapeApiResp<T> {
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub error_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "Record<string, unknown>")]
    #[cfg_attr(feature = "openapi", schema(required = false, value_type = Object))]
    pub args: Option<Value>,
}

impl<T> LandscapeApiResp<T> {
    pub fn success(data: T) -> Self {
        Self {
            data: Some(data),
            error_id: None,
            message: None,
            args: None,
        }
    }

    pub fn error(error_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            data: None,
            error_id: Some(error_id.into()),
            message: Some(message.into()),
            args: None,
        }
    }

    pub fn error_with_args(
        error_id: impl Into<String>,
        message: impl Into<String>,
        args: Value,
    ) -> Self {
        let args = if args.as_object().map_or(true, |m| m.is_empty()) { None } else { Some(args) };
        Self {
            data: None,
            error_id: Some(error_id.into()),
            message: Some(message.into()),
            args,
        }
    }
}
