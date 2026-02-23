use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use landscape_common::api_response::LandscapeApiResp as CommonLandscapeApiResp;
use serde::Serialize;

use crate::error::LandscapeApiError;

#[derive(Debug, Serialize, Default, Clone)]
pub struct LandscapeApiResp<T>(pub CommonLandscapeApiResp<T>);

impl<T> LandscapeApiResp<T> {
    pub fn success(data: T) -> Result<LandscapeApiResp<T>, LandscapeApiError> {
        Ok(Self(CommonLandscapeApiResp::success(data)))
    }
}

impl<T: Serialize> IntoResponse for LandscapeApiResp<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self.0)).into_response()
    }
}
