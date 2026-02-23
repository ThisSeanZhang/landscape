use axum::{
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use landscape_common::api_response::LandscapeApiResp as CommonLandscapeApiResp;
use serde::{de::DeserializeOwned, Serialize};

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

/// Custom JSON extractor that converts deserialization errors into
/// `LandscapeApiError` so the response is always JSON.
pub struct JsonBody<T>(pub T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = LandscapeApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(JsonBody(value)),
            Err(rejection) => Err(LandscapeApiError::JsonRejection(rejection)),
        }
    }
}
