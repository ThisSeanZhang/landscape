use axum::{http::StatusCode, response::IntoResponse};

#[derive(thiserror::Error, Debug)]
pub enum LandscapeApiError {
    #[error("`{0}` not found")]
    NotFound(String),
    #[error("Failed to parse configuration: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("IO error occurred: {0}")]
    IoError(#[from] std::io::Error),
}

impl IntoResponse for LandscapeApiError {
    fn into_response(self) -> axum::response::Response {
        let msg = self.to_string();

        let code = match self {
            LandscapeApiError::NotFound(_) => StatusCode::NOT_FOUND,
            LandscapeApiError::JsonParseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            LandscapeApiError::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = axum::Json(serde_json::json!({ "error": msg}));
        (code, body).into_response()
    }
}

pub type LandscapeResult<T> = Result<T, LandscapeApiError>;
