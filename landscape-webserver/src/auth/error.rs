use landscape_common::LdApiError;

#[derive(Debug, thiserror::Error, LdApiError)]
pub enum AuthError {
    #[error("Missing Authorization header")]
    #[api_error(id = "auth.missing_header", status = 401)]
    MissingAuthorizationHeader,

    #[error("Invalid Authorization header format")]
    #[api_error(id = "auth.invalid_format", status = 401)]
    InvalidAuthorizationHeaderFormat,

    #[error("Invalid token")]
    #[api_error(id = "auth.invalid_token", status = 401)]
    InvalidToken,

    #[error("Unauthorized user")]
    #[api_error(id = "auth.unauthorized", status = 401)]
    UnauthorizedUser,

    #[error("Invalid username or password")]
    #[api_error(id = "auth.invalid_credentials", status = 401)]
    InvalidUsernameOrPassword,

    #[error("Token creation failed: {0}")]
    #[api_error(id = "auth.token_creation_failed", status = 500)]
    JwtCreationFailed(#[from] jsonwebtoken::errors::Error),
}
