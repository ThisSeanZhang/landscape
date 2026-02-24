use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use axum::extract::State;
use axum::Router;
use axum::{extract::Request, middleware::Next, response::Response};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::args::LAND_HOME_PATH;
use landscape_common::auth::LoginInfo;
use landscape_common::auth::LoginResult;
use landscape_common::config::AuthRuntimeConfig;
use landscape_common::LANDSCAPE_SYS_TOKEN_FILE_ANME;
use once_cell::sync::Lazy;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

use crate::api::JsonBody;
use crate::api::LandscapeApiResp;
use crate::auth::error::AuthError;
use crate::error::LandscapeApiError;
use crate::error::LandscapeApiResult;

pub mod error;

const SECRET_KEY_LENGTH: usize = 20;
const DEFAULT_EXPIRE_TIME: usize = 60 * 60 * 1;
const SYS_TOKEN_EXPIRE_TIME: usize = 60 * 60 * 24 * 365 * 30;

pub static SECRET_KEY: Lazy<String> = Lazy::new(|| {
    //
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(SECRET_KEY_LENGTH)
        .map(char::from)
        .collect()
});

pub async fn output_sys_token(auth: &AuthRuntimeConfig) {
    let token_path = LAND_HOME_PATH.join(LANDSCAPE_SYS_TOKEN_FILE_ANME);
    // 生成长期有效的系统 token
    let sys_token =
        create_jwt(&auth.admin_user, SYS_TOKEN_EXPIRE_TIME).expect("Failed to create system token");

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(token_path)
        .await
        .expect("Failed to open landscape_api_token");

    // 写入系统 token
    file.write(sys_token.as_bytes()).await.expect("Failed to write system token");
    file.flush().await.expect("Failed to flush system token");
    // 设置文件权限为 0o400（仅文件所有者可读）
    let perms = Permissions::from_mode(0o400);
    file.set_permissions(perms).await.expect("Failed to set file permissions");
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    // 用户ID或标识
    sub: String,
    // 过期时间（Unix timestamp）
    exp: usize,
}

fn create_jwt(user_id: &str, expiration: usize) -> Result<String, AuthError> {
    // 设置过期时间
    let expiration =
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize + expiration;
    let claims = Claims { sub: user_id.to_owned(), exp: expiration };
    // 使用一个足够复杂的密钥来签名
    Ok(encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET_KEY.as_bytes()))?)
}

pub async fn auth_handler(
    State(auth): State<Arc<AuthRuntimeConfig>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, LandscapeApiError> {
    let Some(auth_header) =
        req.headers().get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok())
    else {
        return Err(AuthError::MissingAuthorizationHeader)?;
    };

    let Some(token) = auth_header.strip_prefix("Bearer ") else {
        return Err(AuthError::InvalidAuthorizationHeaderFormat)?;
    };

    let Ok(token_data) = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET_KEY.as_bytes()),
        &Validation::default(),
    ) else {
        return Err(AuthError::InvalidToken)?;
    };

    if token_data.claims.sub == auth.admin_user {
        let mut response = next.run(req).await;

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        if token_data.claims.exp.saturating_sub(now) < DEFAULT_EXPIRE_TIME / 2 {
            if let Ok(new_token) = create_jwt(&token_data.claims.sub, DEFAULT_EXPIRE_TIME) {
                if let Ok(value) = axum::http::HeaderValue::from_str(&new_token) {
                    response.headers_mut().insert("X-Refresh-Token", value);
                    response.headers_mut().append(
                        axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
                        axum::http::HeaderValue::from_static("X-Refresh-Token"),
                    );
                }
            }
        }

        Ok(response)
    } else {
        Err(AuthError::UnauthorizedUser)?
    }
}

pub async fn auth_handler_from_query(
    State(auth): State<Arc<AuthRuntimeConfig>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, LandscapeApiError> {
    let Some(query_str) = req.uri().query() else {
        return Err(AuthError::MissingAuthorizationHeader)?;
    };

    let Some((_, token)) =
        query_str.split('&').filter_map(|q| q.split_once('=')).find(|(k, _)| k == &"token")
    else {
        return Err(AuthError::MissingAuthorizationHeader)?;
    };

    let Ok(token_data) = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET_KEY.as_bytes()),
        &Validation::default(),
    ) else {
        return Err(AuthError::InvalidToken)?;
    };

    if token_data.claims.sub == auth.admin_user {
        Ok(next.run(req).await)
    } else {
        Err(AuthError::UnauthorizedUser)?
    }
}

/// Build the OpenApiRouter for auth (different state type from LandscapeApp).
/// Used by openapi.rs to extract the spec, and by main.rs to serve.
pub fn get_auth_openapi_router() -> OpenApiRouter<Arc<AuthRuntimeConfig>> {
    OpenApiRouter::new().routes(routes!(login_handler))
}

pub fn get_auth_route(auth: Arc<AuthRuntimeConfig>) -> Router {
    let (router, _) = get_auth_openapi_router().split_for_parts();
    router.with_state(auth)
}

#[utoipa::path(
    post,
    path = "/login",
    tag = "Auth",
    security(()),
    request_body = LoginInfo,
    responses(
        (status = 200, body = CommonApiResp<LoginResult>),
        (status = 401, description = "Invalid credentials")
    )
)]
async fn login_handler(
    State(auth): State<Arc<AuthRuntimeConfig>>,
    JsonBody(LoginInfo { username, password }): JsonBody<LoginInfo>,
) -> LandscapeApiResult<LoginResult> {
    let mut result = LoginResult { success: false, token: "".to_string() };
    if username == auth.admin_user && password == auth.admin_pass {
        result.success = true;
        result.token = create_jwt(&username, DEFAULT_EXPIRE_TIME)?;
    } else {
        return Err(AuthError::InvalidUsernameOrPassword)?;
    }
    LandscapeApiResp::success(result)
}
