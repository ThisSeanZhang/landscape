use std::collections::HashMap;
use std::fs::Permissions;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::{extract::Request, middleware::Next, response::Response};
use landscape_common::LANDSCAPE_SYS_TOKEN_FILE_ANME;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::args::LAND_HOME_PATH;
use landscape_common::auth::LoginInfo;
use landscape_common::auth::LoginResult;
use landscape_common::config::AuthRuntimeConfig;
use once_cell::sync::Lazy;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

use crate::api::JsonBody;
use crate::api::LandscapeApiResp;
use crate::auth::error::AuthError;
use crate::error::LandscapeApiError;
use crate::error::LandscapeApiResult;

pub mod error;

const SECRET_KEY_LENGTH: usize = 20;
const DEFAULT_EXPIRE_TIME: usize = 60 * 60;
const SYS_TOKEN_EXPIRE_TIME: usize = 60 * 60 * 24 * 365 * 30;

const LOGIN_MAX_FAILURES: u32 = 5;
const LOGIN_FAILURE_WINDOW: Duration = Duration::from_secs(300);
const LOGIN_BASE_BLOCK: Duration = Duration::from_secs(30);
const LOGIN_MAX_BLOCK: Duration = Duration::from_secs(900);
const LOGIN_LIMITER_MAX_ENTRIES: usize = 4096;

#[derive(Default)]
struct AttemptState {
    failures: u32,
    window_start: Option<Instant>,
    blocked_until: Option<Instant>,
}

#[derive(Default)]
struct LoginRateLimiter {
    entries: Mutex<HashMap<IpAddr, AttemptState>>,
}

impl LoginRateLimiter {
    fn check(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = entries.get_mut(&ip)
            && let Some(blocked_until) = state.blocked_until
        {
            if now < blocked_until {
                return Err(blocked_until.saturating_duration_since(now));
            }
            state.blocked_until = None;
            state.failures = 0;
            state.window_start = None;
        }
        Ok(())
    }

    fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= LOGIN_LIMITER_MAX_ENTRIES {
            entries.retain(|_, state| {
                state.blocked_until.is_some_and(|t| t > now)
                    || state
                        .window_start
                        .is_some_and(|t| now.saturating_duration_since(t) < LOGIN_FAILURE_WINDOW)
            });
        }

        let state = entries.entry(ip).or_default();
        let window_active = state
            .window_start
            .is_some_and(|t| now.saturating_duration_since(t) < LOGIN_FAILURE_WINDOW);
        if !window_active {
            state.window_start = Some(now);
            state.failures = 0;
        }

        state.failures = state.failures.saturating_add(1);
        if state.failures >= LOGIN_MAX_FAILURES {
            let over = state.failures - LOGIN_MAX_FAILURES;
            let factor = 1u32 << over.min(5);
            let block = LOGIN_BASE_BLOCK.saturating_mul(factor).min(LOGIN_MAX_BLOCK);
            state.blocked_until = Some(now + block);
        }
    }

    fn record_success(&self, ip: IpAddr) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.remove(&ip);
    }
}

static LOGIN_LIMITER: Lazy<LoginRateLimiter> = Lazy::new(LoginRateLimiter::default);

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
    file.write_all(sys_token.as_bytes()).await.expect("Failed to write system token");
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
    State(auth): State<Arc<ArcSwap<AuthRuntimeConfig>>>,
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

    if token_data.claims.sub == auth.load().admin_user {
        let mut response = next.run(req).await;

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        if token_data.claims.exp.saturating_sub(now) < DEFAULT_EXPIRE_TIME / 2
            && let Ok(new_token) = create_jwt(&token_data.claims.sub, DEFAULT_EXPIRE_TIME)
            && let Ok(value) = axum::http::HeaderValue::from_str(&new_token)
        {
            response.headers_mut().insert("X-Refresh-Token", value);
            response.headers_mut().append(
                axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
                axum::http::HeaderValue::from_static("X-Refresh-Token"),
            );
        }

        Ok(response)
    } else {
        Err(AuthError::UnauthorizedUser)?
    }
}

pub async fn auth_handler_from_query(
    State(auth): State<Arc<ArcSwap<AuthRuntimeConfig>>>,
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

    if token_data.claims.sub == auth.load().admin_user {
        Ok(next.run(req).await)
    } else {
        Err(AuthError::UnauthorizedUser)?
    }
}

/// Build the OpenApiRouter for auth (different state type from LandscapeApp).
/// Used by openapi.rs to extract the spec, and by main.rs to serve.
pub fn get_auth_openapi_router() -> OpenApiRouter<Arc<ArcSwap<AuthRuntimeConfig>>> {
    OpenApiRouter::new().routes(routes!(login_handler))
}

pub fn get_auth_route(auth: Arc<ArcSwap<AuthRuntimeConfig>>) -> Router {
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
        (status = 200, description = "Success", body = CommonApiResp<LoginResult>),
        (status = 401, description = "Invalid credentials"),
        (status = 429, description = "Too many login attempts")
    )
)]
async fn login_handler(
    State(auth): State<Arc<ArcSwap<AuthRuntimeConfig>>>,
    connect_info: ConnectInfo<SocketAddr>,
    JsonBody(LoginInfo { username, password }): JsonBody<LoginInfo>,
) -> LandscapeApiResult<LoginResult> {
    let client_ip = connect_info.0.ip();
    let now = Instant::now();
    if LOGIN_LIMITER.check(client_ip, now).is_err() {
        return Err(AuthError::TooManyAttempts.into());
    }

    let auth_config = auth.load();
    let user_ok = username.as_bytes().ct_eq(auth_config.admin_user.as_bytes());
    let pass_ok = password.as_bytes().ct_eq(auth_config.admin_pass.as_bytes());

    if bool::from(user_ok & pass_ok) {
        LOGIN_LIMITER.record_success(client_ip);
        let token = create_jwt(&username, DEFAULT_EXPIRE_TIME)?;
        LandscapeApiResp::success(LoginResult { success: true, token })
    } else {
        LOGIN_LIMITER.record_failure(client_ip, now);
        Err(AuthError::InvalidUsernameOrPassword.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
    }

    #[test]
    fn allows_attempts_below_threshold() {
        let limiter = LoginRateLimiter::default();
        let ip = ip(1);
        let now = Instant::now();
        for _ in 0..LOGIN_MAX_FAILURES - 1 {
            assert!(limiter.check(ip, now).is_ok());
            limiter.record_failure(ip, now);
        }
        assert!(limiter.check(ip, now).is_ok());
    }

    #[test]
    fn blocks_after_threshold_and_recovers() {
        let limiter = LoginRateLimiter::default();
        let ip = ip(2);
        let now = Instant::now();
        for _ in 0..LOGIN_MAX_FAILURES {
            limiter.record_failure(ip, now);
        }
        let remaining = limiter.check(ip, now).unwrap_err();
        assert!(remaining > Duration::ZERO);
        assert!(limiter.check(ip, now + LOGIN_BASE_BLOCK).is_ok());
    }

    #[test]
    fn success_clears_failures() {
        let limiter = LoginRateLimiter::default();
        let ip = ip(3);
        let now = Instant::now();
        for _ in 0..LOGIN_MAX_FAILURES - 1 {
            limiter.record_failure(ip, now);
        }
        limiter.record_success(ip);
        for _ in 0..LOGIN_MAX_FAILURES - 1 {
            limiter.record_failure(ip, now);
        }
        assert!(limiter.check(ip, now).is_ok());
    }

    #[test]
    fn backoff_grows_with_repeated_lockouts() {
        let limiter = LoginRateLimiter::default();
        let ip = ip(4);
        let now = Instant::now();
        for _ in 0..LOGIN_MAX_FAILURES {
            limiter.record_failure(ip, now);
        }
        let first = limiter.check(ip, now).unwrap_err();
        limiter.record_failure(ip, now);
        let second = limiter.check(ip, now).unwrap_err();
        assert!(second > first);
    }

    #[test]
    fn different_ips_are_independent() {
        let limiter = LoginRateLimiter::default();
        let now = Instant::now();
        for _ in 0..LOGIN_MAX_FAILURES {
            limiter.record_failure(ip(5), now);
        }
        assert!(limiter.check(ip(5), now).is_err());
        assert!(limiter.check(ip(6), now).is_ok());
    }
}
