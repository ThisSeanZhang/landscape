use axum::extract::State;
use landscape_common::auth::ChangePasswordRequest;

use crate::api::{JsonBody, LandscapeApiResp};
use crate::auth::error::AuthError;
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

/// Password complexity: >= 8 chars, at least one lowercase, one uppercase, one digit.
fn validate_password_complexity(password: &str) -> bool {
    password.len() >= 8
        && password.chars().any(|c| c.is_ascii_lowercase())
        && password.chars().any(|c| c.is_ascii_uppercase())
        && password.chars().any(|c| c.is_ascii_digit())
}

#[utoipa::path(
    post,
    path = "/config/edit/auth",
    tag = "System Config",
    operation_id = "change_password",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed successfully"),
        (status = 400, description = "Validation error")
    )
)]
pub async fn update_auth_config(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<ChangePasswordRequest>,
) -> LandscapeApiResult<()> {
    // 1. Verify current password
    if req.current_password.is_empty() {
        return Err(AuthError::CurrentPasswordIncorrect.into());
    }
    let current_auth = state.config_service.get_auth_config();
    if req.current_password != current_auth.admin_pass {
        return Err(AuthError::CurrentPasswordIncorrect.into());
    }

    // 2. Confirm password must match
    if req.new_password != req.confirm_password {
        return Err(AuthError::PasswordMismatch.into());
    }

    // 3. Password complexity
    if !validate_password_complexity(&req.new_password) {
        return Err(AuthError::PasswordTooWeak.into());
    }

    // 4. New password must differ from current
    if req.new_password == req.current_password {
        return Err(AuthError::SamePassword.into());
    }

    // 5. Persist
    state.config_service.update_auth_password(req.new_password.clone()).await?;

    // 6. Update the shared auth config so middleware/login see the new password immediately
    state.auth.rcu(|old| {
        let mut new_auth = (**old).clone();
        new_auth.admin_pass = req.new_password.clone();
        new_auth
    });

    LandscapeApiResp::success(())
}
