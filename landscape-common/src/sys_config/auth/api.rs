use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Debug, thiserror::Error, landscape_macro::LdApiError)]
#[api_error(crate_path = "crate")]
pub enum PasswordChangeError {
    #[error("Current password is incorrect")]
    #[api_error(id = "auth.current_password_incorrect", status = 400)]
    CurrentPasswordIncorrect,

    #[error("New password does not meet complexity requirements")]
    #[api_error(id = "auth.password_too_weak", status = 400)]
    PasswordTooWeak,

    #[error("New password and confirm password do not match")]
    #[api_error(id = "auth.password_mismatch", status = 400)]
    PasswordMismatch,

    #[error("New password cannot be the same as current password")]
    #[api_error(id = "auth.password_same_as_old", status = 400)]
    SamePassword,
}

impl ChangePasswordRequest {
    pub fn validate(&self, current: &str) -> Result<(), PasswordChangeError> {
        use subtle::ConstantTimeEq;
        if self.current_password.is_empty()
            || !bool::from(self.current_password.as_bytes().ct_eq(current.as_bytes()))
        {
            return Err(PasswordChangeError::CurrentPasswordIncorrect);
        }
        if self.new_password != self.confirm_password {
            return Err(PasswordChangeError::PasswordMismatch);
        }
        let password = self.new_password.as_bytes();
        if password.len() < 8
            || !password.iter().any(u8::is_ascii_lowercase)
            || !password.iter().any(u8::is_ascii_uppercase)
            || !password.iter().any(u8::is_ascii_digit)
        {
            return Err(PasswordChangeError::PasswordTooWeak);
        }
        if self.new_password == self.current_password {
            return Err(PasswordChangeError::SamePassword);
        }
        Ok(())
    }
}
