use sea_orm::DbErr;
use thiserror::Error;

use crate::error::pty::PtyError;

pub mod pty;

/// 仅定义当前 common 错误
#[derive(Error, Debug)]
pub enum LdError {
    #[error("Lnadscape boot error: {0}")]
    Boot(String),
    // OpenFileError
    #[error("I/O error occurred: {0}")]
    Io(#[from] std::io::Error),

    #[error("homedir error occurred: {0}")]
    HomeError(#[from] homedir::GetHomeError),

    #[error("setting cpu balance error: {0}")]
    SettingCpuBalanceError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] DbErr),

    #[error("data is expired")]
    DataIsExpired,

    #[error("Database error: {0}")]
    DbMsg(String),

    #[error(transparent)]
    PtyError(#[from] PtyError),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Configuration has been modified by others. Please refresh and try again.")]
    ConfigConflict,
}

pub type LdResult<T> = Result<T, LdError>;

/// All domain errors implement this trait to provide error_id and HTTP status code.
pub trait LdApiErrorInfo {
    fn error_id(&self) -> &'static str;
    fn http_status_code(&self) -> u16;
    fn error_args(&self) -> serde_json::Value {
        serde_json::json!({})
    }
}
