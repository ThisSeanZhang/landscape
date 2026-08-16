use std::io;

use sea_orm::DbErr;

use crate::LdApiError;

/// Storage-layer error with HTTP semantics, ready to be exposed to the frontend.
///
/// Note: `Database(DbErr)`/`Io`/`Internal` may contain internal details such as
/// table/constraint names or file paths; use [`DbError::to_public_message`] for
/// the external message and log the full error server-side.
#[derive(Debug, thiserror::Error, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DbError {
    /// Optimistic-lock conflict: the config was modified by someone else, retry after refresh
    #[error("Configuration has been modified by others. Please refresh and try again.")]
    #[api_error(id = "config.conflict", status = 409)]
    Conflict,

    /// Underlying database error, internal details are not exposed
    #[error("Database error: {0}")]
    #[api_error(id = "database.error", status = 500)]
    Database(#[from] DbErr),

    #[error("I/O error occurred: {0}")]
    #[api_error(id = "internal.error", status = 500)]
    Io(#[from] io::Error),

    #[error("{0}")]
    #[api_error(id = "internal.error", status = 500)]
    Internal(String),
}

impl DbError {
    /// Public-safe message: sensitive details only go to the logs, the frontend gets a generic hint.
    pub fn to_public_message(&self) -> String {
        match self {
            DbError::Conflict => {
                "Configuration has been modified by others. Please refresh and try again."
                    .to_string()
            }
            DbError::Database(e) => {
                tracing::error!("database error: {e:?}");
                "Database operation failed, please try again later".to_string()
            }
            DbError::Io(e) => {
                tracing::error!("io error: {e:?}");
                "Internal error, please try again later".to_string()
            }
            DbError::Internal(e) => {
                tracing::error!("internal error: {e}");
                "Internal error, please try again later".to_string()
            }
        }
    }
}
