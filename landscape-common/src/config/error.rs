use landscape_macro::LdApiError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum InitConfigError {
    #[error("Init config file not found in upload")]
    #[api_error(id = "init_config.file_not_found", status = 400)]
    FileNotFound,

    #[error("Init config file read error")]
    #[api_error(id = "init_config.file_read_error", status = 400)]
    FileReadError,

    #[error("Invalid init config: {reason}")]
    #[api_error(id = "init_config.invalid", status = 400)]
    Invalid { reason: String },

    #[error(
        "Init config version mismatch: file version {file_version}, current version {current_version}"
    )]
    #[api_error(id = "init_config.version_mismatch", status = 409)]
    VersionMismatch { file_version: String, current_version: String },
}
