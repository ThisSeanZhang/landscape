use thiserror::Error;

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
}

pub type LdResult<T> = Result<T, LdError>;
