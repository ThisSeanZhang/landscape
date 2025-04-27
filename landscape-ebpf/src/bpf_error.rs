use thiserror::Error;

#[derive(Debug, Error)]
pub enum LandscapeEbpfError {
    #[error("libbpf error: {0}")]
    Libbpf(#[from] libbpf_rs::Error),

    #[error("parse ID Error")]
    ParseIdErr,

    #[error("parse ID Error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
}

pub type LdEbpfResult<T> = Result<T, LandscapeEbpfError>;
