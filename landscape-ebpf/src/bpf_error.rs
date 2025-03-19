use thiserror::Error;

#[derive(Debug, Error)]
pub enum LandscapeEbpfError {
    #[error("libbpf error: {0}")]
    Libbpf(#[from] libbpf_rs::Error),
}

pub type LdEbpfResult<T> = Result<T, LandscapeEbpfError>;
