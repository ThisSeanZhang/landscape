use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LandscapeEbpfError {
    #[error("libbpf error: {0}")]
    Libbpf(#[from] libbpf_rs::Error),

    #[error("{context}: {source}")]
    Context {
        context: String,
        #[source]
        source: libbpf_rs::Error,
    },

    #[error("parse ID Error")]
    ParseIdErr,

    #[error("parse ID Error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

pub type LdEbpfResult<T> = Result<T, LandscapeEbpfError>;

#[macro_export]
macro_rules! bpf_ctx {
    ($expr:expr, $($arg:tt)+) => {
        ($expr).map_err(|err| {
            tracing::error!(
                "{} at {}:{}: {err}",
                format_args!($($arg)+),
                file!(),
                line!()
            );
            err
        })
    };
}
