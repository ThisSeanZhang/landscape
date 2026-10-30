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

/// Lines kept when an eBPF error is written to the log.
pub const MAX_ERROR_LOG_LINES: usize = 32;
/// Lines kept from the start of an over-long error; the tail keeps the
/// verifier's own rejection reason, which is the useful part.
const ERROR_LOG_HEAD_LINES: usize = 24;

/// Render an eBPF error for logging.
///
/// A rejected program makes libbpf put the whole verifier dump into the error
/// value, which is megabytes for a program near the instruction limit. A
/// caller that retries can then turn a single failing attach into hundreds of
/// megabytes of log per day, so keep the head and the tail and say how much was
/// dropped.
pub fn summarize_error_text(text: &str) -> String {
    let total = text.lines().count();
    if total <= MAX_ERROR_LOG_LINES {
        return text.to_string();
    }

    let omitted = total - MAX_ERROR_LOG_LINES;
    let head: Vec<&str> = text.lines().take(ERROR_LOG_HEAD_LINES).collect();
    let tail_keep = MAX_ERROR_LOG_LINES - ERROR_LOG_HEAD_LINES;
    let tail: Vec<&str> = text.lines().skip(total - tail_keep).collect();
    format!("{}\n... {omitted} of {total} lines omitted ...\n{}", head.join("\n"), tail.join("\n"))
}

#[macro_export]
macro_rules! bpf_ctx {
    ($expr:expr, $($arg:tt)+) => {
        ($expr).map_err(|err| {
            tracing::error!(
                "{} at {}:{}: {}",
                format_args!($($arg)+),
                file!(),
                line!(),
                $crate::bpf_error::summarize_error_text(&err.to_string())
            );
            err
        })
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_errors_are_logged_verbatim() {
        let text = "open tc_nat6 skeleton: No such file or directory";
        assert_eq!(summarize_error_text(text), text);
    }

    #[test]
    fn verifier_dumps_keep_the_head_and_the_tail() {
        let mut lines = Vec::new();
        for i in 0..5000 {
            lines.push(format!("processed {i} insns"));
        }
        lines.push("invalid bpf_context access off=16 size=8".to_string());
        let text = lines.join("\n");

        let summarized = summarize_error_text(&text);
        let out: Vec<&str> = summarized.lines().collect();
        assert_eq!(out.len(), MAX_ERROR_LOG_LINES + 1, "head + marker + tail");
        assert_eq!(out[0], "processed 0 insns");
        assert_eq!(out[ERROR_LOG_HEAD_LINES], "... 4969 of 5001 lines omitted ...");
        assert_eq!(out.last().copied(), Some("invalid bpf_context access off=16 size=8"));
        assert!(summarized.len() < text.len() / 50, "summary must stay small");
    }

    #[test]
    fn exactly_the_limit_is_not_truncated() {
        let text =
            (0..MAX_ERROR_LOG_LINES).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        assert_eq!(summarize_error_text(&text), text);
    }
}
