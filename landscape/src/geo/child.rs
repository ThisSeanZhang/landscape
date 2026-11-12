//! Runs the `geo build` stage in a child process.
//!
//! Decoding a geo source allocates millions of short-lived `String`s. glibc
//! keeps the freed arena pages mapped, so a long-running daemon accumulates
//! them across refreshes. A short-lived child returns every page on exit, and
//! gives the parse a hard cancellation path (SIGKILL) plus crash isolation for
//! untrusted `.dat` input.
//!
//! The contract with [`crate::geo::cli`] is deliberately tiny: the child writes
//! the snapshot atomically and prints one JSON summary line on stdout.

use std::{
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use landscape_common::{
    config_service::geo::{GeoError, GeoIpFileFormat},
    geo_cli::{GEO_CLI_SCHEMA, GeoBuildSummary},
};
use tokio::{io::AsyncReadExt, process::Command};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// A hung parser must not pin a geo task forever; the largest real sources
/// convert in well under a minute.
const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone)]
pub(crate) enum BuildKind {
    Ip { format: GeoIpFileFormat, txt_key: Option<String> },
    SiteDat,
    SiteAdguard { key: String },
}

impl BuildKind {
    fn is_ip(&self) -> bool {
        matches!(self, Self::Ip { .. })
    }
}

pub(crate) struct BuildRequest<'a> {
    pub input: &'a Path,
    pub output: &'a Path,
    pub source_id: Uuid,
    pub kind: BuildKind,
}

enum Outcome {
    Done(std::io::Result<ExitStatus>),
    Cancelled,
    TimedOut,
}

pub(crate) async fn build_snapshot(
    request: BuildRequest<'_>,
    cancel: &CancellationToken,
) -> Result<GeoBuildSummary, GeoError> {
    let mut command = Command::new(resolve_executable()?);
    command
        .arg("geo")
        .arg("build")
        .arg(if request.kind.is_ip() { "ip" } else { "site" })
        .arg("--input")
        .arg(request.input)
        .arg("--output")
        .arg(request.output)
        .arg("--source-id")
        .arg(request.source_id.to_string())
        .arg("--json")
        // The child decodes single-threaded; one arena keeps its heap compact
        // and trimmable for the short time it lives.
        .env("MALLOC_ARENA_MAX", "1")
        // Only used by test harnesses to make argv parsing a no-op.
        .env_remove("LANDSCAPE_IGNORE_CLI_ARGS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    match &request.kind {
        BuildKind::Ip { format, txt_key } => {
            command.arg("--format").arg(match format {
                GeoIpFileFormat::Dat => "dat",
                GeoIpFileFormat::Txt => "txt",
            });
            if let Some(key) = txt_key {
                command.arg("--txt-key").arg(key);
            }
        }
        BuildKind::SiteDat => {}
        BuildKind::SiteAdguard { key } => {
            command.arg("--adguard-key").arg(key);
        }
    }

    let mut child = command.spawn().map_err(|error| {
        GeoError::RawDatReadFailed(format!("spawn geo build for {:?}: {error}", request.input))
    })?;

    // Drain both pipes while the child runs to avoid a pipe-buffer deadlock.
    let stdout_reader = spawn_pipe_reader(child.stdout.take());
    let stderr_reader = spawn_pipe_reader(child.stderr.take());

    let outcome = tokio::select! {
        status = child.wait() => Outcome::Done(status),
        _ = cancel.cancelled() => Outcome::Cancelled,
        _ = tokio::time::sleep(BUILD_TIMEOUT) => Outcome::TimedOut,
    };

    let status = match outcome {
        Outcome::Done(status) => status,
        Outcome::Cancelled => {
            stop(&mut child).await;
            discard_tmp(request.output);
            return Err(GeoError::TaskCancelled);
        }
        Outcome::TimedOut => {
            stop(&mut child).await;
            discard_tmp(request.output);
            return Err(GeoError::RawDatReadFailed(format!(
                "geo build for {:?} timed out after {}s",
                request.input,
                BUILD_TIMEOUT.as_secs()
            )));
        }
    };

    let stdout = stdout_reader.await.unwrap_or_default();
    let stderr = stderr_reader.await.unwrap_or_default();

    let status = status.map_err(|error| {
        GeoError::RawDatReadFailed(format!("wait for geo build {:?}: {error}", request.input))
    })?;
    if !status.success() {
        discard_tmp(request.output);
        return Err(failure(&request.kind, status, &stdout, &stderr));
    }

    parse_summary(&stdout).ok_or_else(|| {
        GeoError::RawDatReadFailed(format!(
            "geo build for {:?} produced no summary: {}",
            request.input,
            tail(&stderr)
        ))
    })
}

fn spawn_pipe_reader<R>(pipe: Option<R>) -> tokio::task::JoinHandle<String>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut text = String::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_string(&mut text).await;
        }
        text
    })
}

async fn stop(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn failure(kind: &BuildKind, status: ExitStatus, _stdout: &str, stderr: &str) -> GeoError {
    match status.code() {
        // See `crate::geo::cli::exit_code`.
        Some(4) if kind.is_ip() => GeoError::IpDatDecodeError,
        Some(4) => GeoError::SiteDatDecodeError,
        Some(5) => GeoError::TaskCancelled,
        Some(code) => GeoError::RawDatReadFailed(format!(
            "geo build exited with code {code}: {}",
            tail(stderr)
        )),
        None => GeoError::RawDatReadFailed(format!(
            "geo build was terminated by a signal: {}",
            tail(stderr)
        )),
    }
}

fn parse_summary(stdout: &str) -> Option<GeoBuildSummary> {
    let line = stdout.lines().rev().find(|line| line.trim_start().starts_with('{'))?;
    let summary: GeoBuildSummary = serde_json::from_str(line.trim()).ok()?;
    (summary.schema == GEO_CLI_SCHEMA).then_some(summary)
}

fn tail(stderr: &str) -> String {
    let lines: Vec<&str> = stderr.lines().filter(|line| !line.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(4);
    lines[start..].join(" | ")
}

fn discard_tmp(output: &Path) {
    let mut path = output.as_os_str().to_os_string();
    path.push(".tmp");
    let _ = std::fs::remove_file(PathBuf::from(path));
}

fn resolve_executable() -> Result<PathBuf, GeoError> {
    if let Ok(path) = std::env::current_exe() {
        return Ok(path);
    }
    std::env::args_os().next().map(PathBuf::from).ok_or_else(|| {
        GeoError::RawDatReadFailed("cannot resolve the landscape executable".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_must_match_the_schema() {
        let ok = r#"{"schema":1,"entries":3,"valid_lines":4,"skipped_lines":1}"#;
        let summary = parse_summary(ok).expect("valid summary");
        assert_eq!((summary.entries, summary.valid_lines, summary.skipped_lines), (3, 4, 1));

        assert!(parse_summary(r#"{"schema":2,"entries":3}"#).is_none());
        assert!(parse_summary("built 3 entries").is_none());
        assert!(parse_summary("").is_none());
    }

    #[test]
    fn summary_is_read_from_the_last_json_line() {
        let stdout = "warning: something\n{\"schema\":1,\"entries\":7}\n";
        assert_eq!(parse_summary(stdout).map(|summary| summary.entries), Some(7));
    }

    #[test]
    fn discard_tmp_removes_only_the_tmp_file() {
        let dir = std::env::temp_dir().join(format!("land-geo-child-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("ip.snap");
        let tmp = dir.join("ip.snap.tmp");
        std::fs::write(&output, b"final").unwrap();
        std::fs::write(&tmp, b"partial").unwrap();

        discard_tmp(&output);

        assert!(output.exists(), "the committed snapshot must survive");
        assert!(!tmp.exists(), "the partial tmp file must be removed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stderr_tail_keeps_the_last_lines() {
        assert_eq!(tail("a\nb\nc\nd\ne\n"), "b | c | d | e");
        assert_eq!(tail(""), "");
    }
}
