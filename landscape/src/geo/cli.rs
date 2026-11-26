//! Executors for the `geo fetch` / `geo build` / `geo inspect` commands.
//!
//! Every command is a pure function over files: one input path, one output
//! path, atomic replace on success. The daemon spawns `geo build` as a child
//! process so that the protobuf parse (millions of short-lived allocations)
//! cannot fragment its own heap; `fetch` and `inspect` are conveniences for
//! humans.

use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use futures::TryStreamExt;
use landscape_common::{
    config_service::geo::{GeoError, GeoIpFileFormat},
    geo_cli::{
        GEO_CLI_SCHEMA, GeoAction, GeoBuildArgs, GeoBuildIpArgs, GeoBuildKind, GeoBuildSiteArgs,
        GeoBuildSummary, GeoFetchArgs, GeoFetchSummary, GeoInspectArgs, GeoInspectEntry,
        GeoInspectReport,
    },
};
use landscape_protobuf::geo_snapshot_hash_hex;
use landscape_protobuf::{GeoSnapshotError, GeoSnapshotReader, GeoSnapshotSourceKind};
use tokio_util::sync::CancellationToken;

use crate::geo::download::http_client;
use crate::geo::ip_snapshot::build_ip_snapshot_reader;
use crate::geo::site_snapshot::{build_adguard_snapshot_file, build_dat_snapshot_reader};
use crate::geo::storage::{GeoSealedFile, GeoTmpFile, StreamToSealedError, stream_to_sealed};

/// Exit codes are part of the CLI contract: the daemon maps them back onto
/// [`GeoError`], and scripts can branch on them.
pub mod exit_code {
    pub const OK: u8 = 0;
    pub const OTHER: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const INPUT: u8 = 3;
    pub const DECODE: u8 = 4;
    pub const CANCELLED: u8 = 5;
    pub const OUTPUT: u8 = 6;
}

#[derive(Debug, thiserror::Error)]
pub enum GeoCliError {
    #[error("read {path}: {source}")]
    Input {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("write {path}: {source}")]
    Output {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("fetch failed: {0}")]
    Fetch(String),
    #[error(transparent)]
    Geo(#[from] GeoError),
    #[error(transparent)]
    Snapshot(#[from] GeoSnapshotError),
    #[error("geo task cancelled")]
    Cancelled,
    #[error("{0}")]
    Other(String),
}

impl GeoCliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Input { .. } => exit_code::INPUT,
            Self::Geo(GeoError::IpDatDecodeError | GeoError::SiteDatDecodeError) => {
                exit_code::DECODE
            }
            Self::Cancelled | Self::Geo(GeoError::TaskCancelled) => exit_code::CANCELLED,
            Self::Output { .. } | Self::Snapshot(_) => exit_code::OUTPUT,
            _ => exit_code::OTHER,
        }
    }

    fn input(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Input { path: path.into(), source }
    }

    fn output(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Output { path: path.into(), source }
    }
}

pub async fn run(action: &GeoAction) -> Result<(), GeoCliError> {
    match action {
        GeoAction::Fetch(args) => fetch(args).await,
        GeoAction::Build(args) => build(args).await,
        GeoAction::Inspect(args) => inspect(args).await,
    }
}

/// Write one already-formatted chunk to stdout.
///
/// Piping into `head`/`less` closes stdout early; that is normal for a CLI and
/// must not turn into a panic (or a non-zero exit) the way `println!` does.
fn print_out(text: &str) -> Result<(), GeoCliError> {
    use std::io::Write;

    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(GeoCliError::Other(format!("write stdout: {error}"))),
    }
}

async fn fetch(args: &GeoFetchArgs) -> Result<(), GeoCliError> {
    let mut bytes = 0u64;
    let content_length;
    let sealed = match (&args.url, &args.file) {
        (Some(url), _) => {
            let client = http_client()
                .map_err(|error| GeoCliError::Fetch(format!("build http client: {error}")))?;
            let response = client
                .get(url)
                .send()
                .await
                .map_err(|error| GeoCliError::Fetch(format!("{url}: {error}")))?;
            if !response.status().is_success() {
                return Err(GeoCliError::Fetch(format!(
                    "{url} returned HTTP {}",
                    response.status()
                )));
            }
            content_length = response.content_length();
            let stream = response.bytes_stream().map_err(io::Error::other);
            stream_to_sealed(stream, &args.output, &|| false, &mut |written| bytes = written)
                .await
                .map_err(|error| match error {
                    StreamToSealedError::Cancelled => GeoCliError::Cancelled,
                    StreamToSealedError::Io(source) => GeoCliError::output(&args.output, source),
                })?
        }
        (None, Some(file)) => {
            content_length = std::fs::metadata(file).ok().map(|metadata| metadata.len());
            copy_into_sealed(file, &args.output, &mut bytes)?
        }
        (None, None) => unreachable!("clap requires --url or --file"),
    };
    sealed.commit().map_err(|source| GeoCliError::output(&args.output, source))?;

    let summary = GeoFetchSummary { schema: GEO_CLI_SCHEMA, bytes, content_length };
    let text = if args.json {
        format!("{}\n", serde_json::to_string(&summary).map_err(json_error)?)
    } else {
        let total = summary.content_length.map_or_else(|| "unknown".to_string(), |n| n.to_string());
        format!(
            "fetched {} bytes -> {} (content-length: {total})\n",
            summary.bytes,
            args.output.display()
        )
    };
    print_out(&text)
}

fn copy_into_sealed(
    input: &Path,
    output: &Path,
    bytes: &mut u64,
) -> Result<GeoSealedFile, GeoCliError> {
    let mut source = File::open(input).map_err(|error| GeoCliError::input(input, error))?;
    let mut tmp = GeoTmpFile::create(output).map_err(|error| GeoCliError::output(output, error))?;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer).map_err(|error| GeoCliError::input(input, error))?;
        if read == 0 {
            break;
        }
        tmp.write_chunk(&buffer[..read]).map_err(|error| GeoCliError::output(output, error))?;
        *bytes = bytes.saturating_add(read as u64);
    }
    tmp.seal().map_err(|error| GeoCliError::output(output, error))
}

async fn build(args: &GeoBuildArgs) -> Result<(), GeoCliError> {
    match &args.kind {
        GeoBuildKind::Ip(args) => build_ip(args).await,
        GeoBuildKind::Site(args) => build_site(args).await,
    }
}

async fn build_ip(args: &GeoBuildIpArgs) -> Result<(), GeoCliError> {
    let input = args.input.clone();
    let output = args.output.clone();
    let format: GeoIpFileFormat = args.format.into();
    let txt_key = args.txt_key.clone();
    let source_id = args.source_id.unwrap_or_default();
    let cancel = CancellationToken::new();

    let summary = tokio::task::spawn_blocking(move || {
        let file = File::open(&input).map_err(|error| GeoCliError::input(&input, error))?;
        build_ip_snapshot_reader(file, &output, source_id, &format, txt_key.as_deref(), &cancel)
            .map_err(GeoCliError::from)
    })
    .await
    .map_err(join_error)??;

    emit_build_summary(
        GeoBuildSummary {
            schema: GEO_CLI_SCHEMA,
            entries: summary.entries,
            valid_lines: summary.valid_lines,
            skipped_lines: summary.skipped_lines,
        },
        args.json,
        &args.output,
    )
}

async fn build_site(args: &GeoBuildSiteArgs) -> Result<(), GeoCliError> {
    let input = args.input.clone();
    let output = args.output.clone();
    let adguard_key = args.adguard_key.clone();
    let source_id = args.source_id.unwrap_or_default();
    let cancel = CancellationToken::new();

    let entries = tokio::task::spawn_blocking(move || -> Result<usize, GeoCliError> {
        match adguard_key {
            Some(key) => build_adguard_snapshot_file(&input, &output, source_id, &key, &cancel)
                .map(|summary| summary.entries)
                .map_err(GeoCliError::from),
            None => {
                let file = File::open(&input).map_err(|error| GeoCliError::input(&input, error))?;
                build_dat_snapshot_reader(file, &output, source_id, &cancel)
                    .map(|summary| summary.entries)
                    .map_err(GeoCliError::from)
            }
        }
    })
    .await
    .map_err(join_error)??;

    emit_build_summary(
        GeoBuildSummary {
            schema: GEO_CLI_SCHEMA,
            entries,
            valid_lines: 0,
            skipped_lines: 0,
        },
        args.json,
        &args.output,
    )
}

fn emit_build_summary(
    summary: GeoBuildSummary,
    json: bool,
    output: &Path,
) -> Result<(), GeoCliError> {
    if json {
        println!("{}", serde_json::to_string(&summary).map_err(json_error)?);
    } else {
        println!(
            "built {} entries -> {}{}",
            summary.entries,
            output.display(),
            if summary.valid_lines + summary.skipped_lines > 0 {
                format!(" ({} valid, {} skipped lines)", summary.valid_lines, summary.skipped_lines)
            } else {
                String::new()
            }
        );
    }
    Ok(())
}

async fn inspect(args: &GeoInspectArgs) -> Result<(), GeoCliError> {
    let input = args.input.clone();
    let reader = tokio::task::spawn_blocking(move || GeoSnapshotReader::open(&input))
        .await
        .map_err(join_error)??;

    let metadata = reader.metadata();
    let source_kind = match metadata.source_kind {
        GeoSnapshotSourceKind::Ip => "ip",
        GeoSnapshotSourceKind::Site => "site",
    };
    let report = GeoInspectReport {
        schema: GEO_CLI_SCHEMA,
        format_version: metadata.format_version,
        source_kind: source_kind.to_string(),
        source_id: metadata.source_id,
        created_at_ms: metadata.created_at_ms,
        entries: reader
            .index()
            .iter()
            .map(|entry| GeoInspectEntry {
                key: entry.key.clone(),
                items: entry.item_count,
                payload_bytes: entry.payload_len,
                sha256: geo_snapshot_hash_hex(&entry.hash),
            })
            .collect(),
    };

    if args.json {
        let text = format!("{}\n", serde_json::to_string(&report).map_err(json_error)?);
        return print_out(&text);
    }

    let mut text = String::new();
    text.push_str(&format!("path:           {}\n", args.input.display()));
    text.push_str(&format!("format_version: {}\n", report.format_version));
    text.push_str(&format!("source_kind:    {}\n", report.source_kind));
    text.push_str(&format!("source_id:      {}\n", report.source_id));
    text.push_str(&format!("created_at_ms:  {}\n", report.created_at_ms));
    text.push_str(&format!("keys:           {}\n\n", report.entries.len()));
    let key_width = report.entries.iter().map(|entry| entry.key.len()).max().unwrap_or(3).max(3);
    text.push_str(&format!("{:key_width$}  {:>8}  {:>12}  SHA256\n", "KEY", "ITEMS", "BYTES"));
    for entry in &report.entries {
        text.push_str(&format!(
            "{:key_width$}  {:>8}  {:>12}  {}\n",
            entry.key, entry.items, entry.payload_bytes, entry.sha256
        ));
    }
    print_out(&text)
}

fn join_error(error: tokio::task::JoinError) -> GeoCliError {
    GeoCliError::Other(format!("geo worker failed: {error}"))
}

fn json_error(error: serde_json::Error) -> GeoCliError {
    GeoCliError::Other(format!("encode json summary: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_separate_input_decode_cancel_and_output() {
        let io_input = GeoCliError::input("in.dat", io::Error::from(io::ErrorKind::NotFound));
        assert_eq!(io_input.exit_code(), exit_code::INPUT);

        let io_output = GeoCliError::output("out.snap", io::Error::from(io::ErrorKind::Other));
        assert_eq!(io_output.exit_code(), exit_code::OUTPUT);

        let decode = GeoCliError::Geo(GeoError::IpDatDecodeError);
        assert_eq!(decode.exit_code(), exit_code::DECODE);

        let cancelled = GeoCliError::Geo(GeoError::TaskCancelled);
        assert_eq!(cancelled.exit_code(), exit_code::CANCELLED);

        let other = GeoCliError::Fetch("boom".to_string());
        assert_eq!(other.exit_code(), exit_code::OTHER);
    }
}
