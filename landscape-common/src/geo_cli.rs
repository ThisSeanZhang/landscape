//! Command-line surface of the geo pipeline.
//!
//! The pipeline has three file-boundary stages and the daemon and humans drive
//! the same code:
//!
//! ```text
//! fetch   URL / local file  ->  geo/raw/<kind>-<id>.raw
//! build   raw               ->  geo/snapshots/<kind>-<id>.snap
//! apply   snap              ->  SQLite cache + matchers  (daemon only)
//! ```
//!
//! `apply` is deliberately absent here: only the daemon owns the cache
//! connection and the in-memory matchers, so it never runs out of process.
//!
//! [^note]: `fetch` is a convenience for humans. The daemon downloads into the
//! raw file itself so it can publish progress and honour cancellation; it then
//! spawns `build` as a child process.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config_service::geo::GeoIpFileFormat;

/// Version of the machine-readable summary written to stdout by every command.
pub const GEO_CLI_SCHEMA: u32 = 1;

/// `landscape-webserver geo <action>`. Wrapped in a struct because clap tuple
/// variants of a parent `Subcommand` must implement `Args`.
#[derive(Args, Debug, Clone)]
pub struct GeoArgs {
    #[command(subcommand)]
    pub action: GeoAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GeoAction {
    /// Download (or copy) a geo source into a raw staging file
    Fetch(GeoFetchArgs),
    /// Convert a raw geo source into a snapshot
    Build(GeoBuildArgs),
    /// Print a snapshot's header, index and per-key hashes
    Inspect(GeoInspectArgs),
}

#[derive(Args, Debug, Clone)]
#[command(group = clap::ArgGroup::new("source").required(true).multiple(false))]
pub struct GeoFetchArgs {
    /// URL to download (mutually exclusive with --file)
    #[arg(long, group = "source", value_name = "URL")]
    pub url: Option<String>,

    /// Local file to copy (mutually exclusive with --url)
    #[arg(long, group = "source", value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Destination raw file
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,

    /// Print a JSON summary instead of a human-readable one
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct GeoBuildArgs {
    #[command(subcommand)]
    pub kind: GeoBuildKind,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GeoBuildKind {
    /// geoip.dat (protobuf) or a plain-text CIDR list
    Ip(GeoBuildIpArgs),
    /// geosite.dat (protobuf) or an AdGuard Home rules file
    Site(GeoBuildSiteArgs),
}

#[derive(Args, Debug, Clone)]
pub struct GeoBuildIpArgs {
    /// Raw input file
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,

    /// Snapshot output file
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,

    /// Input encoding
    #[arg(long, value_enum, default_value_t)]
    pub format: GeoFormatArg,

    /// Key used for text inputs (defaults to the whole file)
    #[arg(long, value_name = "KEY")]
    pub txt_key: Option<String>,

    /// Source config id recorded in the snapshot header
    #[arg(long, value_name = "UUID")]
    pub source_id: Option<Uuid>,

    /// Print a JSON summary instead of a human-readable one
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct GeoBuildSiteArgs {
    /// Raw input file
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,

    /// Snapshot output file
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,

    /// Treat the input as an AdGuard Home rules file for this key
    #[arg(long, value_name = "KEY")]
    pub adguard_key: Option<String>,

    /// Source config id recorded in the snapshot header
    #[arg(long, value_name = "UUID")]
    pub source_id: Option<Uuid>,

    /// Print a JSON summary instead of a human-readable one
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct GeoInspectArgs {
    /// Snapshot file to inspect
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,

    /// Print a JSON summary instead of a table
    #[arg(long)]
    pub json: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GeoFormatArg {
    #[default]
    Dat,
    Txt,
}

impl From<GeoFormatArg> for GeoIpFileFormat {
    fn from(value: GeoFormatArg) -> Self {
        match value {
            GeoFormatArg::Dat => Self::Dat,
            GeoFormatArg::Txt => Self::Txt,
        }
    }
}

/// Machine-readable result of `geo build`. Written as a single stdout line so
/// the daemon can consume it from a child process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoBuildSummary {
    #[serde(default)]
    pub schema: u32,
    pub entries: usize,
    #[serde(default)]
    pub valid_lines: usize,
    #[serde(default)]
    pub skipped_lines: usize,
}

/// Machine-readable result of `geo fetch`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoFetchSummary {
    #[serde(default)]
    pub schema: u32,
    pub bytes: u64,
    /// Expected total reported by the source, if it sent a usable length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
}

/// Machine-readable result of `geo inspect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoInspectReport {
    pub schema: u32,
    pub format_version: u16,
    pub source_kind: String,
    pub source_id: Uuid,
    pub created_at_ms: u64,
    pub entries: Vec<GeoInspectEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoInspectEntry {
    pub key: String,
    pub items: u64,
    pub payload_bytes: u64,
    pub sha256: String,
}
