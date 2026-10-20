use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    time::Instant,
};

use reqwest::Client;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::storage::{GeoSealedFile, StreamToSealedError, stream_to_sealed};
use super::{GEO_PROGRESS_PUBLISH_INTERVAL, GeoTaskRegistry};

#[derive(Debug, thiserror::Error)]
pub(crate) enum GeoDownloadError {
    #[error("request {url} failed: {source}")]
    Request {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{url} returned HTTP {status}")]
    HttpStatus { url: String, status: reqwest::StatusCode },
    #[error("stream to {path:?} failed: {source}")]
    Stream {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("geo task cancelled")]
    Cancelled,
}

/// Download a URL into a sealed temporary file while publishing progress to
/// the shared geo task registry.
pub(crate) async fn download_to_sealed(
    source_id: Uuid,
    url: &str,
    destination: &Path,
    tasks: &GeoTaskRegistry,
    cancel: &CancellationToken,
) -> Result<GeoSealedFile, GeoDownloadError> {
    // Downloads run at most once a day per source, so connection reuse across
    // tasks would not pay for a shared client.
    let client = Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|source| GeoDownloadError::Request { url: url.to_string(), source })?;
    if !response.status().is_success() {
        return Err(GeoDownloadError::HttpStatus {
            url: url.to_string(),
            status: response.status(),
        });
    }
    let bytes_total = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let registry = tasks.clone();
    let mut last_publish: Option<Instant> = None;
    let should_stop = || cancel.is_cancelled();
    stream_to_sealed(response.bytes_stream(), destination, &should_stop, &mut |written| {
        let now = Instant::now();
        let due = last_publish
            .is_none_or(|last| now.duration_since(last) >= GEO_PROGRESS_PUBLISH_INTERVAL);
        if due {
            registry.update_download(source_id, written, bytes_total);
            last_publish = Some(now);
        }
    })
    .await
    .map_err(|error| match error {
        StreamToSealedError::Cancelled => GeoDownloadError::Cancelled,
        StreamToSealedError::Io(source) => {
            GeoDownloadError::Stream { path: destination.to_path_buf(), source }
        }
    })
}

/// Progress-reporting `Read` adapter for a blocking snapshot parser.
pub(crate) struct DownloadProgressReader<R> {
    inner: R,
    registry: GeoTaskRegistry,
    source_id: Uuid,
    bytes_total: Option<u64>,
    bytes_read: u64,
    last_publish: Option<Instant>,
    cancel: CancellationToken,
}

impl<R> DownloadProgressReader<R> {
    pub(crate) fn new(
        inner: R,
        registry: GeoTaskRegistry,
        source_id: Uuid,
        bytes_total: Option<u64>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            inner,
            registry,
            source_id,
            bytes_total,
            bytes_read: 0,
            last_publish: None,
            cancel,
        }
    }
}

impl<R: Read> Read for DownloadProgressReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "geo task cancelled"));
        }
        let read = self.inner.read(buffer)?;
        if read > 0 {
            self.bytes_read = self.bytes_read.saturating_add(read as u64);
            let now = Instant::now();
            let due = self
                .last_publish
                .is_none_or(|last| now.duration_since(last) >= GEO_PROGRESS_PUBLISH_INTERVAL);
            if due {
                self.registry.update_download(self.source_id, self.bytes_read, self.bytes_total);
                self.last_publish = Some(now);
            }
        }
        Ok(read)
    }
}
