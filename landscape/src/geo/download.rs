use std::{
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use reqwest::Client;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::storage::{GeoSealedFile, StreamToSealedError, stream_to_sealed};
use super::{GEO_PROGRESS_PUBLISH_INTERVAL, GeoTaskRegistry};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Client shared by the daemon downloader and `geo fetch`.
pub(crate) fn http_client() -> Result<Client, reqwest::Error> {
    Client::builder().connect_timeout(CONNECT_TIMEOUT).read_timeout(READ_TIMEOUT).build()
}

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
    // tasks would not pay for a shared client. The timeouts keep an unreachable
    // or stalled source from pinning a task (and the UI) forever.
    let client = http_client()
        .map_err(|source| GeoDownloadError::Request { url: url.to_string(), source })?;

    // `send` covers DNS + TCP + TLS + response headers; without racing it the
    // cancel token would only be observed once the body starts streaming.
    let response = tokio::select! {
        response = client.get(url).send() => {
            response.map_err(|source| GeoDownloadError::Request { url: url.to_string(), source })?
        }
        _ = cancel.cancelled() => return Err(GeoDownloadError::Cancelled),
    };
    if !response.status().is_success() {
        return Err(GeoDownloadError::HttpStatus {
            url: url.to_string(),
            status: response.status(),
        });
    }
    let bytes_total = response.content_length();
    let registry = tasks.clone();
    let mut last_publish: Option<Instant> = None;
    let should_stop = || cancel.is_cancelled();
    // Racing the body stream as well makes cancellation instant even when the
    // peer stalls between chunks; the tmp file is removed by `GeoTmpFile`.
    let mut on_progress = |written: u64| {
        let now = Instant::now();
        let due = last_publish
            .is_none_or(|last| now.duration_since(last) >= GEO_PROGRESS_PUBLISH_INTERVAL);
        if due {
            registry.update_download(source_id, written, bytes_total);
            last_publish = Some(now);
        }
    };
    let streamed = tokio::select! {
        result = stream_to_sealed(
            response.bytes_stream(),
            destination,
            &should_stop,
            &mut on_progress,
        ) => result,
        _ = cancel.cancelled() => return Err(GeoDownloadError::Cancelled),
    };
    streamed.map_err(|error| match error {
        StreamToSealedError::Cancelled => GeoDownloadError::Cancelled,
        StreamToSealedError::Io(source) => {
            GeoDownloadError::Stream { path: destination.to_path_buf(), source }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::{GeoDownloadError, download_to_sealed};
    use crate::geo::GeoTaskRegistry;

    /// A source that accepts the TCP connection but never sends a byte must not
    /// keep the task alive after cancellation.
    #[tokio::test]
    async fn cancel_interrupts_a_hanging_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Hold every accepted connection open and silent.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });

        let dir = std::env::temp_dir().join(format!("land-geo-download-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let destination = PathBuf::from(&dir).join("ip.raw");

        let cancel = CancellationToken::new();
        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            canceller.cancel();
        });

        let started = std::time::Instant::now();
        let result = download_to_sealed(
            Uuid::new_v4(),
            &format!("http://{addr}/never.dat"),
            &destination,
            &GeoTaskRegistry::default(),
            &cancel,
        )
        .await;

        let elapsed = started.elapsed();
        assert!(matches!(result, Err(GeoDownloadError::Cancelled)), "unexpected result");
        assert!(elapsed < Duration::from_secs(5), "cancellation took {elapsed:?}");
        assert!(!destination.exists(), "no raw file must be left behind");
        assert!(!destination.with_extension("raw.tmp").exists(), "no tmp file must be left");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
