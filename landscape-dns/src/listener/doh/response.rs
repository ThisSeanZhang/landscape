use std::{io, sync::Arc};

use bytes::Bytes;
use futures_util::lock::Mutex;
use http::{Response as HttpResponse, StatusCode, header};

use super::MIME_APPLICATION_DNS;

#[derive(Clone)]
pub(super) struct DohResponseHandle {
    respond: Arc<Mutex<h2::server::SendResponse<Bytes>>>,
    endpoint: Arc<str>,
}

impl DohResponseHandle {
    pub(super) fn new(respond: h2::server::SendResponse<Bytes>, endpoint: Arc<str>) -> Self {
        Self { respond: Arc::new(Mutex::new(respond)), endpoint }
    }

    pub(super) async fn send_http_error(
        &self,
        status: StatusCode,
        message: &str,
    ) -> io::Result<()> {
        let body = Bytes::from(http_error_body(message, &self.endpoint));
        let response = HttpResponse::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::CONTENT_LENGTH, body.len())
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut respond = self.respond.lock().await;
        let mut stream = respond.send_response(response, false).map_err(io::Error::other)?;
        stream.send_data(body, true).map_err(io::Error::other)?;
        Ok(())
    }

    pub(super) async fn send_dns_message(&self, buffer: Vec<u8>) -> io::Result<()> {
        let http_response = HttpResponse::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(header::CONTENT_LENGTH, buffer.len())
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let mut respond = self.respond.lock().await;
        let mut stream = respond.send_response(http_response, false).map_err(io::Error::other)?;
        stream.send_data(Bytes::from(buffer), true).map_err(io::Error::other)?;
        Ok(())
    }
}

fn http_error_body(message: &str, endpoint: &str) -> String {
    format!(
        "DoH request error: {message}\n\nGET usage: {endpoint}?dns=<base64url-no-padding DNS wire message>\nPOST usage: send application/dns-message bytes to {endpoint}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::http_error_body;

    #[test]
    fn http_error_body_uses_configured_endpoint() {
        let body = http_error_body("bad path", "/custom-dns");

        assert!(body.contains("GET usage: /custom-dns?dns="));
        assert!(body.contains("POST usage: send application/dns-message bytes to /custom-dns"));
        assert!(!body.contains("/dns-query"));
    }
}
