use std::{io, sync::Arc};

use bytes::Bytes;
use futures_util::lock::Mutex;
use hickory_proto::{
    op::{Header, MessageType, Metadata, OpCode, ResponseCode},
    rr::Record,
    serialize::binary::{BinEncodable, BinEncoder},
};
use hickory_server::{
    net::NetError,
    server::{ResponseHandler, ResponseInfo},
    zone_handler::MessageResponse,
};
use http::{header, Response as HttpResponse, StatusCode};

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
        let mut stream = respond
            .send_response(response, false)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        stream.send_data(body, true).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
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
        let mut stream = respond
            .send_response(http_response, false)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        stream
            .send_data(Bytes::from(buffer), true)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ResponseHandler for DohResponseHandle {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let id = response.metadata().id;
        let mut buffer = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut buffer);
            encoder.set_max_size(u16::MAX);
            response.destructive_emit(&mut encoder).or_else(|_| {
                buffer.clear();
                let mut encoder = BinEncoder::new(&mut buffer);
                encoder.set_max_size(512);
                let header = servfail_header(id);
                header.emit(&mut encoder)?;
                Ok::<_, hickory_proto::ProtoError>(header.into())
            })?
        };

        self.send_dns_message(buffer).await?;

        Ok(info)
    }
}

fn servfail_header(id: u16) -> Header {
    let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
    metadata.response_code = ResponseCode::ServFail;
    Header { metadata, counts: Default::default() }
}

fn http_error_body(message: &str, endpoint: &str) -> String {
    format!(
        "DoH request error: {message}\n\nGET usage: {endpoint}?dns=<base64url-no-padding DNS wire message>\nPOST usage: send application/dns-message bytes to {endpoint}\n"
    )
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{MessageType, ResponseCode};

    use super::{http_error_body, servfail_header};

    #[test]
    fn http_error_body_uses_configured_endpoint() {
        let body = http_error_body("bad path", "/custom-dns");

        assert!(body.contains("GET usage: /custom-dns?dns="));
        assert!(body.contains("POST usage: send application/dns-message bytes to /custom-dns"));
        assert!(!body.contains("/dns-query"));
    }

    #[test]
    fn servfail_header_is_dns_response_with_request_id() {
        let header = servfail_header(0x1234);

        assert_eq!(header.id, 0x1234);
        assert_eq!(header.message_type, MessageType::Response);
        assert_eq!(header.response_code, ResponseCode::ServFail);
    }
}
