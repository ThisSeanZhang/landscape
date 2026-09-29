use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::BytesMut;
use http::{Method, Request as HttpRequest, StatusCode, header};
use std::time::Duration;

use super::{MAX_DNS_MESSAGE_SIZE, MIME_APPLICATION_DNS};

pub(super) async fn extract_doh_message(
    dns_hostname: Option<&str>,
    endpoint: &str,
    request: HttpRequest<h2::RecvStream>,
    body_timeout: Duration,
) -> Result<BytesMut, DohRequestError> {
    verify_doh_request(dns_hostname, endpoint, &request)?;
    match *request.method() {
        Method::GET => extract_get_message(request.uri()),
        Method::POST => extract_post_message(request, body_timeout).await,
        _ => Err(DohRequestError::bad_request("unsupported method")),
    }
}

fn verify_doh_request<T>(
    dns_hostname: Option<&str>,
    endpoint: &str,
    request: &HttpRequest<T>,
) -> Result<(), DohRequestError> {
    if request.version() != http::Version::HTTP_2 {
        return Err(DohRequestError::bad_request("only HTTP/2 supported"));
    }
    let uri = request.uri();
    if uri.path() != endpoint {
        return Err(DohRequestError::not_found("bad DoH path"));
    }
    if Some(&http::uri::Scheme::HTTPS) != uri.scheme() {
        return Err(DohRequestError::bad_request("must use HTTPS scheme"));
    }
    if let Some(dns_hostname) = dns_hostname {
        let authority =
            uri.authority().ok_or_else(|| DohRequestError::bad_request("missing authority"))?;
        if !authority.host().eq_ignore_ascii_case(dns_hostname) {
            return Err(DohRequestError::bad_request("incorrect authority"));
        }
    }
    if !accepts_dns_message(request.headers()) {
        return Err(DohRequestError::not_acceptable("unsupported Accept header"));
    }
    if request.method() == Method::POST && !has_dns_content_type(request.headers()) {
        return Err(DohRequestError::unsupported_media_type("unsupported Content-Type"));
    }
    Ok(())
}

fn accepts_dns_message(headers: &http::HeaderMap) -> bool {
    let mut values = headers.get_all(header::ACCEPT).iter().peekable();
    if values.peek().is_none() {
        return true;
    }

    values.any(|value| {
        value
            .to_str()
            .ok()
            .is_some_and(|value| value.split(',').any(accept_part_allows_dns_message))
    })
}

fn has_dns_content_type(headers: &http::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| media_type_matches(value, MIME_APPLICATION_DNS))
        .unwrap_or(false)
}

fn accept_part_allows_dns_message(part: &str) -> bool {
    let mut parts = part.split(';');
    let media_type = parts.next().unwrap_or_default().trim();
    if !media_type_matches_dns_range(media_type) {
        return false;
    }

    quality_allows(parts)
}

fn media_type_matches_dns_range(media_type: &str) -> bool {
    media_type_matches(media_type, MIME_APPLICATION_DNS)
        || media_type_matches(media_type, "application/*")
        || media_type_matches(media_type, "*/*")
}

fn media_type_matches(value: &str, expected: &str) -> bool {
    value.split(';').next().unwrap_or_default().trim().eq_ignore_ascii_case(expected)
}

fn quality_allows<'a>(params: impl Iterator<Item = &'a str>) -> bool {
    for param in params {
        let mut parts = param.trim().splitn(2, '=');
        let key = parts.next().unwrap_or_default().trim();
        if !key.eq_ignore_ascii_case("q") {
            continue;
        }

        let Some(value) = parts.next() else {
            return false;
        };
        return value.trim().trim_matches('"').parse::<f32>().is_ok_and(|q| q > 0.0);
    }

    true
}

fn extract_get_message(uri: &http::Uri) -> Result<BytesMut, DohRequestError> {
    let dns = find_query_param(uri.query().unwrap_or_default(), "dns")
        .ok_or_else(|| DohRequestError::bad_request("missing dns query parameter"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(dns.as_bytes())
        .map_err(|_| DohRequestError::bad_request("invalid dns query parameter"))?;
    if bytes.len() > MAX_DNS_MESSAGE_SIZE {
        return Err(DohRequestError::payload_too_large("DNS query too large"));
    }
    Ok(BytesMut::from(bytes.as_slice()))
}

async fn extract_post_message(
    request: HttpRequest<h2::RecvStream>,
    body_timeout: Duration,
) -> Result<BytesMut, DohRequestError> {
    let content_length = parse_content_length(request.headers())?;
    if content_length.is_some_and(|len| len > MAX_DNS_MESSAGE_SIZE) {
        return Err(DohRequestError::payload_too_large("DNS query too large"));
    }

    tokio::time::timeout(body_timeout, read_post_body(request.into_body(), content_length))
        .await
        .map_err(|_| DohRequestError::request_timeout("HTTP/2 body timeout"))?
}

async fn read_post_body(
    mut body: h2::RecvStream,
    content_length: Option<usize>,
) -> Result<BytesMut, DohRequestError> {
    let mut bytes = BytesMut::with_capacity(content_length.unwrap_or(512).clamp(512, 4096));
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| DohRequestError::bad_request("invalid HTTP/2 body"))?;
        let chunk_len = chunk.len();
        if bytes.len() + chunk_len > MAX_DNS_MESSAGE_SIZE {
            release_capacity(&mut body, chunk_len)?;
            return Err(DohRequestError::payload_too_large("DNS query too large"));
        }
        bytes.extend_from_slice(&chunk);
        release_capacity(&mut body, chunk_len)?;
    }

    if let Some(content_length) = content_length
        && bytes.len() != content_length
    {
        return Err(DohRequestError::bad_request("body length mismatch"));
    }
    Ok(bytes)
}

fn release_capacity(body: &mut h2::RecvStream, len: usize) -> Result<(), DohRequestError> {
    body.flow_control()
        .release_capacity(len)
        .map_err(|_| DohRequestError::bad_request("invalid HTTP/2 flow control"))
}

fn find_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let raw_key = parts.next().unwrap_or_default();
        if percent_decode(raw_key)? != key {
            continue;
        }
        let raw_value = parts.next().unwrap_or_default();
        return percent_decode(raw_value);
    }
    None
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = hex_value(bytes[index + 1])?;
                let lo = hex_value(bytes[index + 2])?;
                decoded.push((hi << 4) | lo);
                index += 3;
            }
            b'%' => return None,
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_content_length(headers: &http::HeaderMap) -> Result<Option<usize>, DohRequestError> {
    headers
        .get(header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| DohRequestError::bad_request("invalid Content-Length"))?
                .parse::<usize>()
                .map_err(|_| DohRequestError::bad_request("invalid Content-Length"))
        })
        .transpose()
}

#[derive(Debug)]
pub(super) struct DohRequestError {
    status: StatusCode,
    message: &'static str,
}

impl DohRequestError {
    fn bad_request(message: &'static str) -> Self {
        Self { status: StatusCode::BAD_REQUEST, message }
    }

    fn not_found(message: &'static str) -> Self {
        Self { status: StatusCode::NOT_FOUND, message }
    }

    fn not_acceptable(message: &'static str) -> Self {
        Self { status: StatusCode::NOT_ACCEPTABLE, message }
    }

    fn unsupported_media_type(message: &'static str) -> Self {
        Self {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            message,
        }
    }

    fn payload_too_large(message: &'static str) -> Self {
        Self { status: StatusCode::PAYLOAD_TOO_LARGE, message }
    }

    fn request_timeout(message: &'static str) -> Self {
        Self { status: StatusCode::REQUEST_TIMEOUT, message }
    }

    pub(super) fn status(&self) -> StatusCode {
        self.status
    }

    pub(super) fn message(&self) -> &'static str {
        self.message
    }
}

impl std::fmt::Display for DohRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_message_decodes_dns_query_param() {
        let uri = "/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB".parse().unwrap();

        let bytes = extract_get_message(&uri).unwrap();

        assert!(!bytes.is_empty());
    }

    #[test]
    fn get_message_requires_dns_query_param() {
        let uri = "/dns-query".parse().unwrap();

        let err = extract_get_message(&uri).unwrap_err();

        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn get_message_rejects_invalid_base64() {
        let uri = "/dns-query?dns=%%%".parse().unwrap();

        let err = extract_get_message(&uri).unwrap_err();

        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn verify_get_does_not_require_content_type() {
        let request = HttpRequest::builder()
            .method(Method::GET)
            .uri("https://dns.example/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
            .version(http::Version::HTTP_2)
            .header(header::ACCEPT, MIME_APPLICATION_DNS)
            .body(())
            .unwrap();

        verify_doh_request(Some("dns.example"), "/dns-query", &request).unwrap();
    }

    #[test]
    fn verify_get_allows_missing_accept() {
        let request = HttpRequest::builder()
            .method(Method::GET)
            .uri("https://dns.example/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
            .version(http::Version::HTTP_2)
            .body(())
            .unwrap();

        verify_doh_request(Some("dns.example"), "/dns-query", &request).unwrap();
    }

    #[test]
    fn verify_get_allows_case_insensitive_accept() {
        let request = HttpRequest::builder()
            .method(Method::GET)
            .uri("https://dns.example/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
            .version(http::Version::HTTP_2)
            .header(header::ACCEPT, "Application/DNS-Message")
            .body(())
            .unwrap();

        verify_doh_request(Some("dns.example"), "/dns-query", &request).unwrap();
    }

    #[test]
    fn verify_get_rejects_zero_quality_accept() {
        let request = HttpRequest::builder()
            .method(Method::GET)
            .uri("https://dns.example/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
            .version(http::Version::HTTP_2)
            .header(header::ACCEPT, "application/dns-message;q=0, text/plain")
            .body(())
            .unwrap();

        let err = verify_doh_request(Some("dns.example"), "/dns-query", &request).unwrap_err();

        assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[test]
    fn verify_get_rejects_zero_quality_wildcard_accept() {
        let request = HttpRequest::builder()
            .method(Method::GET)
            .uri("https://dns.example/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
            .version(http::Version::HTTP_2)
            .header(header::ACCEPT, "text/plain, */*;q=0")
            .body(())
            .unwrap();

        let err = verify_doh_request(Some("dns.example"), "/dns-query", &request).unwrap_err();

        assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[test]
    fn verify_get_allows_nonzero_quality_wildcard_accept() {
        let request = HttpRequest::builder()
            .method(Method::GET)
            .uri("https://dns.example/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
            .version(http::Version::HTTP_2)
            .header(header::ACCEPT, "text/plain, application/*;q=0.5")
            .body(())
            .unwrap();

        verify_doh_request(Some("dns.example"), "/dns-query", &request).unwrap();
    }

    #[test]
    fn verify_post_requires_content_type() {
        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri("https://dns.example/dns-query")
            .version(http::Version::HTTP_2)
            .header(header::ACCEPT, MIME_APPLICATION_DNS)
            .body(())
            .unwrap();

        let err = verify_doh_request(Some("dns.example"), "/dns-query", &request).unwrap_err();

        assert_eq!(err.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn verify_post_allows_case_insensitive_content_type_with_params() {
        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri("https://dns.example/dns-query")
            .version(http::Version::HTTP_2)
            .header(header::ACCEPT, MIME_APPLICATION_DNS)
            .header(header::CONTENT_TYPE, "Application/DNS-Message; charset=binary")
            .body(())
            .unwrap();

        verify_doh_request(Some("dns.example"), "/dns-query", &request).unwrap();
    }

    #[test]
    fn invalid_content_length_is_bad_request() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "abc".parse().unwrap());

        let err = parse_content_length(&headers).unwrap_err();

        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn request_timeout_maps_to_408() {
        let err = DohRequestError::request_timeout("HTTP/2 body timeout");

        assert_eq!(err.status(), StatusCode::REQUEST_TIMEOUT);
    }
}
