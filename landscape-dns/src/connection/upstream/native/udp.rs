//! Native plaintext-UDP transport.
//!
//! Mirrors the old hickory-net UDP path: a fresh connected socket (random
//! source port, SO_MARK applied) per query attempt, one datagram per attempt
//! — the pool retries at the attempt level, so a blackholed upstream is not
//! hammered — and up to three receive attempts validating id + question echo
//! before giving up.

use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{DnsRequestOptions, Message, MessageType, Query};

use crate::connection::provider::MarkRuntimeProvider;
use crate::connection::upstream::traits::{DnsConn, DnsConnError, DnsConnector, DnsTransport};

use super::{build_message, classify_message};

/// Builds (stateless) UDP connections to one endpoint.
pub(crate) struct UdpConnector {
    pub(super) addr: SocketAddr,
    pub(super) provider: MarkRuntimeProvider,
    pub(super) query_timeout: Duration,
}

impl Debug for UdpConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpConnector").field("addr", &self.addr).finish()
    }
}

#[async_trait]
impl DnsConnector for UdpConnector {
    async fn connect(&self) -> Result<Arc<dyn DnsConn>, DnsConnError> {
        Ok(Arc::new(UdpConn {
            addr: self.addr,
            provider: self.provider.clone(),
            query_timeout: self.query_timeout,
        }))
    }

    fn transport(&self) -> DnsTransport {
        DnsTransport::Udp
    }

    fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    /// Test-only endpoint introspection (topology assertions).
    #[cfg(test)]
    fn test_endpoint(&self) -> Option<(SocketAddr, String)> {
        Some((self.addr, "Udp".to_string()))
    }
}

/// A UDP "connection": stateless, one socket per query attempt. The pool's
/// connection accounting (reuse, retirement) is bookkeeping over it.
struct UdpConn {
    addr: SocketAddr,
    provider: MarkRuntimeProvider,
    query_timeout: Duration,
}

impl Debug for UdpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpConn").field("addr", &self.addr).finish()
    }
}

#[async_trait]
impl DnsConn for UdpConn {
    async fn query(
        &self,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> Result<Message, DnsConnError> {
        let mut message = build_message(query, options);
        // A random id per query: the connected socket filters foreign sources
        // and the id + question echo filter late/forged datagrams.
        message.metadata.id = rand::random();
        let bytes = message.to_vec().map_err(|e| DnsConnError::Internal(e.to_string()))?;

        let socket =
            self.provider.bind_udp(self.addr).await.map_err(|e| DnsConnError::Io(e.to_string()))?;
        socket.send(&bytes).await.map_err(|e| DnsConnError::Io(e.to_string()))?;

        // The receive buffer is the advertised EDNS payload (mirrors hickory:
        // responses larger than the advertised size are truncated and fail to
        // decode, which is the server's protocol violation).
        let mut buf = vec![0u8; usize::from(options.edns_payload_len.max(512))];
        let result = tokio::time::timeout(self.query_timeout, async {
            // Up to three receive attempts (hickory parity): mismatched or
            // undecodable datagrams are dropped, not fatal.
            for _ in 0..3 {
                let len =
                    socket.recv(&mut buf).await.map_err(|e| DnsConnError::Io(e.to_string()))?;
                if let Ok(response) = validate_response(&buf[..len], &message) {
                    return Ok(response);
                }
                // A *decodable* frame that failed validation is spoofed or
                // late — dropped, never trusted. An *undecodable* frame
                // carrying our id and the response bit is a kernel-truncated
                // answer: surface it as a synthesized truncated response so
                // the pool's truncation path (stream retry) recovers the
                // data instead of aging the attempt into a health-counted
                // Timeout.
                if Message::from_vec(&buf[..len]).is_err()
                    && let Some(truncated) = truncated_response(&buf[..len], &message)
                {
                    return Ok(truncated);
                }
            }
            Err(DnsConnError::Timeout)
        })
        .await;

        match result {
            Ok(result) => match result {
                Ok(message) => classify_message(message),
                Err(e) => Err(e),
            },
            Err(_) => Err(DnsConnError::Timeout),
        }
    }

    fn transport(&self) -> DnsTransport {
        DnsTransport::Udp
    }

    fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    fn shutdown(&self) {}
}

/// Mirrors hickory's UDP response validation: the message must be a response
/// with the query's id, and every question in the response must appear in the
/// request. Returns `None` for anything else (garbage, forged, late).
fn validate_response(bytes: &[u8], query: &Message) -> Result<Message, ()> {
    let response = Message::from_vec(bytes).map_err(|_| ())?;
    if response.metadata.message_type != MessageType::Response {
        return Err(());
    }
    if response.metadata.id != query.metadata.id {
        return Err(());
    }
    if !response.queries.iter().all(|q| query.queries.contains(q)) {
        return Err(());
    }
    Ok(response)
}

/// Detects a kernel-truncated response: a datagram larger than the receive
/// buffer is silently cut by the OS (an EDNS-ignoring server answering
/// beyond the advertised payload size without setting TC), so the message
/// fails to decode — but the 12-octet header survives. If it carries our id
/// and the response (QR) bit, this is our answer losing records, not
/// garbage: synthesize a minimal truncated response (echoed question, TC
/// bit) that flows through the pool's regular truncation handling — the
/// UDP→stream retry recovers the full answer, and the attempt does not age
/// into a `Timeout` that counts against the upstream's health.
fn truncated_response(bytes: &[u8], request: &Message) -> Option<Message> {
    let [b0, b1, b2, ..] = bytes else { return None };
    let id = u16::from_be_bytes([*b0, *b1]);
    // QR bit (0x80 in the flags' high byte) must say "response".
    if id != request.metadata.id || b2 & 0x80 == 0 {
        return None;
    }
    let mut truncated = Message::response(id, request.metadata.op_code);
    truncated.queries.clone_from(&request.queries);
    truncated.metadata.truncation = true;
    Some(truncated)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::op::{DnsRequestOptions, Message, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use super::*;

    fn query() -> Message {
        let mut message = build_message(
            &Query::query(Name::from_str("example.com.").unwrap(), RecordType::A),
            &DnsRequestOptions::default(),
        );
        message.metadata.id = 0x1234;
        message
    }

    fn coded_response(code: hickory_proto::op::ResponseCode) -> Message {
        let mut response = Message::response(0x1234, OpCode::Query);
        response.metadata.response_code = code;
        response
    }

    #[test]
    fn validates_id() {
        let mut wrong_id = coded_response(hickory_proto::op::ResponseCode::NoError);
        wrong_id.metadata.id = 0x9999;
        assert!(validate_response(&wrong_id.to_vec().unwrap(), &query()).is_err());
    }

    #[test]
    fn validates_question_echo() {
        // A response answering a different question is forged.
        let mut wrong_question = coded_response(hickory_proto::op::ResponseCode::NoError);
        wrong_question
            .queries
            .push(Query::query(Name::from_str("other.com.").unwrap(), RecordType::A));
        assert!(validate_response(&wrong_question.to_vec().unwrap(), &query()).is_err());

        // The exact echoed question is accepted.
        let mut echoed = coded_response(hickory_proto::op::ResponseCode::NoError);
        echoed.queries.clone_from(&query().queries);
        assert!(validate_response(&echoed.to_vec().unwrap(), &query()).is_ok());
    }

    #[test]
    fn rejects_non_response_messages() {
        assert!(validate_response(&query().to_vec().unwrap(), &query()).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(validate_response(&[0xde, 0xad, 0xbe, 0xef], &query()).is_err());
    }

    /// A full response cut to a header prefix (kernel truncation of an
    /// oversized datagram) is detected and synthesized into a truncated
    /// response carrying the echoed question and the TC bit.
    #[test]
    fn kernel_truncated_response_becomes_tc_fallback() {
        let request = query();
        let mut response = coded_response(hickory_proto::op::ResponseCode::NoError);
        response.queries.clone_from(&request.queries);
        response.answers.push(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let bytes = response.to_vec().unwrap();
        assert!(Message::from_vec(&bytes).is_ok());

        // Cut mid-question-section: undecodable, but the header (id + QR)
        // survives.
        let cut = &bytes[..20];
        assert!(Message::from_vec(cut).is_err());

        let synthesized = truncated_response(cut, &request).expect("must detect truncation");
        assert!(synthesized.metadata.truncation);
        assert_eq!(synthesized.metadata.id, request.metadata.id);
        assert_eq!(synthesized.queries, request.queries);
    }

    /// Datagrams that do not carry our id, carry the query (not response)
    /// bit, or are too short for a header are never mistaken for
    /// truncations. A header-only datagram with our id and the QR bit is
    /// indistinguishable from a kernel-truncated response and is accepted
    /// as one (it carries no records, so it can only trigger the stream
    /// retry, never inject data).
    #[test]
    fn foreign_or_query_datagrams_are_not_truncation() {
        let request = query();

        // Wrong id.
        let mut wrong_id = coded_response(hickory_proto::op::ResponseCode::NoError);
        wrong_id.metadata.id = 0x9999;
        let bytes = wrong_id.to_vec().unwrap();
        assert!(truncated_response(&bytes, &request).is_none());

        // Right id, but a query (QR bit clear).
        let bytes = request.to_vec().unwrap();
        assert!(truncated_response(&bytes, &request).is_none());

        // Shorter than a DNS header (id + flags).
        assert!(truncated_response(&[0x12, 0x34], &request).is_none());

        // Header-only with our id and the QR bit: treated as truncated.
        assert!(truncated_response(&[0x12, 0x34, 0x80], &request).is_some());
    }
}
