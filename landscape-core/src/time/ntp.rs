use std::{
    io,
    net::SocketAddr,
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use landscape_common::DEFAULT_TIME_FALLBACK_SERVER;

const NTP_UNIX_OFFSET_SECS: u64 = ((70_u64 * 365) + 17) * 24 * 60 * 60;

#[derive(Clone, Debug)]
pub struct NtpQueryResult {
    pub synced_time: SystemTime,
    pub server: String,
    pub offset_ms: f64,
    pub delay_ms: f64,
    pub sample_count: u8,
}

/// Abstract NTP query so the sync loop can be tested against a scripted source.
#[async_trait]
pub trait NtpClient: Send + Sync {
    async fn query(
        &self,
        servers: &[String],
        timeout: StdDuration,
        samples_per_server: u8,
    ) -> io::Result<NtpQueryResult>;
}

/// Production NTP client: parallel UDP samples, best sample by delay/offset.
pub struct UdpNtpClient;

#[async_trait]
impl NtpClient for UdpNtpClient {
    async fn query(
        &self,
        servers: &[String],
        timeout: StdDuration,
        samples_per_server: u8,
    ) -> io::Result<NtpQueryResult> {
        query_ntp_time_with_sampling(servers, timeout, samples_per_server).await
    }
}

async fn query_ntp_time_with_sampling(
    servers: &[String],
    timeout: StdDuration,
    samples_per_server: u8,
) -> io::Result<NtpQueryResult> {
    let mut set = tokio::task::JoinSet::new();
    for server in servers {
        for _ in 0..samples_per_server {
            let server = server.clone();
            set.spawn(async move {
                let result = tokio::time::timeout(timeout, query_ntp_time_from_server(&server))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTP query timed out"))
                    .and_then(|result| result);
                (server, result)
            });
        }
    }

    let mut last_error = None;
    let mut best_result: Option<NtpQueryResult> = None;

    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((_, Ok(result))) => {
                let replace = best_result
                    .as_ref()
                    .map(|best| {
                        result.delay_ms < best.delay_ms
                            || (result.delay_ms == best.delay_ms
                                && result.offset_ms.abs() < best.offset_ms.abs())
                    })
                    .unwrap_or(true);
                if replace {
                    best_result = Some(result);
                }
            }
            Ok((server, Err(err))) => {
                tracing::warn!(server, error = %err, "failed to query NTP server sample");
                last_error = Some(err);
            }
            Err(err) => {
                tracing::warn!(error = %err, "NTP sample task failed");
            }
        }
    }

    if let Some(mut best_result) = best_result {
        best_result.sample_count = samples_per_server;
        return Ok(best_result);
    }

    Err(last_error.unwrap_or_else(|| io::Error::other("no NTP server available")))
}

/// Bind a local socket matching the server address family so that `send_to`
/// never fails with `EINVAL` on the first resolved (possibly IPv6) address.
fn bind_addr_for(addr: &SocketAddr) -> &'static str {
    if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }
}

async fn query_ntp_time_from_server(server: &str) -> io::Result<NtpQueryResult> {
    use std::io::{Error, ErrorKind};

    let server_addr = normalize_ntp_server_addr(server);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&server_addr).await?.collect();
    if addrs.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "failed to resolve NTP server"));
    }

    let mut request = [0_u8; 48];
    request[0] = 0x1b;

    // Try every resolved address (e.g. AAAA before A) with a family-matched
    // socket; a failed attempt falls through to the next address instead of
    // failing the whole sample. A silent server keeps `recv_from` pending,
    // which the caller's `tokio::time::timeout` bounds.
    let mut last_err = None;
    for addr in addrs {
        let socket = match tokio::net::UdpSocket::bind(bind_addr_for(&addr)).await {
            Ok(socket) => socket,
            Err(err) => {
                tracing::warn!(%addr, error = %err, "failed to bind NTP query socket");
                last_err = Some(err);
                continue;
            }
        };

        let t1 = SystemTime::now();
        if let Err(err) = socket.send_to(&request, &addr).await {
            tracing::warn!(%addr, error = %err, "failed to send NTP request");
            last_err = Some(err);
            continue;
        }

        let mut response = [0_u8; 48];
        let (received_len, _) = match socket.recv_from(&mut response).await {
            Ok(received) => received,
            Err(err) => {
                tracing::warn!(%addr, error = %err, "failed to receive NTP response");
                last_err = Some(err);
                continue;
            }
        };
        let t4 = SystemTime::now();
        if received_len < response.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "incomplete NTP response"));
        }

        let mode = response[0] & 0x07;
        if mode != 4 && mode != 5 {
            return Err(Error::new(ErrorKind::InvalidData, "invalid NTP mode in response"));
        }

        let stratum = response[1];
        if stratum == 0 {
            return Err(Error::new(ErrorKind::InvalidData, "kiss-o'-death NTP response"));
        }

        let t2 = parse_ntp_timestamp(&response[32..40])?;
        let t3 = parse_ntp_timestamp(&response[40..48])?;
        let offset_ms = ((signed_duration_ms(t2, t1) + signed_duration_ms(t3, t4)) as f64) / 2.0;
        let delay_ms = (signed_duration_ms(t4, t1) - signed_duration_ms(t3, t2)).max(0) as f64;
        let synced_time = apply_offset(t4, offset_ms);

        return Ok(NtpQueryResult {
            synced_time,
            server: server_addr,
            offset_ms,
            delay_ms,
            sample_count: 1,
        });
    }

    Err(last_err.unwrap_or_else(|| Error::other("failed to query NTP server")))
}

fn normalize_ntp_server_addr(server: &str) -> String {
    let server = server.trim();
    if server.is_empty() {
        return DEFAULT_TIME_FALLBACK_SERVER.to_string();
    }

    if let Some((_, port)) = server.rsplit_once(':')
        && port.parse::<u16>().is_ok()
    {
        return server.to_string();
    }

    format!("{server}:123")
}

fn parse_ntp_timestamp(bytes: &[u8]) -> io::Result<SystemTime> {
    use std::io::{Error, ErrorKind};

    if bytes.len() != 8 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid NTP timestamp length"));
    }

    let seconds = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
    let fraction = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64;
    if seconds < NTP_UNIX_OFFSET_SECS {
        return Err(Error::new(ErrorKind::InvalidData, "invalid NTP timestamp"));
    }

    let unix_seconds = seconds - NTP_UNIX_OFFSET_SECS;
    let nanos = ((fraction as u128) * 1_000_000_000_u128 / (1_u128 << 32)) as u32;
    Ok(UNIX_EPOCH + StdDuration::new(unix_seconds, nanos))
}

fn signed_duration_ms(later: SystemTime, earlier: SystemTime) -> i128 {
    match later.duration_since(earlier) {
        Ok(duration) => duration.as_millis() as i128,
        Err(err) => -(err.duration().as_millis() as i128),
    }
}

fn apply_offset(base: SystemTime, offset_ms: f64) -> SystemTime {
    if offset_ms >= 0.0 {
        base + StdDuration::from_secs_f64(offset_ms / 1000.0)
    } else {
        base - StdDuration::from_secs_f64((-offset_ms) / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ntp_server_addresses() {
        assert_eq!(normalize_ntp_server_addr("pool.ntp.org"), "pool.ntp.org:123");
        assert_eq!(normalize_ntp_server_addr("time.example:124"), "time.example:124");
        assert_eq!(normalize_ntp_server_addr(""), DEFAULT_TIME_FALLBACK_SERVER);
    }

    #[test]
    fn parses_ntp_unix_epoch() {
        let bytes = (NTP_UNIX_OFFSET_SECS as u32).to_be_bytes();
        let timestamp = [bytes[0], bytes[1], bytes[2], bytes[3], 0, 0, 0, 0];

        assert_eq!(parse_ntp_timestamp(&timestamp).unwrap(), UNIX_EPOCH);
    }

    #[test]
    fn applies_positive_and_negative_offsets() {
        let base = UNIX_EPOCH + StdDuration::from_secs(10);

        assert_eq!(apply_offset(base, 500.0), base + StdDuration::from_millis(500));
        assert_eq!(apply_offset(base, -500.0), base - StdDuration::from_millis(500));
    }

    #[test]
    fn bind_addr_matches_address_family() {
        let v4 = SocketAddr::from(([127, 0, 0, 1], 123));
        let v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 123));

        assert_eq!(bind_addr_for(&v4), "0.0.0.0:0");
        assert_eq!(bind_addr_for(&v6), "[::]:0");
    }

    fn fake_ntp_timestamp(unix_secs: u64) -> [u8; 8] {
        let mut bytes = [0_u8; 8];
        bytes[..4].copy_from_slice(&((unix_secs + NTP_UNIX_OFFSET_SECS) as u32).to_be_bytes());
        bytes
    }

    /// Queries a local one-shot NTP responder; exercises numeric resolution and
    /// the family-matched socket binding of the real UDP client.
    async fn assert_query_against_local_responder(responder_bind: &str) {
        let responder = tokio::net::UdpSocket::bind(responder_bind).await.unwrap();
        let responder_addr = responder.local_addr().unwrap();

        let responder_task = tokio::spawn(async move {
            let mut buf = [0_u8; 48];
            let (_, peer) = responder.recv_from(&mut buf).await.unwrap();

            let unix_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let mut response = [0_u8; 48];
            response[0] = 0x24; // LI=0, VN=4, Mode=4 (server)
            response[1] = 1; // stratum
            response[32..40].copy_from_slice(&fake_ntp_timestamp(unix_secs));
            response[40..48].copy_from_slice(&fake_ntp_timestamp(unix_secs));
            responder.send_to(&response, peer).await.unwrap();
        });

        let server = responder_addr.to_string();
        let result =
            tokio::time::timeout(StdDuration::from_secs(2), query_ntp_time_from_server(&server))
                .await
                .expect("query timed out")
                .expect("query failed");

        responder_task.await.unwrap();
        assert_eq!(result.server, server);
        assert!(result.delay_ms >= 0.0);
        assert!(result.offset_ms.abs() < 1_000.0);
    }

    #[tokio::test]
    async fn queries_local_udp_responder_ipv4() {
        assert_query_against_local_responder("127.0.0.1:0").await;
    }

    #[tokio::test]
    async fn queries_local_udp_responder_ipv6() {
        // Regression: a v6 server address must get a v6 socket instead of a
        // fixed 0.0.0.0 bind whose send_to would fail with EINVAL.
        if tokio::net::UdpSocket::bind("[::1]:0").await.is_err() {
            return; // no IPv6 available in this environment
        }
        assert_query_against_local_responder("[::1]:0").await;
    }
}
