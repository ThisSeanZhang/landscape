pub(crate) mod stream;
pub(crate) mod tls;
pub(crate) mod udp;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{DnsResponse, Query};
use hickory_resolver::net::NetError;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub(crate) use crate::exp_conn_pool::transport::stream::connect_tcp;
pub(crate) use crate::exp_conn_pool::transport::tls::{connect_tls, dot_client_config};
pub(crate) use crate::exp_conn_pool::transport::udp::UdpExchange;

use crate::exp_conn_pool::transport::stream::StreamConnection;
use crate::exp_conn_pool::transport::tls::TlsConnection;

#[derive(Clone)]
pub(crate) struct WireQuery {
    /// Full RFC 1035 wire message; the first two bytes are the caller's
    /// message ID, which stream transports rewrite and restore.
    pub(crate) wire: Bytes,
    pub(crate) retry_interval: Duration,
    /// Question section, for UDP response validation (RFC 1035 §7.3).
    pub(crate) queries: Arc<[Query]>,
}

impl WireQuery {
    pub(crate) fn id(&self) -> u16 {
        u16::from_be_bytes([self.wire[0], self.wire[1]])
    }
}

pub(crate) enum Transport {
    Tcp(StreamConnection<OwnedReadHalf, OwnedWriteHalf>),
    Tls(TlsConnection),
    Udp(UdpExchange),
}

impl Transport {
    pub(crate) async fn query(&self, query: WireQuery) -> Result<DnsResponse, NetError> {
        match self {
            Transport::Tcp(conn) => conn.query(query).await,
            Transport::Tls(conn) => conn.query(query).await,
            Transport::Udp(conn) => conn.query(query).await,
        }
    }

    pub(crate) fn is_alive(&self) -> bool {
        match self {
            Transport::Tcp(conn) => conn.is_alive(),
            Transport::Tls(conn) => conn.is_alive(),
            Transport::Udp(conn) => conn.is_alive(),
        }
    }

    pub(crate) fn close(&self) {
        match self {
            Transport::Tcp(conn) => conn.close(),
            Transport::Tls(conn) => conn.close(),
            Transport::Udp(conn) => conn.close(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DialParams {
    pub(crate) mark_value: u32,
    pub(crate) bind_addr4: Option<Ipv4Addr>,
    pub(crate) bind_addr6: Option<Ipv6Addr>,
}

impl DialParams {
    pub(crate) fn bind_for(&self, addr: SocketAddr) -> Option<SocketAddr> {
        match addr {
            SocketAddr::V4(_) => self.bind_addr4.map(|ip| SocketAddr::new(IpAddr::V4(ip), 0)),
            SocketAddr::V6(_) => self.bind_addr6.map(|ip| SocketAddr::new(IpAddr::V6(ip), 0)),
        }
    }

    pub(crate) fn udp_bind_addr(&self, addr: SocketAddr) -> SocketAddr {
        self.bind_for(addr).unwrap_or(match addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        })
    }
}

#[cfg(test)]
pub(crate) fn wire_query(request: hickory_proto::op::DnsRequest) -> WireQuery {
    let (message, options) = request.into_parts();
    let queries: Arc<[Query]> = Arc::from(message.queries.clone());
    WireQuery {
        wire: Bytes::from(message.to_vec().expect("test request serializes")),
        retry_interval: options.retry_interval,
        queries,
    }
}
