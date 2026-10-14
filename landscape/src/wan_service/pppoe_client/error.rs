use std::fmt;

#[derive(Debug)]
pub enum PppoeError {
    // === Fatal: should not retry, exit directly ===
    AuthFailed(String),
    IfaceNotFound(String),
    EbpfInitFailed(String),
    LcpConfigRejected,
    IpRequiredButRejected,
    UnsupportedAuthType(u16),

    // === Retryable: can retry dialing ===
    DiscoveryTimeout,
    /// The AC answered PADO/PADS with an RFC 2516 §5.4 error tag
    /// (Service-Name-Error / AC-System-Error / Generic-Error).
    DiscoveryRejected(String),
    LcpTimeout,
    EchoFailed(u8),
    PeerTerminated,
    PadtReceived,
    Ipv6cpRejected,
    ChannelClosed,
    SendError(String),

    // === External signal ===
    ServiceStopped,
}

impl fmt::Display for PppoeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed(reason) => write!(f, "authentication failed: {reason}"),
            Self::IfaceNotFound(name) => write!(f, "interface not found: {name}"),
            Self::EbpfInitFailed(msg) => write!(f, "eBPF initialization failed: {msg}"),
            Self::LcpConfigRejected => write!(f, "peer rejected LCP configuration"),
            Self::IpRequiredButRejected => write!(f, "peer rejected IPCP, no IPv4 assigned"),
            Self::UnsupportedAuthType(t) => write!(f, "unsupported authentication type: 0x{t:04x}"),
            Self::DiscoveryTimeout => write!(f, "PPPoE discovery timeout"),
            Self::DiscoveryRejected(reason) => write!(f, "discovery rejected by peer: {reason}"),
            Self::LcpTimeout => write!(f, "LCP negotiation timeout"),
            Self::EchoFailed(n) => {
                write!(f, "LCP echo keepalive failed ({n} consecutive failures)")
            }
            Self::PeerTerminated => write!(f, "peer terminated the session"),
            Self::PadtReceived => write!(f, "peer sent PPPoE PADT, session terminated"),
            Self::Ipv6cpRejected => write!(f, "peer rejected IPv6CP"),
            Self::ChannelClosed => write!(f, "eBPF channel closed unexpectedly"),
            Self::SendError(reason) => write!(f, "packet send error: {reason}"),
            Self::ServiceStopped => write!(f, "service stopped by user"),
        }
    }
}

impl std::error::Error for PppoeError {}

impl PppoeError {
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::AuthFailed(_)
                | Self::IfaceNotFound(_)
                | Self::EbpfInitFailed(_)
                | Self::LcpConfigRejected
                | Self::IpRequiredButRejected
                | Self::UnsupportedAuthType(_)
        )
    }

    pub fn can_redial(&self) -> bool {
        !self.is_fatal() && !matches!(self, Self::ServiceStopped)
    }
}
