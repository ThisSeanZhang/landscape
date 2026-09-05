use landscape_common::net::MacAddr;

pub(crate) mod auth;
mod error;
mod lcp;
mod negotiation;
mod runtime;
mod system;

#[cfg(test)]
mod test_lcp;

#[cfg(test)]
mod test_negotiation;
pub use error::PppoeError;
pub use runtime::run;

pub(crate) type PppoeResult<T> = Result<T, PppoeError>;

pub const DEFAULT_TIMEOUT: u64 = 3;
pub const LCP_ECHO_INTERVAL: u64 = 20;
pub const DEFAULT_CLIENT_MRU: u16 = 1492;
pub const ETH_P_PPOED: u16 = 0x8863;
pub const ETH_P_PPOES: u16 = 0x8864;

#[derive(Clone, Debug)]
pub struct PPPoEClientConfig {
    pub index: u32,
    pub iface_name: String,
    pub iface_mac: MacAddr,
    pub peer_id: String,
    pub password: String,
    pub default_router: bool,
    pub requested_mru: u16,
    pub ac_name: Option<String>,
    /// LCP echo keepalive interval in seconds. `None` uses the default
    /// `LCP_ECHO_INTERVAL` (20 s). Tests use a smaller value to speed up
    /// link-loss detection.
    pub lcp_echo_interval: Option<u64>,
    /// Base backoff (seconds) between redial attempts after a failed session.
    /// `None` uses the default 300 s; the delay grows linearly with the retry
    /// count and is capped at 30 minutes. Tests use a smaller value to speed
    /// up reconnect scenarios.
    pub redial_backoff_base_secs: Option<u64>,
}

impl PPPoEClientConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: u32,
        iface_name: String,
        iface_mac: MacAddr,
        peer_id: String,
        password: String,
        default_router: bool,
        requested_mru: u16,
        ac_name: Option<String>,
    ) -> Self {
        Self {
            index,
            iface_name,
            iface_mac,
            peer_id,
            password,
            default_router,
            requested_mru: if requested_mru == 0 {
                DEFAULT_CLIENT_MRU
            } else {
                requested_mru.min(DEFAULT_CLIENT_MRU)
            },
            ac_name,
            lcp_echo_interval: None,
            redial_backoff_base_secs: None,
        }
    }
}

pub(crate) const MAX_DISCOVERY_RETRIES: u8 = 5;
pub(crate) const MAX_LCP_RETRIES: u8 = 5;

pub(crate) fn build_l2_header(dst: &[u8], src_mac: MacAddr, ethertype: u16) -> [u8; 14] {
    let mut header = [0u8; 14];
    header[..6].copy_from_slice(dst);
    header[6..12].copy_from_slice(&src_mac.octets());
    header[12..14].copy_from_slice(&ethertype.to_be_bytes());
    header
}

pub(crate) async fn send_pppoe_session_frame(
    server_mac: &[u8],
    src_mac: MacAddr,
    session_id: u16,
    payload: Vec<u8>,
    tx: &mut tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<(), PppoeError> {
    use landscape_common::net_proto::pppoe::PPPoEFrame;
    let l2 = build_l2_header(server_mac, src_mac, ETH_P_PPOES);
    let frame = PPPoEFrame {
        ver: 1,
        t: 1,
        code: 0,
        sid: session_id,
        length: payload.len() as u16,
        payload,
    };
    let packet: Vec<u8> = [l2.to_vec(), frame.convert_to_payload()].concat();
    tx.send(packet).await.map_err(|_| PppoeError::ChannelClosed)?;
    Ok(())
}
