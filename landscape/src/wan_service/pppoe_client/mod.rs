use landscape_common::net::MacAddr;

mod error;
mod lcp;
mod negotiation;
mod runtime;

#[cfg(test)]
mod test_lcp;

pub use crate::pppoe_client::PPPoEClientConfig;
pub use error::PppoeError;
pub use runtime::run;

pub(crate) type PppoeResult<T> = Result<T, PppoeError>;

pub const DEFAULT_TIMEOUT: u64 = 3;
pub const LCP_ECHO_INTERVAL: u64 = 20;
pub const DEFAULT_CLIENT_MRU: u16 = 1492;
pub const ETH_P_PPOED: u16 = 0x8863;
pub const ETH_P_PPOES: u16 = 0x8864;

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
    tx: &mut tokio::sync::mpsc::Sender<Box<Vec<u8>>>,
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
    tx.send(Box::new(packet)).await.map_err(|_| PppoeError::ChannelClosed)?;
    Ok(())
}
