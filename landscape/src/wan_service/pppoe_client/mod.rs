use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::PointToPoint;
use landscape_common::net_proto::pppoe::PPPoEFrame;

use uuid::Uuid;

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

#[cfg(test)]
mod test_runtime;

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
    pub link_id: Uuid,
    /// eBPF chain slot of the owning wan link.
    pub chain_id: u16,
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
        link_id: Uuid,
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
            link_id,
            chain_id: 0,
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
/// Consecutive unanswered LCP echo requests before the session is
/// considered dead. Shared by the negotiation and keepalive phases.
pub(crate) const MAX_ECHO_FAILURES: u8 = 5;

/// Maximum number of consecutive Configure-Naks sent while answering peer
/// LCP renegotiation requests before disagreeing options are escalated to
/// Configure-Reject (pppd's `DEFMAXNAKLOOPS` / `reject_if_disagree`
/// behavior; RFC 1661 §4.5 recommends loop detection for exactly this
/// negotiation ping-pong).
pub(crate) const MAX_NAK_LOOPS: u8 = 5;

/// LCP option types (RFC 1661 Appendix A).
pub(crate) const OPT_MRU: u8 = 1;
pub(crate) const OPT_AUTH: u8 = 3;
pub(crate) const OPT_MAGIC: u8 = 5;

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

/// Send a PPPoE PADT (code 0xa7) on the discovery ethertype to close the
/// session at the PPPoE layer (RFC 2516 §5.6). Best-effort: callers that are
/// already tearing down may ignore errors.
pub(crate) async fn send_padt(
    server_mac: &[u8],
    src_mac: MacAddr,
    session_id: u16,
    tx: &mut tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<(), PppoeError> {
    let l2 = build_l2_header(server_mac, src_mac, ETH_P_PPOED);
    let frame = PPPoEFrame::get_padt(session_id);
    let packet: Vec<u8> = [l2.to_vec(), frame.convert_to_payload()].concat();
    tx.send(packet).await.map_err(|_| PppoeError::ChannelClosed)?;
    Ok(())
}

/// An inbound frame for an established PPPoE session.
pub(crate) enum SessionPacket {
    /// PPPoE PADT: the peer terminated the session (RFC 2516 §5.6). PADT
    /// arrives on the discovery ethertype (0x8863) and must be acted on
    /// immediately instead of waiting for LCP echo timeouts.
    Padt,
    Ppp(PointToPoint),
}

/// Parse a raw ethernet frame into a [`SessionPacket`] for the given
/// session. Accepts session data (0x8864) and PADT (0x8863, or defensively
/// also on 0x8864). Only frames whose ethernet source MAC is the
/// established peer's are considered.
pub(crate) fn parse_session_packet(
    raw: &[u8],
    session_id: u16,
    server_mac: &[u8],
) -> Option<SessionPacket> {
    if raw.len() < 16 {
        return None;
    }
    // Only frames from the established peer count: on a shared medium a
    // stray PADT from another host (session-id collision or broadcast)
    // must not tear down our session.
    if &raw[6..12] != server_mac {
        return None;
    }
    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    if ethertype != ETH_P_PPOES && ethertype != ETH_P_PPOED {
        return None;
    }
    let frame = PPPoEFrame::new(&raw[14..])?;
    if frame.is_terminate() {
        // A PADT closes the session only when it carries exactly our
        // session id: RFC 2516 §5.6 requires the PADT to carry the id of
        // the session being closed and the id MUST NOT be zero, and pppd
        // matches it strictly — so a stray PADT with another (or a
        // broadcast, sid 0) id must not tear down our session.
        if frame.sid == session_id {
            return Some(SessionPacket::Padt);
        }
        return None;
    }
    if ethertype != ETH_P_PPOES || frame.sid != session_id {
        return None;
    }
    PointToPoint::new(&frame.payload).map(SessionPacket::Ppp)
}

/// RFC 1661 §5.8: an Echo-Reply carries the sender's 4-byte Magic-Number
/// followed by a Data field of "zero or more octets" — pppd copies the
/// request payload verbatim into its reply, so replies longer than 4 bytes
/// are legal and only shorter ones are malformed. The reply only counts as
/// liveness evidence when the Magic-Number differs from our own (an equal
/// magic means the link is looped, RFC 1661 §6.4).
pub(crate) fn echo_reply_is_valid_liveness(ppp: &PointToPoint, own_magic: u32) -> bool {
    ppp.payload.len() >= 4
        && u32::from_be_bytes([ppp.payload[0], ppp.payload[1], ppp.payload[2], ppp.payload[3]])
            != own_magic
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const FOREIGN_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    const SID: u16 = 0x0042;

    fn wrap_eth(src: &[u8], ethertype: u16, payload: Vec<u8>) -> Vec<u8> {
        let mut packet = SERVER_MAC.to_vec();
        packet.extend_from_slice(src);
        packet.extend(ethertype.to_be_bytes());
        packet.extend(payload);
        packet
    }

    fn session_frame(sid: u16, ppp_payload: Vec<u8>) -> Vec<u8> {
        let frame = PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: ppp_payload.len() as u16,
            payload: ppp_payload,
        };
        frame.convert_to_payload()
    }

    fn echo_reply_payload(magic: u32) -> Vec<u8> {
        PointToPoint {
            protocol: 0xc021,
            code: 10,
            id: 1,
            length: 8,
            payload: magic.to_be_bytes().to_vec(),
        }
        .convert_to_payload()
    }

    #[test]
    fn echo_reply_liveness_validation() {
        let reply = |payload: Vec<u8>| PointToPoint {
            protocol: 0xc021,
            code: 10,
            id: 1,
            length: payload.len() as u16 + 4,
            payload,
        };

        // Peer magic: valid liveness evidence
        assert!(echo_reply_is_valid_liveness(
            &reply(0xFEED_FACE_u32.to_be_bytes().to_vec()),
            0xDEAD_BEEF
        ));
        // Our own magic: looped link, must not count (RFC 1661 §6.4)
        assert!(!echo_reply_is_valid_liveness(
            &reply(0xDEAD_BEEF_u32.to_be_bytes().to_vec()),
            0xDEAD_BEEF
        ));
        // Trailing Data beyond the Magic-Number is legal (RFC 1661 §5.8).
        assert!(echo_reply_is_valid_liveness(&reply(vec![1, 2, 3, 4, 5]), 0xDEAD_BEEF));
        // 16-byte reply as produced by pppd with lcp-rtt-file enabled:
        // magic + RTT magic + seconds + nanoseconds.
        let mut rtt = 0xFEED_FACE_u32.to_be_bytes().to_vec();
        rtt.extend(0x5254_5443_u32.to_be_bytes());
        rtt.extend(1_700_000_000u32.to_be_bytes());
        rtt.extend(123_456u32.to_be_bytes());
        assert!(echo_reply_is_valid_liveness(&reply(rtt), 0xDEAD_BEEF));
        // Our own magic plus trailing data is still looped-link evidence.
        let mut looped = 0xDEAD_BEEF_u32.to_be_bytes().to_vec();
        looped.extend([0, 0, 0, 0]);
        assert!(!echo_reply_is_valid_liveness(&reply(looped), 0xDEAD_BEEF));
        // No Magic-Number at all
        assert!(!echo_reply_is_valid_liveness(&reply(vec![]), 0xDEAD_BEEF));
        // Truncated magic
        assert!(!echo_reply_is_valid_liveness(&reply(vec![1, 2, 3]), 0xDEAD_BEEF));
    }

    #[test]
    fn padt_from_server_mac_accepted() {
        let raw =
            wrap_eth(&SERVER_MAC, ETH_P_PPOED, PPPoEFrame::get_padt(SID).convert_to_payload());
        assert!(
            matches!(parse_session_packet(&raw, SID, &SERVER_MAC), Some(SessionPacket::Padt)),
            "PADT from the established peer must terminate the session"
        );
    }

    #[test]
    fn broadcast_padt_sid_zero_from_server_mac_ignored() {
        // RFC 2516 §5.6: a PADT's session id MUST NOT be zero; pppd
        // matches the sid strictly, so a broadcast id must be ignored.
        let raw = wrap_eth(&SERVER_MAC, ETH_P_PPOED, PPPoEFrame::get_padt(0).convert_to_payload());
        assert!(
            parse_session_packet(&raw, SID, &SERVER_MAC).is_none(),
            "a PADT with broadcast sid 0 must be ignored even from the established peer"
        );
    }

    #[test]
    fn padt_from_foreign_mac_ignored() {
        let raw =
            wrap_eth(&FOREIGN_MAC, ETH_P_PPOED, PPPoEFrame::get_padt(SID).convert_to_payload());
        assert!(
            parse_session_packet(&raw, SID, &SERVER_MAC).is_none(),
            "a PADT with our session id but a foreign source MAC must be ignored"
        );
    }

    #[test]
    fn padt_for_other_session_from_server_mac_ignored() {
        let raw =
            wrap_eth(&SERVER_MAC, ETH_P_PPOED, PPPoEFrame::get_padt(0x7777).convert_to_payload());
        assert!(parse_session_packet(&raw, SID, &SERVER_MAC).is_none());
    }

    #[test]
    fn session_data_from_server_mac_parsed() {
        let raw = wrap_eth(&SERVER_MAC, ETH_P_PPOES, session_frame(SID, echo_reply_payload(1)));
        assert!(matches!(
            parse_session_packet(&raw, SID, &SERVER_MAC),
            Some(SessionPacket::Ppp(_))
        ));
    }

    #[test]
    fn session_data_from_foreign_mac_ignored() {
        let raw = wrap_eth(&FOREIGN_MAC, ETH_P_PPOES, session_frame(SID, echo_reply_payload(1)));
        assert!(
            parse_session_packet(&raw, SID, &SERVER_MAC).is_none(),
            "session data from a foreign source MAC must be ignored"
        );
    }
}
