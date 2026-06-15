use landscape_common::net::MacAddr;

pub(crate) mod auth;
pub(crate) mod runtime;
pub(crate) mod session;
pub(crate) mod state;
pub(crate) mod system;

pub use runtime::create_pppoe_client;

const DEFAULT_TIME_OUT: u64 = 3;
const LCP_ECHO_INTERVAL: u64 = 20;

/// 接近于永久不触发的 秒数  s    m    h
// const PAUSE_FOREVER: u64 = 60 * 60 * 24 * 365 * 10;

const DEFAULT_CLIENT_MRU: u16 = 1492;
const ETH_P_PPOED: u16 = 0x8863;
const ETH_P_PPOES: u16 = 0x8864;

#[derive(Clone, Debug)]
pub struct PPPoEClientConfig {
    pub index: u32,
    pub iface_name: String,
    pub iface_mac: MacAddr,
    pub peer_id: String,
    pub password: String,
    pub default_router: bool,
    pub requested_mru: u16,
}

impl PPPoEClientConfig {
    pub fn new(
        index: u32,
        iface_name: String,
        iface_mac: MacAddr,
        peer_id: String,
        password: String,
        default_router: bool,
        requested_mru: u16,
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
        }
    }
}
