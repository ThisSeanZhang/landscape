use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Serialize, Deserialize, Debug, Clone, Default, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
#[serde(rename_all = "snake_case")]
#[serde(tag = "t")]
pub enum DnsUpstreamMode {
    #[default]
    Plaintext, // 传统 DNS（UDP/TCP，无加密）
    Tls {
        domain: String,
    }, // DNS over TLS (DoT)
    Https {
        domain: String,
    }, // DNS over HTTPS (DoH)
    Quic {
        domain: String,
    }, // DNS over Quic (DoQ)
}
