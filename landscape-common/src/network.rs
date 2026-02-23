use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/firewall.d.ts")]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum LandscapeIpProtocolCode {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ICMPv6 = 58,
}
