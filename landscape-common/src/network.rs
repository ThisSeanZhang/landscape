use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum LandscapeIpProtocolCode {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ICMPv6 = 58,
}
