use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum LandscapeIpProtocolCode {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ICMPV6 = 58,
}
