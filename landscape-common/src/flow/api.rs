use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::net::MacAddr;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowMatchRequest {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub src_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub src_ipv6: Option<Ipv6Addr>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub src_mac: Option<MacAddr>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowVerdictRequest {
    pub flow_id: u32,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub src_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub src_ipv6: Option<Ipv6Addr>,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub dst_ips: Vec<IpAddr>,
}
