use core::ops::Range;
use serde::{Deserialize, Serialize};

use crate::wan_service::nat::error::NatServiceError;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NatConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = crate::wan_service::nat::PortRange))]
    pub tcp_range: Range<u16>,
    #[cfg_attr(feature = "openapi", schema(value_type = crate::wan_service::nat::PortRange))]
    pub udp_range: Range<u16>,
    #[cfg_attr(feature = "openapi", schema(value_type = crate::wan_service::nat::PortRange))]
    pub icmp_in_range: Range<u16>,
}

impl NatConfig {
    fn validate_range(name: &str, range: &Range<u16>) -> Result<(), NatServiceError> {
        if range.start == 0 {
            return Err(NatServiceError::PortStartZero { name: name.to_string() });
        }
        if range.start >= range.end {
            return Err(NatServiceError::PortRangeInvalid {
                name: name.to_string(),
                start: range.start,
                end: range.end,
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), NatServiceError> {
        Self::validate_range("tcp_range", &self.tcp_range)?;
        Self::validate_range("udp_range", &self.udp_range)?;
        Self::validate_range("icmp_in_range", &self.icmp_in_range)?;
        Ok(())
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            tcp_range: 32768..65535,
            udp_range: 32768..65535,
            icmp_in_range: 32768..65535,
        }
    }
}
