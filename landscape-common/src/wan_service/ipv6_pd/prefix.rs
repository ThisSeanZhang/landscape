use std::net::Ipv6Addr;

pub const fn prefix_len_meets_expectation(actual_prefix_len: u8, expected_pd_len: u8) -> bool {
    actual_prefix_len <= expected_pd_len
}

pub const fn pd_expectation_fits_snapshot(expected_pd_len: u8, snapshot_prefix_len: u8) -> bool {
    expected_pd_len <= snapshot_prefix_len
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LDIAPrefix {
    /// unit: s
    pub preferred_lifetime: u32,
    /// unit: s
    pub valid_lifetime: u32,
    pub prefix_len: u8,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix_ip: Ipv6Addr,

    pub last_update_time: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IPV6PDPrefixStatus {
    pub expected_pd_len: u8,
    pub actual_prefix: LDIAPrefix,
    pub meets_expected_pd_len: bool,
}

impl IPV6PDPrefixStatus {
    pub fn new(expected_pd_len: u8, actual_prefix: LDIAPrefix) -> Self {
        let meets_expected_pd_len =
            prefix_len_meets_expectation(actual_prefix.prefix_len, expected_pd_len);
        Self {
            expected_pd_len,
            actual_prefix,
            meets_expected_pd_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::{
        IPV6PDPrefixStatus, LDIAPrefix, pd_expectation_fits_snapshot, prefix_len_meets_expectation,
    };

    fn prefix(prefix_len: u8) -> LDIAPrefix {
        LDIAPrefix {
            preferred_lifetime: 300,
            valid_lifetime: 600,
            prefix_len,
            prefix_ip: Ipv6Addr::LOCALHOST,
            last_update_time: 0.0,
        }
    }

    #[test]
    fn larger_or_equal_network_meets_expected_pd_len() {
        assert!(IPV6PDPrefixStatus::new(60, prefix(56)).meets_expected_pd_len);
        assert!(IPV6PDPrefixStatus::new(60, prefix(60)).meets_expected_pd_len);
    }

    #[test]
    fn compatibility_helpers_follow_prefix_length_ordering() {
        assert!(prefix_len_meets_expectation(56, 60));
        assert!(prefix_len_meets_expectation(60, 60));
        assert!(!prefix_len_meets_expectation(64, 60));

        assert!(pd_expectation_fits_snapshot(56, 60));
        assert!(pd_expectation_fits_snapshot(60, 60));
        assert!(!pd_expectation_fits_snapshot(64, 60));
    }

    #[test]
    fn smaller_network_does_not_meet_expected_pd_len() {
        assert!(!IPV6PDPrefixStatus::new(60, prefix(64)).meets_expected_pd_len);
    }
}
