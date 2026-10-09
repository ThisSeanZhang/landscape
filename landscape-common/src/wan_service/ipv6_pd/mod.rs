pub mod config;
pub mod prefix;

pub use config::DEFAULT_EXPECTED_PD_LEN;
pub use prefix::{
    IPV6PDPrefixStatus, LDIAPrefix, pd_expectation_fits_snapshot, prefix_len_meets_expectation,
};
