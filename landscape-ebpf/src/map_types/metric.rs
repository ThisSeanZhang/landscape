//! Inner map of `metric_bucket_map` (see `share_map.skel.rs`).

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct NetMetricKey {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub l4_proto: u8,
    pub l3_proto: u8,
    pub flow_id: u8,
    pub trace_id: u8,
}

#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct NetMetricValue {
    pub pkt_num: u64,
    pub pkt_sizes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map_setting::share_map::types as share;

    #[test]
    fn metric_layouts_match_skel() {
        assert_size!(NetMetricKey, share::net_metric_key);
        assert_field!(NetMetricKey, share::net_metric_key, src_addr);
        assert_field!(NetMetricKey, share::net_metric_key, dst_addr);
        assert_field!(NetMetricKey, share::net_metric_key, src_port);
        assert_field!(NetMetricKey, share::net_metric_key, dst_port);
        assert_field!(NetMetricKey, share::net_metric_key, l4_proto);
        assert_field!(NetMetricKey, share::net_metric_key, l3_proto);
        assert_field!(NetMetricKey, share::net_metric_key, flow_id);
        assert_field!(NetMetricKey, share::net_metric_key, trace_id);

        assert_size!(NetMetricValue, share::net_metric_value);
        assert_field!(NetMetricValue, share::net_metric_value, pkt_num);
        assert_field!(NetMetricValue, share::net_metric_value, pkt_sizes);
    }
}
