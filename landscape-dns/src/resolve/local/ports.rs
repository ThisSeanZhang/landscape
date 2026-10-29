use std::{net::IpAddr, sync::Arc};

use hickory_proto::rr::RecordType;

pub trait LocalDnsAnswerProvider: Send + Sync {
    fn load_local_answer_addrs(&self, query_type: RecordType) -> Arc<Vec<IpAddr>>;

    fn load_local_answer_addrs_for_ifindex(
        &self,
        query_type: RecordType,
        ifindex: u32,
    ) -> Arc<Vec<IpAddr>> {
        let _ = query_type;
        let _ = ifindex;
        Arc::new(Vec::new())
    }
}

/// Supplies the DoH discovery (DDR) advertisement domains for local answers.
pub trait DohAdvertiseProvider: Send + Sync {
    fn advertise_domains(&self) -> Vec<String>;
}
