use std::collections::HashSet;

use uuid::Uuid;

use crate::config_service::geo::GeoFileCacheKey;

#[derive(Clone, Debug)]
pub enum DnsEvent {
    RulesChanged { flow_id: Option<u32> },
    RedirectsChanged { flow_id: Option<u32> },
    DynamicRedirectsChanged { flow_id: Option<u32>, source_id: String },
    UpstreamsChanged { upstream_ids: Vec<Uuid> },
    GeoSitesChanged { changed_keys: Option<HashSet<GeoFileCacheKey>> },
    RuntimeConfigChanged,
    FlowUpdated,
}

#[derive(Clone, Debug)]
pub enum DstIpEvent {
    GeoIpUpdated { changed_keys: HashSet<GeoFileCacheKey> },
}
