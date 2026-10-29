use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::rr::{Record, RecordType};
use landscape_common::{
    dns::DohRuntimeConfig, metric::dns::DnsOutcome, sys_service::lan_hostname::LanHostnameConfig,
};
use landscape_core::lan_device::LanDeviceDirectory;

use crate::{domain::ParsedDomain, resolve::answer::response_code_for};

mod arpa;
mod ddr;
mod forward;
mod ports;
mod zone;

#[cfg(test)]
mod tests;

pub use ports::{DohAdvertiseProvider, LocalDnsAnswerProvider};

/// Result of the local classification stage. `Answered` carries a records
/// field (possibly empty); `Empty` carries none. Which variant a name lands
/// in is part of the check/refresh API contract, so the mapping must stay
/// stable: every `.arpa` branch answers with records present, while blocked
/// TLDs and local-zone apexes answer with records absent.
pub enum LocalAnswer {
    Answered { records: Vec<Record>, outcome: DnsOutcome },
    Empty { outcome: DnsOutcome },
}

impl LocalAnswer {
    /// The protocol response code this local answer implies. Local stages
    /// own their answer, so the code is derived from the business outcome
    /// (NXDOMAIN for negative classifications, ServFail for local errors,
    /// NoError otherwise).
    pub fn response_code(&self) -> hickory_proto::op::ResponseCode {
        match self {
            LocalAnswer::Answered { outcome, .. } | LocalAnswer::Empty { outcome } => {
                response_code_for(*outcome)
            }
        }
    }
}

/// Local answers that never leave the resolver: blocked TLDs, localhost, the
/// configured LAN hostname zone, `local.` (mDNS), reverse PTR for managed
/// addresses, special-use `.arpa` names and DoH Discovery of Resolvers (DDR)
/// records.
///
/// Device identity and addresses come from the LAN device directory (point
/// reads over the live tables); zone configuration is shared with the DHCPv4
/// server (LAN suffix in options 15/119) through the same `ArcSwap` handle.
#[derive(Clone)]
pub struct LocalResolver {
    directory: Arc<LanDeviceDirectory>,
    hostname_config: Arc<ArcSwap<LanHostnameConfig>>,
    local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
    doh_advertise_provider: Option<Arc<dyn DohAdvertiseProvider>>,
    doh_runtime: Option<DohRuntimeConfig>,
}

impl LocalResolver {
    pub fn new(
        directory: Arc<LanDeviceDirectory>,
        hostname_config: Arc<ArcSwap<LanHostnameConfig>>,
        local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
        doh_advertise_provider: Option<Arc<dyn DohAdvertiseProvider>>,
        doh_runtime: Option<DohRuntimeConfig>,
    ) -> Self {
        Self {
            directory,
            hostname_config,
            local_answer_provider,
            doh_advertise_provider,
            doh_runtime,
        }
    }

    fn is_enabled(&self) -> bool {
        self.hostname_config.load().enable
    }

    /// Local interface addresses shared with the redirect engine
    /// (`AllLocalIps` answer mode) and DDR records (address hints).
    pub fn local_answer_provider(&self) -> Option<&Arc<dyn LocalDnsAnswerProvider>> {
        self.local_answer_provider.as_ref()
    }

    /// Unified local stage of the resolution chain. Dispatches `.arpa` names
    /// to the reverse path and everything else to the forward path, so live
    /// queries, config checks and cache refreshes agree on one
    /// classification. Returns `None` when the name is not local and must
    /// continue to the cache/upstream stage.
    pub fn resolve_local(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<LocalAnswer> {
        if domain.name().ends_with(".arpa") {
            self.resolve_arpa(domain, query_type)
        } else {
            self.resolve_forward_local(domain, query_type)
        }
    }
}
