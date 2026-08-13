use hickory_proto::{
    op::ResponseCode,
    rr::{rdata::svcb::SvcParamValue, RData, Record, RecordType},
};
use landscape_common::dns::rule::LandscapeDnsRecordType;
use landscape_common::{
    dns::rule::FilterResult,
    flow::{DnsRuntimeMarkInfo, FlowMarkInfo},
};

pub use landscape_common::dns::check::{
    CheckChainDnsResult, CheckDnsReq, CheckDnsResult, LandscapeRecord as CommonRecord,
};
use moka::future::Cache;
use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Instant};

pub fn to_common_records(records: Vec<Record>) -> Vec<CommonRecord> {
    records
        .into_iter()
        .map(|r| {
            let data = format!("{}", r.data);
            CommonRecord {
                name: r.name.to_string(),
                rr_type: r.record_type().to_string(),
                ttl: r.ttl,
                data,
            }
        })
        .collect()
}

pub(crate) mod connection;
pub(crate) mod domain;

pub mod error;
pub mod listener;
pub mod mdns;
pub mod server;

static RESOLVER_CONF: &'static str = "/etc/resolv.conf";
static RESOLVER_CONF_LD_BACK: &'static str = "/etc/resolv.conf.ld_back";

fn check_resolver_conf() -> bool {
    let resolver_file = PathBuf::from(RESOLVER_CONF);
    let resolver_file_back = PathBuf::from(RESOLVER_CONF_LD_BACK);
    let new_content = "nameserver 127.0.0.1\n";

    if resolver_file.is_symlink() {
        // symlink: remove it directly
        if let Err(e) = std::fs::remove_file(&resolver_file) {
            tracing::error!("remove {resolver_file:?} symlink error: {e}");
            return false;
        }
    } else if resolver_file.exists() {
        if resolver_file.is_file() {
            // regular file: check the backup file
            if resolver_file_back.exists() {
                if let Err(e) = std::fs::remove_file(&resolver_file) {
                    tracing::error!("remove {resolver_file:?} error: {e}");
                    return false;
                }
            } else {
                let Ok(()) = std::fs::rename(&resolver_file, &resolver_file_back) else {
                    tracing::error!("move {resolver_file:?} error, Skip it");
                    return false;
                };
            }
        } else {
            tracing::error!("{resolver_file:?} is neither a symlink nor a regular file, Skip it");
            return false;
        }
    }

    // write new content to /etc/resolv.conf
    if let Err(e) = std::fs::write(&resolver_file, new_content) {
        tracing::error!("write {resolver_file:?} error: {e}");
        return false;
    }
    true
}

pub fn prepare_system_dns() -> bool {
    check_resolver_conf()
}

/// restore /etc/resolv.conf on stop
pub fn restore_resolver_conf() {
    let resolver_file = PathBuf::from(RESOLVER_CONF);
    let resolver_file_back = PathBuf::from(RESOLVER_CONF_LD_BACK);

    if resolver_file_back.exists() {
        if let Err(e) = std::fs::rename(&resolver_file_back, &resolver_file) {
            tracing::error!("restore {resolver_file:?} from backup error: {e}");
        } else {
            tracing::info!("restored {resolver_file:?} from backup");
        }
    } else {
        tracing::warn!("no backup file found at {resolver_file_back:?}, skipping restore");
    }
}

pub fn convert_record_type(record_type: LandscapeDnsRecordType) -> RecordType {
    match record_type {
        LandscapeDnsRecordType::A => RecordType::A,
        LandscapeDnsRecordType::AAAA => RecordType::AAAA,
        LandscapeDnsRecordType::HTTPS => RecordType::HTTPS,
    }
}

#[derive(Clone, Debug)]
pub struct CacheDNSItem {
    pub rdatas: Vec<Record>,
    pub response_code: ResponseCode,
    pub insert_time: Instant,

    pub min_ttl: u32,
    pub mark: DnsRuntimeMarkInfo,
    pub filter: FilterResult,
    pub matched_rule_id: Option<uuid::Uuid>,
    pub matched_rule_order: Option<u32>,
}

impl CacheDNSItem {
    fn get_update_rules(&self) -> HashSet<FlowMarkInfo> {
        self.get_update_rules_with_mark(&self.mark)
    }

    fn get_update_rules_with_mark(&self, info: &DnsRuntimeMarkInfo) -> HashSet<FlowMarkInfo> {
        let mut result = HashSet::new();
        if !info.mark.need_insert_in_ebpf_map() {
            return result;
        }
        for rdata in self.rdatas.iter() {
            match &rdata.data {
                RData::A(a) => {
                    result.insert(FlowMarkInfo {
                        mark: info.mark.clone().into(),
                        ip: std::net::IpAddr::V4(a.0),
                        priority: info.priority,
                    });
                }
                RData::AAAA(a) => {
                    result.insert(FlowMarkInfo {
                        mark: info.mark.clone().into(),
                        ip: std::net::IpAddr::V6(a.0),
                        priority: info.priority,
                    });
                }
                // the ipv4hint / ipv6hint in HTTPS records may be used by the
                // client to connect directly, so write them into the eBPF map
                // as well to keep those connections under route mark control.
                RData::HTTPS(https) => {
                    for (_key, value) in https.0.svc_params.iter() {
                        match value {
                            SvcParamValue::Ipv4Hint(hint) => {
                                for a in hint.0.iter() {
                                    result.insert(FlowMarkInfo {
                                        mark: info.mark.clone().into(),
                                        ip: std::net::IpAddr::V4(a.0),
                                        priority: info.priority,
                                    });
                                }
                            }
                            SvcParamValue::Ipv6Hint(hint) => {
                                for aaaa in hint.0.iter() {
                                    result.insert(FlowMarkInfo {
                                        mark: info.mark.clone().into(),
                                        ip: std::net::IpAddr::V6(aaaa.0),
                                        priority: info.priority,
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        result
    }
}

pub type DNSCache = Cache<(Arc<str>, RecordType), Arc<CacheDNSItem>>;
