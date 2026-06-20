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
use std::{collections::HashSet, path::PathBuf, time::Instant};

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

pub mod error;
pub mod listener;
pub mod mdns;
pub mod server;

static RESOLVER_CONF: &'static str = "/etc/resolv.conf";
static RESOLVER_CONF_LD_BACK: &'static str = "/etc/resolv.conf.ld_back";

fn check_resolver_conf() {
    let resolver_file = PathBuf::from(RESOLVER_CONF);
    let resolver_file_back = PathBuf::from(RESOLVER_CONF_LD_BACK);
    let new_content = "nameserver 127.0.0.1\n";

    if resolver_file.is_symlink() {
        // 如果是符号链接，直接删除
        std::fs::remove_file(&resolver_file).unwrap();
    } else if resolver_file.exists() {
        if resolver_file.is_file() {
            // 如果是普通文件，检查备份文件
            if resolver_file_back.exists() {
                std::fs::remove_file(&resolver_file).unwrap();
            } else {
                let Ok(()) = std::fs::rename(&resolver_file, &resolver_file_back) else {
                    tracing::error!("move {resolver_file:?} error, Skip it");
                    return;
                };
            }
        } else {
            panic!("other kind file");
        }
    }

    // 写入新内容到 /etc/resolv.conf
    std::fs::write(&resolver_file, new_content).unwrap();
}

pub fn prepare_system_dns() {
    check_resolver_conf();
}

/// 停止时恢复 /etc/resolv.conf
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
                // HTTPS 记录中的 ipv4hint / ipv6hint 包含客户端可能直接用来建连的
                // IP 地址，同样需要写入 eBPF map，确保这些连接也受路由标记控制。
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

pub type DNSCache = Cache<(String, RecordType), std::sync::Arc<CacheDNSItem>>;
