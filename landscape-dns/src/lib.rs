use hickory_proto::rr::{Record, RecordType};
use landscape_common::flow::{mark::FlowDnsMark, FlowDnsMarkInfo};
use lru::LruCache;
use std::{collections::HashSet, time::Instant};

pub mod connection;
pub mod diff_server;
pub mod ip_rule;
pub mod rule;
pub mod server;
pub mod socket;

#[derive(Clone)]
pub struct CacheDNSItem {
    rdatas: Vec<Record>,
    insert_time: Instant,
    mark: FlowDnsMark,
}

impl CacheDNSItem {
    fn get_update_rules(&self) -> HashSet<FlowDnsMarkInfo> {
        self.get_update_rules_with_mark(&self.mark)
    }

    fn get_update_rules_with_mark(&self, mark: &FlowDnsMark) -> HashSet<FlowDnsMarkInfo> {
        let mut result = HashSet::new();
        for rdata in self.rdatas.iter() {
            match rdata.data() {
                hickory_proto::rr::RData::A(a) => {
                    if mark.need_insert_in_ebpf_map() {
                        result.insert(FlowDnsMarkInfo {
                            mark: self.mark.clone().into(),
                            ip: std::net::IpAddr::V4(a.0),
                        });
                    }
                }
                hickory_proto::rr::RData::AAAA(a) => {
                    if mark.need_insert_in_ebpf_map() {
                        result.insert(FlowDnsMarkInfo {
                            mark: self.mark.clone().into(),
                            ip: std::net::IpAddr::V6(a.0),
                        });
                    }
                }
                _ => {}
            }
        }
        result
    }
}

pub type DNSCache = LruCache<(String, RecordType), Vec<CacheDNSItem>>;
