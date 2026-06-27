use std::{collections::HashMap, net::Ipv6Addr};

use landscape_common::ipv6::lan::{LanPrefixGroupConfig, PrefixParentSource};
use landscape_common::ipv6_pd::IAPrefixMap;

pub mod connection;
pub mod dhcpv6;
pub mod icmpv6;
pub mod pd;
pub mod server;

use self::pd::{PdRange, PdSlotKey};

pub struct Ip6AssignInfo {}

pub enum AssignId {
    Duid,
    Mac,
}

// ── Prefix resolution result types ──

pub struct RaEntry {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}

pub struct NaEntry {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
}

pub struct PrefixState {
    pub ra_entries: Vec<RaEntry>,
    pub na_entries: Vec<NaEntry>,
    pub pd_ranges: Vec<PdRange>,
}

impl PrefixState {
    pub fn new() -> Self {
        PrefixState {
            ra_entries: Vec::new(),
            na_entries: Vec::new(),
            pd_ranges: Vec::new(),
        }
    }

    pub fn refresh(&mut self, groups: &[LanPrefixGroupConfig], prefix_map: &IAPrefixMap) {
        self.ra_entries.clear();
        self.na_entries.clear();
        self.pd_ranges.clear();

        for group in groups {
            let (parent_ip, parent_len, pd_lifetimes) = match &group.parent {
                PrefixParentSource::Static { base_prefix, parent_prefix_len } => (
                    pd::normalize_prefix(*base_prefix, *parent_prefix_len),
                    *parent_prefix_len,
                    (0u32, 0u32),
                ),
                PrefixParentSource::Pd { depend_iface, planned_parent_prefix_len: _ } => {
                    match prefix_map.load(depend_iface) {
                        Some(prefix) => (
                            pd::normalize_prefix(prefix.prefix_ip, prefix.prefix_len),
                            prefix.prefix_len,
                            (prefix.preferred_lifetime, prefix.valid_lifetime),
                        ),
                        None => continue,
                    }
                }
            };

            if let Some(ra) = &group.ra {
                let (pref_lt, valid_lt) = match &group.parent {
                    PrefixParentSource::Static { .. } => (ra.preferred_lifetime, ra.valid_lifetime),
                    PrefixParentSource::Pd { .. } => pd_lifetimes,
                };
                self.ra_entries.push(RaEntry {
                    prefix: parent_ip,
                    prefix_len: parent_len,
                    preferred_lifetime: pref_lt,
                    valid_lifetime: valid_lt,
                });
            }

            if group.na.is_some() {
                self.na_entries.push(NaEntry { prefix: parent_ip, prefix_len: parent_len });
            }

            if let Some(pd) = &group.pd {
                let (pref_lt, valid_lt) = match &group.parent {
                    PrefixParentSource::Static { .. } => {
                        if let Some(ra) = &group.ra {
                            (ra.preferred_lifetime, ra.valid_lifetime)
                        } else {
                            (0u32, 0u32)
                        }
                    }
                    PrefixParentSource::Pd { .. } => pd_lifetimes,
                };
                self.pd_ranges.push(PdRange {
                    group_id: group.group_id.clone(),
                    parent: parent_ip,
                    parent_len,
                    pool_len: pd.pool_len,
                    start_idx: pd.start_index,
                    end_idx: pd.end_index,
                    preferred_lifetime: pref_lt,
                    valid_lifetime: valid_lt,
                });
            }
        }
    }
}

pub struct Ipv6ServerStatus {
    assign_ip_map: HashMap<Ipv6Addr, Ip6AssignInfo>,
    assign_suffix_duid_map: HashMap<AssignId, Ipv6Addr>,
    prefix_state: PrefixState,
    // pd info
}
impl Ipv6ServerStatus {
    pub fn new() -> Self {
        Ipv6ServerStatus {
            assign_ip_map: todo!(),
            assign_suffix_duid_map: todo!(),
            prefix_state: PrefixState::new(),
        }
    }
    pub fn assign_ipv6() {}
    pub fn assign_ipv6_pd() {}
    pub fn get_ra_prefixs() {}
    pub fn get_ra_onlink_prefixs() {}
    pub fn upate_prefix(&mut self, groups: &[LanPrefixGroupConfig], prefix_map: &IAPrefixMap) {
        self.prefix_state.refresh(groups, prefix_map);
    }

    pub fn upate_device(// ...
    ) {
    }

    pub fn ra_prefixes(&self) -> &[RaEntry] {
        &self.prefix_state.ra_entries
    }

    pub fn na_prefixes(&self) -> &[NaEntry] {
        &self.prefix_state.na_entries
    }

    pub fn pd_ranges(&self) -> &[PdRange] {
        &self.prefix_state.pd_ranges
    }

    pub fn resolve_pd_prefix(&self, key: &PdSlotKey) -> Option<(Ipv6Addr, u8)> {
        pd::resolve_pd_prefix(&self.prefix_state.pd_ranges, key)
    }
}
