//! Event folding: the single-writer side of the directory.
//!
//! Everything in this module mutates the live tables and must only be called
//! from the projection task (and, for the `apply_*` functions, from tests).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dashmap::DashMap;
use landscape_common::event::hub::{
    EnrolledDeviceEvent, IPv4AssignEvent, IPv6AssignEvent, LanDiscoveryEvent,
};
use landscape_common::net::MacAddr;
use landscape_common::utils::time::get_f64_timestamp;
use uuid::Uuid;

use super::ANONYMOUS_TTL_SECS;
use super::LanDeviceDirectory;
use super::entry::{AddressSourceV4, AddressSourceV6, LanDeviceEntry, ipv6_interface_id};

impl LanDeviceDirectory {
    pub(super) fn update_entry(&self, id: &Uuid, f: impl FnOnce(&mut LanDeviceEntry)) -> bool {
        let Some(mut slot) = self.entries.get_mut(id) else { return false };
        let mut next = slot.value().as_ref().clone();
        f(&mut next);
        *slot = Arc::new(next);
        true
    }

    fn resolve_or_create_by_mac(&self, mac: MacAddr) -> Uuid {
        if let Some(id) = self.by_mac.get(&mac).map(|r| *r.value()) {
            return id;
        }
        let id = Uuid::new_v4();
        self.entries.insert(id, Arc::new(LanDeviceEntry::new(id, Some(mac), get_f64_timestamp())));
        self.by_mac.insert(mac, id);
        id
    }

    /// Claims `ip` for entry `id` under evidence-strength arbitration: when
    /// the address belongs to a different entry, a weaker claim is rejected
    /// (`false`), equal or stronger claims move the address over. Self-claims
    /// always succeed. A missing owner source (stale index) counts as weakest.
    fn claim_ipv4(&self, id: Uuid, ip: Ipv4Addr, source: AddressSourceV4) -> bool {
        let owner = self.by_ipv4.get(&ip).map(|r| *r.value()).filter(|owner| *owner != id);
        if let Some(owner) = owner {
            let owner_rank =
                self.entries.get(&owner).and_then(|e| e.ipv4_source).map_or(u8::MAX, |s| s.rank());
            if source.rank() > owner_rank {
                return false;
            }
            self.update_entry(&owner, |e| {
                if e.ipv4 == Some(ip) {
                    e.ipv4 = None;
                    e.ipv4_source = None;
                }
            });
        }
        self.by_ipv4.insert(ip, id);
        true
    }

    fn release_ipv4(&self, id: &Uuid, ip: Ipv4Addr) {
        self.by_ipv4.remove_if(&ip, |_, owner| *owner == *id);
        self.update_entry(id, |e| {
            if e.ipv4 == Some(ip) {
                e.ipv4 = None;
                e.ipv4_source = None;
            }
        });
    }

    /// Claims `ip` for entry `id` under evidence-strength arbitration; see
    /// [`Self::claim_ipv4`]. The owner's rank is per-address (an entry may
    /// hold addresses of different strengths).
    fn claim_ipv6(&self, id: Uuid, ip: Ipv6Addr, source: AddressSourceV6) -> bool {
        let owner = self.by_ipv6.get(&ip).map(|r| *r.value()).filter(|owner| *owner != id);
        if let Some(owner) = owner {
            let owner_rank = self
                .entries
                .get(&owner)
                .and_then(|e| e.ipv6_addrs.get(&ip).copied())
                .map_or(u8::MAX, |s| s.rank());
            if source.rank() > owner_rank {
                return false;
            }
            self.update_entry(&owner, |e| {
                e.ipv6_addrs.remove(&ip);
            });
        }
        self.by_ipv6.insert(ip, id);
        true
    }

    fn set_device_id(&self, id: &Uuid, device_id: Uuid) {
        let free = self
            .by_device_id
            .get(&device_id)
            .map(|r| *r.value())
            .is_none_or(|previous| previous == *id);
        if free {
            self.by_device_id.insert(device_id, *id);
            self.update_entry(id, |e| e.device_id = Some(device_id));
        }
    }

    /// Hostname (re)claim with enrolled-priority adjudication at write time.
    fn claim_hostname(&self, id: &Uuid, hostname: Option<String>, from_enroll: bool) {
        let Some(current) = self.entries.get(id).map(|e| e.value().clone()) else { return };

        let Some(punycode) = hostname else {
            if let Some(old) = &current.hostname {
                self.by_hostname.remove_if(old, |_, owner| *owner == *id);
            }
            self.update_entry(id, |e| {
                e.hostname = None;
                e.hostname_from_enroll = false;
            });
            return;
        };

        // Who held the target key before this claim?
        let previous_owner = self.by_hostname.get(&punycode).map(|r| *r.value());

        // A DHCP observation must not downgrade the entry's own enrolled
        // hostname (parity with the old hostname registry).
        if previous_owner == Some(*id) && current.hostname_from_enroll && !from_enroll {
            return;
        }

        if let Some(old) = &current.hostname {
            self.by_hostname.remove_if(old, |_, owner| *owner == *id);
        }

        if let Some(owner) = previous_owner
            && owner != *id
        {
            let owner_enrolled =
                self.entries.get(&owner).map(|e| e.hostname_from_enroll).unwrap_or(false);
            if owner_enrolled && !from_enroll {
                // An enrolled hostname wins over a DHCP-learned one.
                self.update_entry(id, |e| {
                    e.hostname = None;
                    e.hostname_from_enroll = false;
                });
                return;
            }
            self.update_entry(&owner, |e| {
                e.hostname = None;
                e.hostname_from_enroll = false;
            });
        }

        self.by_hostname.insert(punycode.clone(), *id);
        self.update_entry(id, |e| {
            e.hostname = Some(punycode);
            e.hostname_from_enroll = from_enroll;
        });
    }

    pub(super) fn apply_device_event(&self, event: EnrolledDeviceEvent) {
        match event {
            EnrolledDeviceEvent::Updated { old, new } => {
                let id = self
                    .by_device_id
                    .get(&new.id)
                    .map(|r| *r.value())
                    .or_else(|| self.by_mac.get(&new.mac).map(|r| *r.value()))
                    .or_else(|| {
                        old.as_ref().and_then(|o| self.by_mac.get(&o.mac).map(|r| *r.value()))
                    })
                    .unwrap_or_else(|| self.resolve_or_create_by_mac(new.mac));

                if let Some(old) = &old
                    && old.mac != new.mac
                {
                    self.by_mac.remove_if(&old.mac, |_, owner| *owner == id);
                }
                self.by_mac.insert(new.mac, id);
                self.by_device_id.insert(new.id, id);

                match new.ipv4 {
                    Some(ip) => {
                        self.claim_ipv4(id, ip, AddressSourceV4::Static);
                    }
                    None => {
                        if let Some((ip, AddressSourceV4::Static)) =
                            current_ipv4(&self.entries, &id)
                        {
                            self.release_ipv4(&id, ip);
                        }
                    }
                }

                let hostname_punycode =
                    new.hostname.as_ref().and_then(|h| idna::domain_to_ascii(h).ok());
                self.claim_hostname(&id, hostname_punycode, new.hostname.is_some());

                let suffix = new.ipv6.map(ipv6_interface_id);
                self.update_entry(&id, |e| {
                    e.mac = Some(new.mac);
                    e.device_id = Some(new.id);
                    e.display_name = Some(new.name.clone());
                    e.enrolled_ipv6_suffix = suffix;
                    match new.ipv4 {
                        Some(ip) => {
                            e.ipv4 = Some(ip);
                            e.ipv4_source = Some(AddressSourceV4::Static);
                        }
                        None => {
                            if e.ipv4_source == Some(AddressSourceV4::Static) {
                                e.ipv4 = None;
                                e.ipv4_source = None;
                            }
                        }
                    }
                    e.iface_name = new.iface_name.clone();
                    e.last_active = get_f64_timestamp();
                });
            }
            EnrolledDeviceEvent::Deleted { old } => {
                let Some(id) = self
                    .by_device_id
                    .get(&old.id)
                    .map(|r| *r.value())
                    .or_else(|| self.by_mac.get(&old.mac).map(|r| *r.value()))
                else {
                    return;
                };
                self.by_device_id.remove_if(&old.id, |_, owner| *owner == id);

                // Release enrolled-only data; observed leases/SLAAC stay so
                // the (now anonymous) device remains visible on the LAN.
                self.claim_hostname(&id, None, false);
                if let Some((ip, AddressSourceV4::Static)) = current_ipv4(&self.entries, &id) {
                    self.release_ipv4(&id, ip);
                }
                let static_v6: Vec<Ipv6Addr> = self
                    .entries
                    .get(&id)
                    .map(|e| {
                        e.ipv6_addrs
                            .iter()
                            .filter(|(_, s)| **s == AddressSourceV6::Static)
                            .map(|(ip, _)| *ip)
                            .collect()
                    })
                    .unwrap_or_default();
                for ip in static_v6 {
                    self.by_ipv6.remove_if(&ip, |_, owner| *owner == id);
                    self.update_entry(&id, |e| {
                        e.ipv6_addrs.remove(&ip);
                    });
                }
                self.update_entry(&id, |e| {
                    e.device_id = None;
                    e.display_name = None;
                    e.enrolled_ipv6_suffix = None;
                    e.last_active = get_f64_timestamp();
                });
            }
        }
    }

    pub(super) fn apply_ipv4_event(&self, event: IPv4AssignEvent) {
        match event {
            IPv4AssignEvent::Allocated(info) => {
                let id = self.resolve_or_create_by_mac(info.mac);
                // An enrolled static IPv4 wins over DHCP observations for the
                // same device (parity with the old hostname registry).
                let current = current_ipv4(&self.entries, &id);
                let static_conflict = current
                    .is_some_and(|(ip, source)| source == AddressSourceV4::Static && ip != info.ip);
                if !static_conflict {
                    let claimed = self.claim_ipv4(id, info.ip, AddressSourceV4::Lease);
                    let keep_static = current.is_some_and(|(ip, source)| {
                        source == AddressSourceV4::Static && ip == info.ip
                    });
                    self.update_entry(&id, |e| {
                        e.mac = Some(info.mac);
                        if claimed && !keep_static {
                            e.ipv4 = Some(info.ip);
                            e.ipv4_source = Some(AddressSourceV4::Lease);
                        }
                        e.iface_name = Some(info.iface_name.clone());
                        e.last_active = get_f64_timestamp();
                    });
                } else {
                    self.update_entry(&id, |e| e.last_active = get_f64_timestamp());
                }
                if let Some(device_id) = info.device_id {
                    self.set_device_id(&id, device_id);
                }
                if let Some(hostname) =
                    info.hostname.as_ref().and_then(|h| idna::domain_to_ascii(h).ok())
                {
                    self.claim_hostname(&id, Some(hostname), false);
                }
            }
            IPv4AssignEvent::Expired(info) => {
                let Some(id) = self.by_mac.get(&info.mac).map(|r| *r.value()) else { return };
                self.release_ipv4(&id, info.ip);
                if let Some(hostname) =
                    info.hostname.as_ref().and_then(|h| idna::domain_to_ascii(h).ok())
                {
                    let owned = self
                        .entries
                        .get(&id)
                        .map(|e| e.hostname.as_deref() == Some(hostname.as_str()))
                        .unwrap_or(false);
                    if owned {
                        self.claim_hostname(&id, None, false);
                    }
                }
                self.update_entry(&id, |e| e.last_active = get_f64_timestamp());
            }
        }
    }

    pub(super) fn apply_ipv6_event(&self, event: IPv6AssignEvent) {
        match event {
            IPv6AssignEvent::Allocated(info) => {
                let id = self.resolve_or_create_by_mac(info.mac);
                if let Some(device_id) = info.device_id {
                    self.set_device_id(&id, device_id);
                }
                let suffix = self.entries.get(&id).and_then(|e| e.enrolled_ipv6_suffix);
                for addr in &info.ips {
                    let source = AddressSourceV6::from_event(addr.source, suffix, addr.ip);
                    if self.claim_ipv6(id, addr.ip, source) {
                        self.update_entry(&id, |e| {
                            e.ipv6_addrs.insert(addr.ip, source);
                        });
                    }
                }
                self.update_entry(&id, |e| {
                    e.mac = Some(info.mac);
                    e.iface_name = Some(info.iface_name.clone());
                    e.last_active = get_f64_timestamp();
                });
            }
            IPv6AssignEvent::Expired(info) => {
                let Some(id) = self.by_mac.get(&info.mac).map(|r| *r.value()) else { return };
                for addr in &info.ips {
                    self.by_ipv6.remove_if(&addr.ip, |_, owner| *owner == id);
                    self.update_entry(&id, |e| {
                        e.ipv6_addrs.remove(&addr.ip);
                    });
                }
                self.update_entry(&id, |e| e.last_active = get_f64_timestamp());
            }
            IPv6AssignEvent::Flush(info) => {
                let id = self.resolve_or_create_by_mac(info.mac);
                if let Some(device_id) = info.device_id {
                    self.set_device_id(&id, device_id);
                }
                let suffix = self.entries.get(&id).and_then(|e| e.enrolled_ipv6_suffix);
                let previous: Vec<Ipv6Addr> = self
                    .entries
                    .get(&id)
                    .map(|e| e.ipv6_addrs.keys().copied().collect())
                    .unwrap_or_default();
                for ip in previous {
                    self.by_ipv6.remove_if(&ip, |_, owner| *owner == id);
                }
                self.update_entry(&id, |e| e.ipv6_addrs.clear());
                for addr in &info.ips {
                    let source = AddressSourceV6::from_event(addr.source, suffix, addr.ip);
                    if self.claim_ipv6(id, addr.ip, source) {
                        self.update_entry(&id, |e| {
                            e.ipv6_addrs.insert(addr.ip, source);
                        });
                    }
                }
                self.update_entry(&id, |e| {
                    e.mac = Some(info.mac);
                    e.iface_name = Some(info.iface_name.clone());
                    e.last_active = get_f64_timestamp();
                });
            }
        }
    }

    pub(super) fn apply_discovery_event(&self, event: LanDiscoveryEvent) {
        let now = get_f64_timestamp();

        // Entity resolution: MAC first (strong anchor), then the IP anchor.
        // A MAC-less observation attaches to whoever owns the IP, otherwise
        // an anonymous IP-anchored entry is created.
        let id = match event.mac {
            Some(mac) => self.resolve_or_create_by_mac(mac),
            None => {
                let anchored = match event.ip {
                    IpAddr::V4(ip) => self.by_ipv4.get(&ip).map(|r| *r.value()),
                    IpAddr::V6(ip) => self.by_ipv6.get(&ip).map(|r| *r.value()),
                };
                match anchored {
                    Some(id) => id,
                    None => {
                        let id = Uuid::new_v4();
                        self.entries.insert(id, Arc::new(LanDeviceEntry::new(id, None, now)));
                        id
                    }
                }
            }
        };

        match event.ip {
            IpAddr::V4(ip) => {
                // ARP is the weakest evidence: it fills in a missing IPv4 or
                // refreshes activity, but never displaces another entry's
                // lease/static address (rank arbitration in `claim_ipv4`).
                if current_ipv4(&self.entries, &id).is_none()
                    && self.claim_ipv4(id, ip, AddressSourceV4::Arp)
                {
                    self.update_entry(&id, |e| {
                        e.ipv4 = Some(ip);
                        e.ipv4_source = Some(AddressSourceV4::Arp);
                    });
                }
            }
            IpAddr::V6(ip) => {
                let known =
                    self.entries.get(&id).map(|e| e.ipv6_addrs.contains_key(&ip)).unwrap_or(false);
                if !known && self.claim_ipv6(id, ip, AddressSourceV6::Slaac) {
                    self.update_entry(&id, |e| {
                        e.ipv6_addrs.insert(ip, AddressSourceV6::Slaac);
                    });
                }
            }
        }

        if let Some(mac) = event.mac {
            self.update_entry(&id, |e| e.mac = Some(mac));
        }
        self.update_entry(&id, |e| {
            e.iface_name = Some(event.iface_name.clone());
            e.last_active = now;
        });
    }

    /// Drops anonymous entries idle beyond [`ANONYMOUS_TTL_SECS`]. Returns
    /// whether anything was removed.
    pub(super) fn sweep_expired(&self, now: f64) -> bool {
        let mut removed: Vec<Uuid> = Vec::new();
        self.entries.retain(|id, entry| {
            let keep = entry.device_id.is_some() || now - entry.last_active <= ANONYMOUS_TTL_SECS;
            if !keep {
                removed.push(*id);
            }
            keep
        });
        if removed.is_empty() {
            return false;
        }
        self.by_mac.retain(|_, owner| !removed.contains(owner));
        self.by_ipv4.retain(|_, owner| !removed.contains(owner));
        self.by_ipv6.retain(|_, owner| !removed.contains(owner));
        self.by_device_id.retain(|_, owner| !removed.contains(owner));
        self.by_hostname.retain(|_, owner| !removed.contains(owner));
        true
    }

    pub(super) fn rebuild_snapshot(&self) {
        let mut snapshot = super::DirectorySnapshot {
            built_at: get_f64_timestamp(),
            ..Default::default()
        };
        for entry in self.entries.iter() {
            let entry = entry.value().clone();
            snapshot.entries.insert(entry.entry_id, entry.clone());
            if let Some(mac) = entry.mac {
                snapshot.by_mac.insert(mac, entry.clone());
            }
            if let Some(ip) = entry.ipv4 {
                snapshot.by_ipv4.insert(ip, entry.clone());
            }
            for ip in entry.ipv6_addrs.keys() {
                snapshot.by_ipv6.insert(*ip, entry.clone());
            }
            if let Some(device_id) = entry.device_id {
                snapshot.by_device_id.insert(device_id, entry.clone());
            }
            if let Some(hostname) = &entry.hostname {
                snapshot.by_hostname.insert(hostname.clone(), entry.clone());
            }
        }
        self.snapshot.store(Arc::new(snapshot));
        self.watch_tx.send_replace(());
    }
}

fn current_ipv4(
    entries: &DashMap<Uuid, Arc<LanDeviceEntry>>,
    id: &Uuid,
) -> Option<(Ipv4Addr, AddressSourceV4)> {
    entries.get(id).and_then(|e| e.ipv4.zip(e.ipv4_source))
}
