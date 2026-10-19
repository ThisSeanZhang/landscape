//! Global, single-instance controller for the WAN dispatch trie.
//!
//! [`WanTrieDispatcher`] owns the authoritative entry set and every write
//! to it: mutations go through [`WanTrieDispatcher::apply`] (or the sugar
//! methods), which updates the entry set and republishes to all registered
//! targets in one A/B flip. Production registers one target: the XDP seed's
//! arena, whose fd every other intro program reuses at load time.
//!
//! Register a program's table right after skeleton load and BEFORE attaching
//! the program: [`WanTrieDispatcher::register`] immediately publishes the
//! current entry set, so a fresh program never runs on a zeroed table. The
//! returned [`TargetGuard`] detaches on drop; store it next to the skeleton
//! (declared after it, so it drops first).

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::bpf_error::{LandscapeEbpfError, LdEbpfResult};

use super::builder::{
    PrefixEntry, masked_key, ppp_entry, reference_lpm, v4_entry, v6_entry, wan_trie_publish,
};
use super::types::WanTrieTbl;

/// After a `cur` flip, in-flight readers may still hold pointers into the
/// old half; a republish that would zero that half must wait at least this
/// long first. Packet walks finish in nanoseconds, so this is generous.
const FLIP_GRACE: Duration = Duration::from_millis(2);

/// One batchable mutation.
pub(crate) enum Op {
    /// Insert or replace (same masked key + plen).
    Set(PrefixEntry),
    /// Remove by (masked key, plen); missing keys are ignored.
    Del { prefix: [u8; 8], plen: u8 },
}

/// Dedup identity of an entry.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct TrieKey([u8; 8], u8);

impl TrieKey {
    fn of(e: &PrefixEntry) -> Self {
        Self(masked_key(e.prefix, e.plen), e.plen)
    }
}

struct Target {
    tbl: *mut WanTrieTbl,
    last_flip: Option<Instant>,
}

// SAFETY: the raw table pointer stays valid until the matching TargetGuard
// (declared after the owning skeleton) drops and detaches it; all dispatcher
// access is serialized by the inner mutex.
unsafe impl Send for Target {}

struct Inner {
    /// Authoritative entry set: masked key + plen -> dispatch root.
    entries: HashMap<TrieKey, u32>,
    targets: HashMap<u32, Target>,
    next_target_id: u32,
}

pub struct WanTrieDispatcher {
    inner: Mutex<Inner>,
}

impl WanTrieDispatcher {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                targets: HashMap::new(),
                next_target_id: 0,
            }),
        }
    }

    /// Register a program's mmap'd arena table as a publish target and
    /// immediately publish the current entry set. Returns a guard that
    /// detaches the target when dropped.
    ///
    /// Fails (without registering) when the initial publish cannot be
    /// built: the caller must treat the program's arena as unusable and
    /// abort the load/attach, instead of attaching over a zeroed table
    /// that would silently drop every dispatch.
    pub(crate) fn register(self: &Arc<Self>, tbl: &mut WanTrieTbl) -> LdEbpfResult<TargetGuard> {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_target_id;
        inner.next_target_id += 1;

        let list = entry_list(&inner);
        // SAFETY: the caller guarantees the table outlives the guard.
        wan_trie_publish(tbl, &list).map_err(|e| {
            tracing::error!("wan_trie: initial publish to target {id} failed: {e}");
            LandscapeEbpfError::Io(std::io::Error::other(e))
        })?;
        inner.targets.insert(
            id,
            Target {
                tbl: tbl as *mut _,
                last_flip: Some(Instant::now()),
            },
        );

        Ok(TargetGuard { id, dispatcher: Arc::downgrade(self) })
    }

    fn detach(&self, id: u32) {
        self.inner.lock().unwrap().targets.remove(&id);
    }

    /// Apply a batch of mutations and republish to every target in one
    /// flip per target. Holding the (internal) mutex across the flip —
    /// including the flip-grace wait — keeps writes serialized; writes are
    /// rare configuration events.
    pub(crate) fn apply(&self, ops: &[Op]) {
        let mut inner = self.inner.lock().unwrap();
        for op in ops {
            match op {
                Op::Set(e) => {
                    inner.entries.insert(TrieKey::of(e), e.root);
                }
                Op::Del { prefix, plen } => {
                    inner.entries.remove(&TrieKey(masked_key(*prefix, *plen), *plen));
                }
            }
        }
        publish_all(&mut inner);
    }

    /// IPv6 WAN prefix (PD delegation & friends).
    pub(crate) fn set_ipv6_prefix(
        &self,
        addr: Ipv6Addr,
        plen: u8,
        root: u32,
    ) -> Result<(), String> {
        let e = v6_entry(addr, plen, root)?;
        self.apply(&[Op::Set(e)]);
        Ok(())
    }

    pub(crate) fn del_ipv6_prefix(&self, addr: Ipv6Addr, plen: u8) {
        let prefix: [u8; 8] = addr.octets()[..8].try_into().unwrap();
        self.apply(&[Op::Del { prefix, plen }]);
    }

    /// IPv4 WAN prefix.
    pub(crate) fn set_ipv4_prefix(
        &self,
        addr: Ipv4Addr,
        plen: u8,
        root: u32,
    ) -> Result<(), String> {
        let e = v4_entry(addr, plen, root)?;
        self.apply(&[Op::Set(e)]);
        Ok(())
    }

    pub(crate) fn del_ipv4_prefix(&self, addr: Ipv4Addr, plen: u8) {
        // An invalid plen addresses nothing: deleting it is a no-op.
        let Ok(e) = v4_entry(addr, plen, 0) else { return };
        self.apply(&[Op::Del { prefix: e.prefix, plen: 8 + plen }]);
    }

    /// PPPoE session binding: `(ifindex, session)` — session ids are
    /// assigned per-NIC by the BRAS, the ingress ifindex namespaces them.
    pub(crate) fn set_ppp_session(&self, ifindex: u32, session: u16, root: u32) {
        self.apply(&[Op::Set(ppp_entry(ifindex, session, root))]);
    }

    pub(crate) fn del_ppp_session(&self, ifindex: u32, session: u16) {
        self.apply(&[Op::Del {
            prefix: ppp_entry(ifindex, session, 0).prefix,
            plen: 56,
        }]);
    }

    /// Userspace mirror lookup over the authoritative set (tests/debug).
    pub(crate) fn resolve(&self, key: &[u8; 8]) -> u32 {
        let inner = self.inner.lock().unwrap();
        let list = entry_list(&inner);
        reference_lpm(&list, key)
    }
}

fn entry_list(inner: &Inner) -> Vec<PrefixEntry> {
    inner
        .entries
        .iter()
        .map(|(TrieKey(p, plen), root)| PrefixEntry { prefix: *p, plen: *plen, root: *root })
        .collect()
}

fn publish_all(inner: &mut Inner) {
    if inner.targets.is_empty() {
        return;
    }
    let list = entry_list(inner);
    for (id, t) in inner.targets.iter_mut() {
        if let Some(last) = t.last_flip {
            let elapsed = last.elapsed();
            if elapsed < FLIP_GRACE {
                std::thread::sleep(FLIP_GRACE - elapsed);
            }
        }
        // SAFETY: valid until the TargetGuard drops and detaches.
        // A failure is logged and skipped: `wan_trie_publish` gives up
        // before flipping `cur`, so the target keeps serving its previous
        // (complete) table until a later publish succeeds.
        if let Err(e) = wan_trie_publish(unsafe { &mut *t.tbl }, &list) {
            tracing::error!("wan_trie: publish to target {id} failed: {e}");
        }
        t.last_flip = Some(Instant::now());
    }
}

/// Cast a generated skel's `wan_trie_tbl` arena global to the mirror type.
/// The generated and mirror layouts are pinned equal by the wan_trie layout
/// tests (the same C header generates both).
pub(crate) fn cast_arena_tbl<T>(generated: &mut T) -> &mut WanTrieTbl {
    assert_eq!(
        std::mem::size_of::<T>(),
        std::mem::size_of::<WanTrieTbl>(),
        "generated wan_trie_tbl layout drifted from the mirror"
    );
    // SAFETY: identical #[repr(C)] layouts, pinned by tests.
    unsafe { &mut *(generated as *mut T as *mut WanTrieTbl) }
}

/// Owns a registered skeleton together with its [`TargetGuard`].
///
/// The dispatcher holds a raw pointer into the skeleton's arena mmap, so
/// the target MUST be detached (guard drop) before the mmap closes
/// (skeleton drop). Lifetimes cannot express that: targets have
/// independent dynamic lifetimes under the one global dispatcher, and a
/// guard borrowing the skeleton could not live in the same handle struct
/// (self-referential). This wrapper is the structural substitute: the
/// drop-order invariant exists in exactly one place — the field order
/// below — instead of in every owning handle.
pub(crate) struct TrieTarget<S> {
    #[allow(dead_code)]
    guard: TargetGuard,
    pub skel: S,
}

impl<S> TrieTarget<S> {
    /// Wrap a skeleton together with its target guard.
    pub(crate) fn from_parts(guard: TargetGuard, skel: S) -> Self {
        Self { guard, skel }
    }
}

/// Detaches its publish target on drop. Declare the guard field BEFORE the
/// owning skeleton field: fields drop in declaration order, so the target is
/// detached while the arena mmap is still alive.
pub struct TargetGuard {
    id: u32,
    dispatcher: Weak<WanTrieDispatcher>,
}

impl Drop for TargetGuard {
    fn drop(&mut self) {
        if let Some(d) = self.dispatcher.upgrade() {
            d.detach(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use super::super::builder::wan_trie_resolve;

    use super::super::builder::tests::{d, tbl};

    fn dispatcher() -> Arc<WanTrieDispatcher> {
        Arc::new(WanTrieDispatcher::new())
    }

    /// Sugar methods land in every registered target and in the
    /// userspace mirror; four namespaces coexist without crosstalk.
    #[test]
    fn sugar_methods_publish_to_targets() {
        let disp = dispatcher();
        let t1 = tbl();
        let mut t1 = t1;
        let _g1 = disp.register(&mut t1).unwrap();

        disp.set_ipv6_prefix(Ipv6Addr::from_str("fd22:2222:33ab::").unwrap(), 48, 71).unwrap();
        disp.set_ipv4_prefix(Ipv4Addr::new(203, 0, 113, 0), 24, 72).unwrap();
        disp.set_ppp_session(9, 0x1234, 73);

        assert_eq!(wan_trie_resolve(&t1, &d("fd22:2222:33ab::1")), 71);
        let v4_key = v4_entry(Ipv4Addr::new(203, 0, 113, 9), 32, 0).unwrap().prefix;
        assert_eq!(wan_trie_resolve(&t1, &v4_key), 72);
        assert_eq!(wan_trie_resolve(&t1, &ppp_entry(9, 0x1234, 0).prefix), 73);
        assert_eq!(wan_trie_resolve(&t1, &ppp_entry(8, 0x1234, 0).prefix), 0);
        assert_eq!(wan_trie_resolve(&t1, &d("fd99::1")), 0);

        assert_eq!(disp.resolve(&d("fd22:2222:33ab::1")), 71);
    }

    /// set -> del round trip removes the entry everywhere; invalid v6
    /// prefixes are rejected without touching the targets. Del addresses
    /// carrying host bits still canonicalize to the stored key.
    #[test]
    fn del_and_validation() {
        let disp = dispatcher();
        let mut t1 = tbl();
        let _g = disp.register(&mut t1).unwrap();

        disp.set_ppp_session(3, 0x4321, 9);
        assert_eq!(wan_trie_resolve(&t1, &ppp_entry(3, 0x4321, 0).prefix), 9);
        disp.del_ppp_session(3, 0x4321);
        assert_eq!(wan_trie_resolve(&t1, &ppp_entry(3, 0x4321, 0).prefix), 0);

        disp.set_ipv6_prefix(Ipv6Addr::from_str("fd00:aa::").unwrap(), 48, 11).unwrap();
        assert_eq!(wan_trie_resolve(&t1, &d("fd00:aa::1")), 11);
        disp.del_ipv6_prefix(Ipv6Addr::from_str("fd00:aa::1").unwrap(), 48);
        assert_eq!(wan_trie_resolve(&t1, &d("fd00:aa::1")), 0, "del_ipv6_prefix must remove");
        // Missing keys are ignored, not an error.
        disp.del_ipv6_prefix(Ipv6Addr::from_str("fd00:aa::").unwrap(), 48);

        disp.set_ipv4_prefix(Ipv4Addr::new(198, 51, 100, 0), 24, 12).unwrap();
        let v4_key = v4_entry(Ipv4Addr::new(198, 51, 100, 7), 32, 0).unwrap().prefix;
        assert_eq!(wan_trie_resolve(&t1, &v4_key), 12);
        disp.del_ipv4_prefix(Ipv4Addr::new(198, 51, 100, 199), 24);
        assert_eq!(wan_trie_resolve(&t1, &v4_key), 0, "del_ipv4_prefix must remove");
        disp.del_ipv4_prefix(Ipv4Addr::new(198, 51, 100, 0), 24);

        assert!(disp.set_ipv6_prefix(Ipv6Addr::from_str("::").unwrap(), 0, 1).is_err());
        assert!(disp.set_ipv4_prefix(Ipv4Addr::new(203, 0, 113, 0), 33, 1).is_err());
    }

    /// A later register sees the current entries; dropping the guard
    /// detaches the target, which then stops receiving updates.
    #[test]
    fn register_initial_publish_and_guard_detach() {
        let disp = dispatcher();

        disp.set_ppp_session(3, 0x1234, 30);

        let mut t1 = tbl();
        let g1 = disp.register(&mut t1).unwrap();
        assert_eq!(wan_trie_resolve(&t1, &ppp_entry(3, 0x1234, 0).prefix), 30, "initial publish");

        drop(g1);
        disp.set_ppp_session(4, 0x4321, 40);
        assert_eq!(
            wan_trie_resolve(&t1, &ppp_entry(4, 0x4321, 0).prefix),
            0,
            "detached target must not update"
        );
        assert_eq!(wan_trie_resolve(&t1, &ppp_entry(3, 0x1234, 0).prefix), 30);
        assert_eq!(disp.resolve(&ppp_entry(4, 0x4321, 0).prefix), 40);
    }
}
