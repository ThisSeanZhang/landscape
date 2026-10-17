//! Per-interface XDP slot arbitration.
//!
//! One interface effectively has a single usable XDP slot: native (driver)
//! and generic (SKB) mode cannot be active at the same time (the kernel
//! returns `-EEXIST`).  Two independent lifecycles contend for that slot:
//!
//! * the route services attaching their intro/route programs natively
//!   (opt-in via `--try-xdp`);
//! * PPPoE sessions needing the generic-mode decap fallback program.
//!
//! [`XdpAttach`] owns the arbitration: every lifecycle event re-decides
//! whether the slot is native, SKB-fallback, or parked (skeleton loaded
//! but detached, so a future flip is cheap).  Both route services and the
//! PPPoE handle talk to this object instead of touching XDP directly.

use std::collections::HashMap;
use std::mem::size_of;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::Mutex;

use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use libbpf_rs::Program;
use libbpf_rs::Xdp;
use libbpf_rs::XdpFlags;
use libbpf_rs::libbpf_sys;

use crate::LandscapeMapPath;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::OwnedOpenObject;

pub struct NativeXdpLink {
    attach: Arc<XdpAttach>,
    ifindex: i32,
    prog_fd: i32,
}

impl NativeXdpLink {
    #[allow(clippy::field_reassign_with_default)]
    pub(crate) fn attach(
        attach: Arc<XdpAttach>,
        prog: &Program,
        ifindex: u32,
    ) -> LdEbpfResult<Self> {
        let ifindex_i32 = ifindex as i32;

        // Native and generic (SKB) XDP cannot be active at the same time on
        // the same interface (kernel returns -EEXIST).  Always detach any
        // SKB-mode program unconditionally before attempting native attach,
        // regardless of whether we know about the SKB program through our
        // internal bookkeeping.
        let mut skb_detach_opts = libbpf_sys::bpf_xdp_attach_opts::default();
        skb_detach_opts.sz = size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t;
        let _ = unsafe {
            libbpf_sys::bpf_xdp_detach(ifindex_i32, XdpFlags::SKB_MODE.bits(), &skb_detach_opts)
        };

        // Recycle any previously-attached SKB bundle: detach the link
        // (no-op if the unconditional detach above already handled it)
        // and return the skeleton to the pending pool so it can be
        // reused if native XDP fails now or in the future.
        if let Some(old_bundle) = attach.take_skb_bundle(ifindex) {
            let SkbXdpBundle { _link: _, _skel, _backing } = old_bundle;
            attach.set_skb_pending(ifindex, SkbPending::new(_backing, _skel));
        }

        let result = Self::try_native(attach.clone(), prog, ifindex_i32);

        match result {
            Ok(link) => {
                // Native XDP succeeded — the pending SKB skeleton remains
                // in the manager untouched.
                Ok(link)
            }
            Err(e) => {
                // Native XDP failed — consume the pending SKB skeleton
                // (if any) and attach it as a fallback.
                if let Some(pending) = attach.take_skb_pending(ifindex) {
                    let SkbPending { _skel, _backing } = pending;
                    match SkbXdpLink::attach(&_skel.progs.pppoe_skb_fallback, ifindex) {
                        Ok(skb_link) => {
                            let bundle = SkbXdpBundle::new(_backing, _skel, skb_link);
                            attach.set_skb_bundle(ifindex, bundle);
                        }
                        Err(skb_err) => {
                            tracing::warn!(
                                "native XDP attach failed for ifindex={ifindex}, \
                                 SKB fallback also failed: {skb_err}"
                            );
                        }
                    }
                }
                Err(e)
            }
        }
    }

    fn try_native(attach: Arc<XdpAttach>, prog: &Program, ifindex: i32) -> LdEbpfResult<Self> {
        match attach.try_native.clone() {
            None => {
                return Err(crate::bpf_error::LandscapeEbpfError::Context {
                    context: format!(
                        "native XDP not enabled, use --try-xdp to enable (ifindex={ifindex})"
                    ),
                    source: libbpf_rs::Error::from_raw_os_error(libc::EOPNOTSUPP),
                });
            }
            Some(ref ifindices) => {
                if !ifindices.is_empty() && !ifindices.contains(&ifindex) {
                    return Err(crate::bpf_error::LandscapeEbpfError::Context {
                        context: format!(
                            "native XDP not enabled for this interface (ifindex={ifindex})"
                        ),
                        source: libbpf_rs::Error::from_raw_os_error(libc::EOPNOTSUPP),
                    });
                }
            }
        }

        let xdp = Xdp::new(prog.as_fd());
        let attach_flags = XdpFlags::DRV_MODE;

        crate::bpf_ctx!(xdp.attach(ifindex, attach_flags), "attach native XDP ifindex={ifindex}")?;

        let query = match crate::bpf_ctx!(
            xdp.query(ifindex, XdpFlags::DRV_MODE),
            "query native XDP ifindex={ifindex}"
        ) {
            Ok(query) => query,
            Err(err) => {
                Self::detach(ifindex, prog.as_fd().as_raw_fd());
                return Err(err.into());
            }
        };
        if query.drv_prog_id == 0 {
            Self::detach(ifindex, prog.as_fd().as_raw_fd());
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("native XDP attach missing drv prog id ifindex={ifindex}"),
                source: libbpf_rs::Error::from_raw_os_error(libc::ENODEV),
            });
        }

        Ok(Self { attach, ifindex, prog_fd: prog.as_fd().as_raw_fd() })
    }

    #[allow(clippy::field_reassign_with_default)]
    fn detach(ifindex: i32, prog_fd: i32) {
        let mut opts = libbpf_sys::bpf_xdp_attach_opts::default();
        opts.sz = size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t;
        opts.old_prog_fd = prog_fd;

        let ret = unsafe { libbpf_sys::bpf_xdp_detach(ifindex, XdpFlags::DRV_MODE.bits(), &opts) };
        if ret != 0 {
            tracing::debug!("detach native XDP ifindex={ifindex} failed: {}", -ret);
        }
    }
}

/// Generic/SKB-mode XDP link for fallback scenarios (e.g., PPPoE decap when
/// native XDP is unavailable).
pub(crate) struct SkbXdpLink {
    ifindex: i32,
}

impl SkbXdpLink {
    pub(crate) fn attach(prog: &Program, ifindex: u32) -> LdEbpfResult<Self> {
        let ifindex = ifindex as i32;
        let xdp = Xdp::new(prog.as_fd());
        let attach_flags = XdpFlags::SKB_MODE;

        crate::bpf_ctx!(xdp.attach(ifindex, attach_flags), "attach SKB XDP ifindex={ifindex}")?;

        let query = match crate::bpf_ctx!(
            xdp.query(ifindex, XdpFlags::SKB_MODE),
            "query SKB XDP ifindex={ifindex}"
        ) {
            Ok(query) => query,
            Err(err) => {
                Self::detach(ifindex);
                return Err(err.into());
            }
        };
        if query.skb_prog_id == 0 {
            Self::detach(ifindex);
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("SKB XDP attach missing skb prog id ifindex={ifindex}"),
                source: libbpf_rs::Error::from_raw_os_error(libc::ENODEV),
            });
        }

        Ok(Self { ifindex })
    }

    #[allow(clippy::field_reassign_with_default)]
    fn detach(ifindex: i32) {
        let mut opts = libbpf_sys::bpf_xdp_attach_opts::default();
        opts.sz = size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t;
        // old_prog_fd=0 (default) → detach whatever is in SKB mode.
        let ret = unsafe { libbpf_sys::bpf_xdp_detach(ifindex, XdpFlags::SKB_MODE.bits(), &opts) };
        if ret != 0 {
            tracing::debug!("detach SKB XDP ifindex={ifindex} failed: {}", -ret);
        }
    }
}

impl Drop for SkbXdpLink {
    fn drop(&mut self) {
        Self::detach(self.ifindex);
    }
}

/// An SKB XDP skeleton that has been loaded but NOT yet attached to any
/// interface.  PPPoE prepares one of these and hands it to the manager.
/// The manager decides whether to attach it (as SKB fallback) or keep it
/// for later, depending on native XDP availability.
pub(crate) struct SkbPending {
    _skel: crate::skel::pppoe_skb_fallback::PppoeSkbFallbackSkel<'static>,
    _backing: OwnedOpenObject,
}

impl SkbPending {
    pub(crate) fn new(
        backing: OwnedOpenObject,
        skel: crate::skel::pppoe_skb_fallback::PppoeSkbFallbackSkel<'static>,
    ) -> Self {
        Self { _backing: backing, _skel: skel }
    }
}

/// Bundle holding all resources needed to keep an SKB-mode XDP program
/// alive.  Struct fields are dropped in declaration order, so *link* is
/// dropped first — detaching the XDP program.  Then the skeleton is
/// dropped (OwnedRef accesses the backing which is still alive) and
/// finally the backing memory is freed.
pub(crate) struct SkbXdpBundle {
    _link: SkbXdpLink,
    _skel: crate::skel::pppoe_skb_fallback::PppoeSkbFallbackSkel<'static>,
    _backing: OwnedOpenObject,
}

impl SkbXdpBundle {
    pub(crate) fn new(
        backing: OwnedOpenObject,
        skel: crate::skel::pppoe_skb_fallback::PppoeSkbFallbackSkel<'static>,
        link: SkbXdpLink,
    ) -> Self {
        Self { _backing: backing, _skel: skel, _link: link }
    }
}

impl Drop for NativeXdpLink {
    fn drop(&mut self) {
        Self::detach(self.ifindex, self.prog_fd);
        // If native XDP had failed and SKB was running as fallback,
        // detach it and recycle the skeleton back as pending for reuse.
        if let Some(old_bundle) = self.attach.take_skb_bundle(self.ifindex as u32) {
            let SkbXdpBundle { _link: _, _skel, _backing } = old_bundle;
            self.attach.set_skb_pending(self.ifindex as u32, SkbPending::new(_backing, _skel));
        }
    }
}

// Pure interest-count decision helpers for the shared PPPoE SKB
// fallback, kept free of manager state so the semantics are
// unit-testable without loading any BPF objects.

/// Register interest; returns `true` when this is the first link on the
/// interface (the caller must prepare and park/attach the program).
fn acquire_fallback_interest(refs: &mut HashMap<u32, usize>, ifindex: u32) -> bool {
    let count = refs.entry(ifindex).or_insert(0);
    *count += 1;
    *count == 1
}

/// Drop interest; returns `true` when this was the last link (the
/// caller must detach and forget the shared program).
fn release_fallback_interest(refs: &mut HashMap<u32, usize>, ifindex: u32) -> bool {
    match refs.get_mut(&ifindex) {
        Some(count) if *count > 1 => {
            *count -= 1;
            false
        }
        _ => {
            refs.remove(&ifindex);
            true
        }
    }
}

/// The per-iface XDP attach coordinator.
pub struct XdpAttach {
    paths: Arc<LandscapeMapPath>,
    /// The CLI `--try-xdp` policy: `None` disables native attach,
    /// `Some([])` enables it on every interface and `Some([ifindex..])`
    /// restricts it to the listed interfaces.
    try_native: Option<Vec<i32>>,
    skb_bundles: Mutex<HashMap<u32, SkbXdpBundle>>,
    skb_pending: Mutex<HashMap<u32, SkbPending>>,
    // Per-iface interest count of native PPPoE links sharing the SKB
    // fallback program (attach on first, detach on last release).
    pppoe_fallback_refs: Mutex<HashMap<u32, usize>>,
    // Session map of each interface's live fallback instance.
    pppoe_fallback_maps: Mutex<HashMap<u32, MapHandle>>,
}

impl XdpAttach {
    pub fn new(paths: Arc<LandscapeMapPath>, try_native: Option<Vec<i32>>) -> Self {
        Self {
            paths,
            try_native,
            skb_bundles: Mutex::new(HashMap::new()),
            skb_pending: Mutex::new(HashMap::new()),
            pppoe_fallback_refs: Mutex::new(HashMap::new()),
            pppoe_fallback_maps: Mutex::new(HashMap::new()),
        }
    }

    /// Attach `prog` in native XDP mode on `ifindex`, recycling any
    /// generic-mode program through the pending pool as usual.
    pub fn attach_native(
        self: &Arc<Self>,
        prog: &Program<'_>,
        ifindex: u32,
    ) -> LdEbpfResult<NativeXdpLink> {
        NativeXdpLink::attach(self.clone(), prog, ifindex)
    }

    pub(crate) fn set_skb_bundle(&self, ifindex: u32, bundle: SkbXdpBundle) {
        self.skb_bundles.lock().unwrap().insert(ifindex, bundle);
    }

    pub(crate) fn take_skb_bundle(&self, ifindex: u32) -> Option<SkbXdpBundle> {
        self.skb_bundles.lock().unwrap().remove(&ifindex)
    }

    pub(crate) fn set_skb_pending(&self, ifindex: u32, pending: SkbPending) {
        let _ = self.skb_bundles.lock().unwrap().remove(&ifindex);

        match crate::maps::redirect_able::get_xdp_redirect_able(&self.paths, ifindex) {
            Some(true) => {
                // Native XDP is already serving this interface — store the
                // skeleton as pending for potential future SKB fallback.
                self.skb_pending.lock().unwrap().insert(ifindex, pending);
            }
            Some(false) => {
                // WR is active but running in TC-only mode — no native XDP
                // on the interface, safe to attach SKB immediately.
                let SkbPending { _skel, _backing } = pending;
                match SkbXdpLink::attach(&_skel.progs.pppoe_skb_fallback, ifindex) {
                    Ok(link) => {
                        let bundle = SkbXdpBundle::new(_backing, _skel, link);
                        self.skb_bundles.lock().unwrap().insert(ifindex, bundle);
                    }
                    Err(e) => {
                        tracing::warn!("SKB XDP attach for ifindex={ifindex} failed: {e}");
                    }
                }
            }
            None => {
                // WR is not active — store the skeleton as pending without
                // attaching, so it can be used if WR starts later.
                self.skb_pending.lock().unwrap().insert(ifindex, pending);
            }
        }
    }

    pub(crate) fn take_skb_pending(&self, ifindex: u32) -> Option<SkbPending> {
        self.skb_pending.lock().unwrap().remove(&ifindex)
    }

    /// Register one native PPPoE link's interest in the shared per-iface
    /// SKB fallback program.  The first link prepares and parks (or, in
    /// TC-only mode, attaches) a single fallback; further links only bump
    /// the count and add their session.
    pub(crate) fn acquire_pppoe_skb_fallback(
        &self,
        ifindex: u32,
        session: u16,
        chain: u16,
        make: impl FnOnce() -> LdEbpfResult<(SkbPending, libbpf_rs::MapHandle)>,
    ) -> LdEbpfResult<()> {
        let first = {
            let mut refs = self.pppoe_fallback_refs.lock().unwrap();
            acquire_fallback_interest(&mut refs, ifindex)
        };

        if !first {
            // Instance already alive: just publish this link's session.
            let result = {
                let maps = self.pppoe_fallback_maps.lock().unwrap();
                match maps.get(&ifindex) {
                    Some(map) => map
                        .update(
                            &session.to_ne_bytes(),
                            &(chain as u32).to_ne_bytes(),
                            MapFlags::ANY,
                        )
                        .map_err(|e| crate::bpf_error::LandscapeEbpfError::Context {
                            context: format!(
                                "pppoe fallback session publish failed (ifindex={ifindex})"
                            ),
                            source: e,
                        }),
                    None => Err(crate::bpf_error::LandscapeEbpfError::Context {
                        context: format!(
                            "pppoe fallback refs/maps out of sync (ifindex={ifindex})"
                        ),
                        source: libbpf_rs::Error::from_raw_os_error(libc::ENOENT),
                    }),
                }
            };
            if result.is_err() {
                // Roll the just-created interest back on failure.
                let mut refs = self.pppoe_fallback_refs.lock().unwrap();
                let _ = release_fallback_interest(&mut refs, ifindex);
            }
            return result;
        }

        match make() {
            Ok((pending, map)) => {
                let publish = map.update(
                    &session.to_ne_bytes(),
                    &(chain as u32).to_ne_bytes(),
                    MapFlags::ANY,
                );
                match publish {
                    Ok(()) => {
                        self.set_skb_pending(ifindex, pending);
                        self.pppoe_fallback_maps.lock().unwrap().insert(ifindex, map);
                        Ok(())
                    }
                    Err(e) => {
                        // Drop the fresh instance and roll the interest back.
                        drop(pending);
                        let mut refs = self.pppoe_fallback_refs.lock().unwrap();
                        let _ = release_fallback_interest(&mut refs, ifindex);
                        Err(e.into())
                    }
                }
            }
            Err(e) => {
                // Roll the just-created interest back on failure.
                let mut refs = self.pppoe_fallback_refs.lock().unwrap();
                let _ = release_fallback_interest(&mut refs, ifindex);
                Err(e)
            }
        }
    }

    /// Drop one link's interest (and its session); the last one out
    /// detaches (if attached) and forgets the shared fallback program.
    pub(crate) fn release_pppoe_skb_fallback(&self, ifindex: u32, session: u16) {
        if let Some(map) = self.pppoe_fallback_maps.lock().unwrap().get(&ifindex) {
            let _ = map.delete(&session.to_ne_bytes());
        }
        let last = {
            let mut refs = self.pppoe_fallback_refs.lock().unwrap();
            release_fallback_interest(&mut refs, ifindex)
        };
        if last {
            self.take_skb_bundle(ifindex);
            let _ = self.take_skb_pending(ifindex);
            self.pppoe_fallback_maps.lock().unwrap().remove(&ifindex);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_first_acquire_prepares_and_last_release_removes() {
        let mut refs = HashMap::new();
        assert!(acquire_fallback_interest(&mut refs, 9), "first link must prepare");
        assert!(release_fallback_interest(&mut refs, 9), "last link must remove");
        assert!(!refs.contains_key(&9));
    }

    #[test]
    fn fallback_extra_links_do_not_reprepare() {
        let mut refs = HashMap::new();
        assert!(acquire_fallback_interest(&mut refs, 3));
        assert!(!acquire_fallback_interest(&mut refs, 3), "second link must reuse");
        assert!(!acquire_fallback_interest(&mut refs, 3), "third link must reuse");

        assert!(!release_fallback_interest(&mut refs, 3));
        assert!(!release_fallback_interest(&mut refs, 3));
        assert!(release_fallback_interest(&mut refs, 3), "only the last removes");
        assert!(!refs.contains_key(&3));
    }

    #[test]
    fn fallback_interests_are_per_ifindex() {
        let mut refs = HashMap::new();
        assert!(acquire_fallback_interest(&mut refs, 1));
        assert!(acquire_fallback_interest(&mut refs, 2));
        assert!(!acquire_fallback_interest(&mut refs, 2), "second link on ifindex 2 reuses");
        // Releasing all links of ifindex 1 must not touch ifindex 2.
        assert!(release_fallback_interest(&mut refs, 1));
        assert!(!release_fallback_interest(&mut refs, 2));
        assert_eq!(refs.get(&2), Some(&1));
    }

    #[test]
    fn fallback_release_without_acquire_is_noop_last() {
        let mut refs = HashMap::new();
        // Defensive: a release with no registered interest still reports
        // "last" so callers cleaning up shared state stay idempotent.
        assert!(release_fallback_interest(&mut refs, 7));
        assert!(!refs.contains_key(&7));
    }
}
