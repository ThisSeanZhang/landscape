//! Access the dedicated trie mapping owned by a loaded seed skeleton.

use libbpf_rs::{AsRawLibbpf, MapCore, MapMut, MapType, libbpf_sys};

use crate::bpf_error::LdEbpfResult;

use super::types::WanTrieTbl;

/// Return the table at the arena mapping's start, matching BPF's arena_base().
///
/// Only call on a freshly loaded, owning skeleton, not on a reused FD or a
/// table already registered with the dispatcher. libbpf owns the mmap and
/// unmaps it when the skeleton drops; TrieTarget detaches the dispatcher first.
pub(crate) fn mapped_table<'a>(map: &'a mut MapMut<'_>) -> LdEbpfResult<&'a mut WanTrieTbl> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if map.map_type() != MapType::Arena
        || page <= 0
        || u64::from(map.max_entries()) * (page as u64) < size_of::<WanTrieTbl>() as u64
    {
        return Err(std::io::Error::other("invalid WAN trie arena type or capacity").into());
    }
    let mut globals_size = 0;
    // For ARENA maps this returns the mmap base, even without arena globals.
    // Its size output describes the ELF globals (zero), not the mapping size.
    let ptr = unsafe {
        libbpf_sys::bpf_map__initial_value(map.as_libbpf_object().as_ptr(), &mut globals_size)
    };
    if ptr.is_null()
        || globals_size != 0
        || !(ptr as usize).is_multiple_of(align_of::<WanTrieTbl>())
    {
        return Err(std::io::Error::other(
            "WAN trie requires an owned arena mapping without globals",
        )
        .into());
    }
    // SAFETY: libbpf owns a page-aligned, read/write shared mapping of at least
    // the checked table size. Fresh arena pages are zero initialized. The table
    // contains only integers; all bit patterns are valid. The mutable borrow is
    // scoped to the owning map, and publication retains the existing guard rule.
    Ok(unsafe { &mut *ptr.cast::<WanTrieTbl>() })
}
