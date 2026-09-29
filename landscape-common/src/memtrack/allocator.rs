//! 全局分配器包装:`#[global_allocator]` 声明处位于最终二进制
//! (`landscape-webserver/src/main.rs`)。
//!
//! 仅在显式开启 feature `mem-track` 时统计:每次分配前附加 32 字节头部,
//! 记录 owner 与基础布局,dealloc/realloc 按真实 owner 扣减,各子系统
//! live 字节精确。未开启时本包装为 `System` 的纯透传,零开销、不计数。

#[cfg(not(feature = "mem-track"))]
use std::alloc::System;

use std::alloc::{GlobalAlloc, Layout};

/// 全局分配器。在二进制中声明:
///
/// ```ignore
/// #[global_allocator]
/// static GLOBAL_ALLOCATOR: landscape_common::memtrack::CountingAllocator =
///     landscape_common::memtrack::CountingAllocator;
/// ```
pub struct CountingAllocator;

#[cfg(feature = "mem-track")]
mod precise {
    use std::alloc::{GlobalAlloc, Layout, System};

    use super::super::registry::{record_alloc, record_free};
    use super::super::tag::current_tag;

    pub(super) const HEADER_SIZE: usize = 32;
    const HEADER_ALIGN: usize = 8;
    const MAGIC: u32 = 0x4C44_4D45; // "LDME"

    /// 紧跟数据指针之前的分配头。总长 32 字节、8 对齐(数据指针至少 8 对齐
    /// 保证头部读取天然对齐,仍用 read/write_unaligned 以防万一)。
    #[repr(C)]
    struct AllocHeader {
        magic: u32,
        owner: u32,
        /// 传给 System 的基础布局 size,dealloc 需原样传回。
        base_size: u64,
        /// 传给 System 的基础布局 align。
        base_align: u32,
        /// 数据指针相对基础分配起点的偏移。
        base_offset: u32,
        /// 业务原始请求 size(live 字节按此计)。
        orig_size: u64,
    }

    impl AllocHeader {
        fn read_before(ptr: *mut u8) -> AllocHeader {
            unsafe { (ptr.sub(HEADER_SIZE) as *const AllocHeader).read_unaligned() }
        }
    }

    pub(super) fn alloc(layout: Layout) -> *mut u8 {
        let align = layout.align().max(HEADER_ALIGN);
        // 多要 align 字节,保证 base+HEADER 之后总能找到满足业务对齐的数据指针。
        let base_size = layout.size() + HEADER_SIZE + layout.align();
        let Ok(base_layout) = Layout::from_size_align(base_size, align) else {
            return std::ptr::null_mut();
        };
        let base = unsafe { System.alloc(base_layout) };
        if base.is_null() {
            return std::ptr::null_mut();
        }

        let data_addr = (base as usize + HEADER_SIZE + layout.align() - 1) & !(layout.align() - 1);
        let data = data_addr as *mut u8;
        debug_assert!(data_addr >= base as usize + HEADER_SIZE);
        debug_assert!(base as usize + base_size >= data_addr + layout.size());
        debug_assert!(data_addr.is_multiple_of(layout.align()));
        debug_assert!(data_addr - base as usize <= HEADER_SIZE + layout.align());

        let owner = current_tag();
        unsafe {
            (data.sub(HEADER_SIZE) as *mut AllocHeader).write_unaligned(AllocHeader {
                magic: MAGIC,
                owner: owner as u32,
                base_size: base_size as u64,
                base_align: base_layout.align() as u32,
                base_offset: (data_addr - base as usize) as u32,
                orig_size: layout.size() as u64,
            });
        }
        record_alloc(owner, layout.size());
        data
    }

    /// `fallback_layout`:magic 不匹配(分配器安装前的极早期分配,理论不可达)
    /// 时按原布局直接回收,不泄漏也不计账。
    pub(super) fn dealloc(ptr: *mut u8, fallback_layout: Layout) {
        let header = AllocHeader::read_before(ptr);
        if header.magic != MAGIC {
            unsafe { System.dealloc(ptr, fallback_layout) };
            return;
        }
        let Ok(base_layout) =
            Layout::from_size_align(header.base_size as usize, header.base_align as usize)
        else {
            return;
        };
        let base = unsafe { ptr.sub(header.base_offset as usize) };
        record_free(header.owner as usize, header.orig_size as usize);
        unsafe { System.dealloc(base, base_layout) };
    }

    /// realloc 保持原 owner:同 owner 新分配 → 拷贝 → 按头释放旧块。
    pub(super) fn realloc(ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let header = AllocHeader::read_before(ptr);
        if header.magic != MAGIC {
            return passthrough_realloc(ptr, old_layout, new_size);
        }
        let Ok(new_layout) = Layout::from_size_align(new_size, old_layout.align()) else {
            return std::ptr::null_mut();
        };
        let owner = header.owner as usize;
        let new_ptr = super::super::tag::with_tag(owner, || alloc(new_layout));
        if new_ptr.is_null() {
            return std::ptr::null_mut();
        }
        let copy_len = (header.orig_size as usize).min(new_size);
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, new_ptr, copy_len);
            dealloc(ptr, old_layout);
        }
        new_ptr
    }

    /// 无头分配的纯透传 realloc(理论不可达路径,不计账)。
    fn passthrough_realloc(ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { System.realloc(ptr, old_layout, new_size) }
    }

    #[test]
    fn header_is_32_bytes() {
        assert_eq!(std::mem::size_of::<AllocHeader>(), HEADER_SIZE);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(feature = "mem-track")]
        {
            precise::alloc(layout)
        }
        #[cfg(not(feature = "mem-track"))]
        {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[cfg(feature = "mem-track")]
        {
            precise::dealloc(ptr, layout)
        }
        #[cfg(not(feature = "mem-track"))]
        {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[cfg(feature = "mem-track")]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        precise::realloc(ptr, layout, new_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memtrack::registry::{UNATTRIBUTED, registry};
    use crate::memtrack::tag::with_tag;
    use std::sync::atomic::Ordering;

    fn allocated(index: usize) -> u64 {
        registry().get(index).allocated_bytes.load(Ordering::Relaxed)
    }

    fn freed(index: usize) -> u64 {
        registry().get(index).freed_bytes.load(Ordering::Relaxed)
    }

    #[test]
    fn alloc_attributed_to_current_tag() {
        let layout = Layout::from_size_align(64, 8).unwrap();
        let before = allocated(0);
        let ptr = with_tag(0, || unsafe { GlobalAlloc::alloc(&CountingAllocator, layout) });
        assert!(!ptr.is_null());
        let after = allocated(0);
        if cfg!(feature = "mem-track") {
            assert_eq!(after, before + 64);
        } else {
            assert_eq!(after, before);
        }

        let freed_before = freed(0);
        unsafe { GlobalAlloc::dealloc(&CountingAllocator, ptr, layout) };
        if cfg!(feature = "mem-track") {
            assert_eq!(freed(0), freed_before + 64);
        } else {
            assert_eq!(freed(0), freed_before);
        }
    }

    #[test]
    fn zero_size_alloc_roundtrips() {
        let layout = Layout::from_size_align(0, 1).unwrap();
        let ptr =
            with_tag(UNATTRIBUTED, || unsafe { GlobalAlloc::alloc(&CountingAllocator, layout) });
        if !ptr.is_null() {
            unsafe { GlobalAlloc::dealloc(&CountingAllocator, ptr, layout) };
        }
    }

    #[cfg(feature = "mem-track")]
    #[test]
    fn free_attributed_to_allocating_owner_even_after_tag_change() {
        let layout = Layout::from_size_align(128, 16).unwrap();
        let alloc_before = allocated(2);
        let freed_before = freed(2);
        let ptr = with_tag(2, || unsafe { GlobalAlloc::alloc(&CountingAllocator, layout) });
        assert!(!ptr.is_null());
        unsafe { std::ptr::write_bytes(ptr, 0xAB, 128) };
        assert_eq!(allocated(2), alloc_before + 128);

        with_tag(5, || unsafe { GlobalAlloc::dealloc(&CountingAllocator, ptr, layout) });
        assert_eq!(freed(2), freed_before + 128);
    }

    #[cfg(feature = "mem-track")]
    #[test]
    fn realloc_preserves_owner_and_counts() {
        let layout = Layout::from_size_align(32, 8).unwrap();
        let alloc_before = allocated(1);
        let freed_before = freed(1);
        let ptr = with_tag(1, || unsafe { GlobalAlloc::alloc(&CountingAllocator, layout) });
        assert!(!ptr.is_null());
        unsafe { std::ptr::write_bytes(ptr, 0x11, 32) };
        assert_eq!(allocated(1), alloc_before + 32);

        let bigger =
            with_tag(3, || unsafe { GlobalAlloc::realloc(&CountingAllocator, ptr, layout, 256) });
        assert!(!bigger.is_null());
        assert_eq!(allocated(1), alloc_before + 32 + 256);
        assert_eq!(freed(1), freed_before + 32);

        let big_layout = Layout::from_size_align(256, 8).unwrap();
        with_tag(UNATTRIBUTED, || unsafe {
            GlobalAlloc::dealloc(&CountingAllocator, bigger, big_layout)
        });
    }

    #[cfg(feature = "mem-track")]
    #[test]
    fn various_alignments_roundtrip() {
        // 槽位 10(lan):避开 alloc_attributed_to_current_tag 占用的槽 0,
        // 保证并行测试下双方的精确断言互不干扰。
        for align in [1usize, 2, 4, 8, 16, 32, 64, 4096] {
            let layout = Layout::from_size_align(align * 3, align).unwrap();
            let ptr = with_tag(10, || unsafe { GlobalAlloc::alloc(&CountingAllocator, layout) });
            assert!(!ptr.is_null(), "alloc align={align} failed");
            assert_eq!(ptr as usize % align, 0, "alignment align={align} broken");
            unsafe {
                std::ptr::write_bytes(ptr, 0xCD, layout.size());
                GlobalAlloc::dealloc(&CountingAllocator, ptr, layout);
            }
        }
    }

    #[test]
    fn tag_overflow_clamps_to_unattributed() {
        let layout = Layout::from_size_align(16, 8).unwrap();
        let before = allocated(UNATTRIBUTED);
        let ptr =
            with_tag(usize::MAX, || unsafe { GlobalAlloc::alloc(&CountingAllocator, layout) });
        assert!(!ptr.is_null());
        if cfg!(feature = "mem-track") {
            assert_eq!(allocated(UNATTRIBUTED), before + 16);
        } else {
            assert_eq!(allocated(UNATTRIBUTED), before);
        }
        unsafe { GlobalAlloc::dealloc(&CountingAllocator, ptr, layout) };
    }
}
