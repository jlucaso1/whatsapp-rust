use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

pub struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AllocSnapshot {
    alloc_count: u64,
    alloc_bytes: u64,
}

impl AllocSnapshot {
    pub fn now() -> Self {
        Self {
            alloc_count: ALLOC_COUNT.load(Ordering::Relaxed),
            alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AllocDelta {
    pub alloc_count: u64,
    pub alloc_bytes: u64,
}

impl AllocDelta {
    pub fn between(before: AllocSnapshot, after: AllocSnapshot) -> Self {
        Self {
            alloc_count: after.alloc_count.saturating_sub(before.alloc_count),
            alloc_bytes: after.alloc_bytes.saturating_sub(before.alloc_bytes),
        }
    }
}
