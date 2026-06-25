//! Page-locked secret memory with optional write-protection.
//!
//! `LockedPage<T>` allocates its contents on a private `mmap`-backed page
//! (or set of pages) and calls `mlock` to prevent the kernel from swapping
//! the pages to disk. After construction, `protect()` can be called to make
//! the pages read-only via `mprotect(PROT_READ)`, turning any unexpected
//! write into a `SIGSEGV` rather than a silent corruption. `Zeroize::zeroize()`
//! automatically unprotects the pages before zeroing.
//!
//! On non-Unix targets the type falls back to a `Box<T>` that is zeroed on
//! drop, without mlock or mprotect guarantees.

use zeroize::Zeroize;

// ── Unix implementation (Android + Linux + macOS) ─────────────────────────────

#[cfg(unix)]
mod imp {
    use super::*;
    use core::{marker::PhantomData, mem::size_of, ptr};

    fn page_size() -> usize {
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ps <= 0 {
            4096
        } else {
            ps as usize
        }
    }

    fn round_to_pages(n: usize) -> usize {
        let ps = page_size();
        n.max(1).div_ceil(ps) * ps
    }

    pub struct LockedPage<T: Zeroize> {
        ptr: ptr::NonNull<T>,
        mmap_len: usize,
        /// True when `mprotect(PROT_READ)` has been applied.
        protected: bool,
        _marker: PhantomData<T>,
    }

    // SAFETY: LockedPage owns its mmap'd allocation exclusively; T's own Send/Sync
    // bounds propagate through the PhantomData.
    unsafe impl<T: Zeroize + Send> Send for LockedPage<T> {}
    unsafe impl<T: Zeroize + Sync> Sync for LockedPage<T> {}

    impl<T: Zeroize> LockedPage<T> {
        /// Allocates an anonymous `mmap` region (always zero-initialised by the
        /// kernel) and pins it in RAM with `mlock`. The returned page is writable.
        ///
        /// # Safety
        /// `T` must be valid when all bytes are zero. This holds for any type
        /// composed entirely of integer primitives (`[u8; N]`, `[u32; N]`, …).
        pub unsafe fn new_zeroed() -> Self {
            let mmap_len = round_to_pages(size_of::<T>());
            let raw = libc::mmap(
                ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert!(
                !raw.is_null() && raw != libc::MAP_FAILED,
                "LockedPage: mmap({mmap_len}) failed"
            );
            // Best-effort: mlock may fail under a low ulimit (e.g. default 64 KB on
            // some Linux distros). The page is still usable without locking.
            libc::mlock(raw, mmap_len);
            LockedPage {
                ptr: ptr::NonNull::new_unchecked(raw as *mut T),
                mmap_len,
                protected: false,
                _marker: PhantomData,
            }
        }

        /// Switches the page to `PROT_READ` so any write causes `SIGSEGV`.
        /// Call once after the value has been fully initialised.
        pub fn protect(&mut self) {
            if !self.protected {
                unsafe {
                    libc::mprotect(
                        self.ptr.as_ptr() as *mut libc::c_void,
                        self.mmap_len,
                        libc::PROT_READ,
                    );
                }
                self.protected = true;
            }
        }

        fn unprotect_for_write(&mut self) {
            if self.protected {
                unsafe {
                    libc::mprotect(
                        self.ptr.as_ptr() as *mut libc::c_void,
                        self.mmap_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                }
                self.protected = false;
            }
        }
    }

    impl<T: Zeroize> core::ops::Deref for LockedPage<T> {
        type Target = T;
        #[inline]
        fn deref(&self) -> &T {
            unsafe { self.ptr.as_ref() }
        }
    }

    impl<T: Zeroize> core::ops::DerefMut for LockedPage<T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut T {
            // SAFETY: if `protect()` has been called, a write would SIGSEGV —
            // that is intentional. Callers that need to mutate a protected page
            // must call `unprotect_for_write()` first (done automatically by
            // `zeroize()` and `Drop`).
            unsafe { self.ptr.as_mut() }
        }
    }

    impl<T: Zeroize> Zeroize for LockedPage<T> {
        fn zeroize(&mut self) {
            self.unprotect_for_write();
            unsafe { self.ptr.as_mut() }.zeroize();
        }
    }

    impl<T: Zeroize> Drop for LockedPage<T> {
        fn drop(&mut self) {
            self.unprotect_for_write();
            unsafe { self.ptr.as_mut() }.zeroize();
            unsafe {
                libc::munlock(self.ptr.as_ptr() as *const libc::c_void, self.mmap_len);
                libc::munmap(self.ptr.as_ptr() as *mut libc::c_void, self.mmap_len);
            }
        }
    }

    impl<T: Zeroize> core::fmt::Debug for LockedPage<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("LockedPage([REDACTED])")
        }
    }
}

// ── Non-Unix fallback (Windows, Wasm, …) ─────────────────────────────────────

#[cfg(not(unix))]
mod imp {
    use super::*;
    use core::alloc::Layout;

    pub struct LockedPage<T: Zeroize> {
        ptr: core::ptr::NonNull<T>,
    }

    impl<T: Zeroize> LockedPage<T> {
        /// Allocates zeroed memory on the system heap.
        ///
        /// # Safety
        /// Same precondition as the Unix path: `T` must be valid when zero.
        pub unsafe fn new_zeroed() -> Self {
            let layout = Layout::new::<T>();
            // alloc_zeroed is only valid for non-ZST layouts.
            assert!(layout.size() > 0, "LockedPage: zero-sized T");
            let raw = std::alloc::alloc_zeroed(layout) as *mut T;
            assert!(!raw.is_null(), "LockedPage: allocation failed");
            LockedPage {
                ptr: core::ptr::NonNull::new_unchecked(raw),
            }
        }

        /// No-op on non-Unix — no `mprotect` available.
        pub fn protect(&mut self) {}
    }

    impl<T: Zeroize> core::ops::Deref for LockedPage<T> {
        type Target = T;
        fn deref(&self) -> &T {
            unsafe { self.ptr.as_ref() }
        }
    }

    impl<T: Zeroize> core::ops::DerefMut for LockedPage<T> {
        fn deref_mut(&mut self) -> &mut T {
            unsafe { self.ptr.as_mut() }
        }
    }

    impl<T: Zeroize> Zeroize for LockedPage<T> {
        fn zeroize(&mut self) {
            unsafe { self.ptr.as_mut() }.zeroize();
        }
    }

    impl<T: Zeroize> Drop for LockedPage<T> {
        fn drop(&mut self) {
            unsafe { self.ptr.as_mut() }.zeroize();
            unsafe {
                std::alloc::dealloc(
                    self.ptr.as_ptr() as *mut u8,
                    core::alloc::Layout::new::<T>(),
                );
            }
        }
    }

    impl<T: Zeroize> core::fmt::Debug for LockedPage<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("LockedPage([REDACTED])")
        }
    }
}

pub use imp::LockedPage;
