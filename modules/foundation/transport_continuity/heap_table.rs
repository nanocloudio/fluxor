// heap_table — a table of `T` a module takes from its heap at instantiation,
// as long as one of its params says.
//
// A module whose capacity is a count the graph sets (flows it moves at once,
// slots, connections) keeps the entries in a table of that length rather
// than a compile-time array. The composer sizes the module's heap for the
// count (`[capacities] heap_per_param`); the module takes the table in
// `module_new` ([`HeapTable::take`]). Zeroed memory is the empty table (no
// entries), so a state struct holding one is still initialised by zeroing
// it, and a `const` empty value exists for statics and defaults.
//
// `no_std`, zero-alloc: the memory is the module's heap's, or a host test's.

/// A module heap's allocator: the syscall table's `heap_alloc`.
pub type HeapAlloc = unsafe extern "C" fn(size: u32) -> *mut u8;

/// A table of `T` in memory the module owns for its lifetime.
pub struct HeapTable<T> {
    ptr: *mut T,
    len: usize,
}

impl<T> HeapTable<T> {
    /// No entries. Zeroed memory is this value.
    pub const EMPTY: Self = Self {
        ptr: core::ptr::null_mut(),
        len: 0,
    };

    /// The heap hands out 8-byte-aligned memory (an 8-byte block header
    /// ahead of a 16-byte-granular block), which holds an entry of at most
    /// that alignment.
    const ALIGNED: () = assert!(core::mem::align_of::<T>() <= 8);

    /// # Safety
    /// `ptr` holds `len` initialised entries, live and exclusively this
    /// table's for as long as it is used.
    pub const unsafe fn from_raw(ptr: *mut T, len: usize) -> Self {
        Self { ptr, len }
    }

    /// The bytes a table of `len` entries takes, `None` past `u32`.
    pub const fn bytes_for(len: usize) -> Option<u32> {
        match len.checked_mul(core::mem::size_of::<T>()) {
            Some(b) if b <= u32::MAX as usize => Some(b as u32),
            _ => None,
        }
    }

    /// Take `len` zeroed entries from the module's heap: `None` when the
    /// heap cannot hold them, the empty table for `len` 0.
    ///
    /// # Safety
    /// `alloc` is the instance's own `heap_alloc`, and zeroed memory is a
    /// valid `T`.
    pub unsafe fn take(alloc: HeapAlloc, len: usize) -> Option<Self> {
        let () = Self::ALIGNED;
        if len == 0 {
            return Some(Self::EMPTY);
        }
        let bytes = Self::bytes_for(len)?;
        // SAFETY: the caller's contract.
        let p = unsafe { alloc(bytes) };
        if p.is_null() {
            return None;
        }
        // SAFETY: `p` holds `bytes` bytes, aligned for `T` (`ALIGNED`), and
        // zeroed memory is a `T`.
        unsafe {
            core::ptr::write_bytes(p, 0, bytes as usize);
            Some(Self::from_raw(p as *mut T, len))
        }
    }
}

impl<T> core::ops::Deref for HeapTable<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        if self.ptr.is_null() {
            return &[];
        }
        // SAFETY: `from_raw`'s contract.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T> core::ops::DerefMut for HeapTable<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        if self.ptr.is_null() {
            return &mut [];
        }
        // SAFETY: `from_raw`'s contract.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl<T: PartialEq> PartialEq for HeapTable<T> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

// SAFETY: a table is one module instance's own, stepped on one thread; a
// shared `HeapTable` is only ever the empty one (an empty provider in a
// static), which points at nothing.
unsafe impl<T> Sync for HeapTable<T> {}
