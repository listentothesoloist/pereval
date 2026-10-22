//! Guest address space.
//!
//! The whole guest virtual address range `[0, size)` is one contiguous host
//! reservation (`mmap(PROT_NONE)`), so translating a guest address is a single
//! addition: `host = base + guest`. This is what keeps the interpreter cheap
//! today and what a JIT will emit tomorrow (base lives in a pinned register).
//!
//! Page sizes differ: the guest (x86-64 Linux) expects 4 KiB pages, Apple
//! Silicon uses 16 KiB. Two guest mappings with different permissions can
//! therefore share one host page. We never execute guest code directly (it is
//! interpreted or translated), so every committed host page is simply RW and the
//! guest-visible protection is tracked in software in the VMA list.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::Mutex;

pub const GUEST_PAGE: u64 = 4096;
/// Default guest address-space size: 32 TiB (Linux x86-64 user space is 128 TiB,
/// but nothing we run needs more and the host needs room too).
pub const DEFAULT_SIZE: u64 = 1 << 45;
/// Like Linux `vm.mmap_min_addr`: the first 64 KiB are never mapped, so NULL
/// dereferences fault.
pub const MIN_ADDR: u64 = 0x10000;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Prot(pub u8);

impl Prot {
    pub const NONE: Prot = Prot(0);
    pub const R: Prot = Prot(1);
    pub const W: Prot = Prot(2);
    pub const X: Prot = Prot(4);
    pub const RW: Prot = Prot(3);
    pub const RX: Prot = Prot(5);
    pub const RWX: Prot = Prot(7);

    /// From Linux `PROT_*` bits (same values as ours).
    pub fn from_linux(p: u64) -> Prot {
        Prot((p & 7) as u8)
    }
    pub fn contains(self, other: Prot) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Prot {
    type Output = Prot;
    fn bitor(self, rhs: Prot) -> Prot {
        Prot(self.0 | rhs.0)
    }
}

impl fmt::Debug for Prot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = |b, ch| if self.0 & b != 0 { ch } else { '-' };
        write!(f, "{}{}{}", c(1, 'r'), c(2, 'w'), c(4, 'x'))
    }
}

/// A guest memory access that cannot be satisfied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub addr: u64,
    pub write: bool,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.write { "write" } else { "read" };
        write!(f, "guest {kind} fault at {:#x}", self.addr)
    }
}

impl std::error::Error for Fault {}

#[derive(Debug)]
pub enum MapError {
    /// Address or length not page aligned, or outside the guest range.
    Invalid,
    /// No free range large enough.
    NoSpace,
    Host(io::Error),
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MapError::Invalid => write!(f, "invalid mapping range"),
            MapError::NoSpace => write!(f, "guest address space exhausted"),
            MapError::Host(e) => write!(f, "host mmap failed: {e}"),
        }
    }
}

impl std::error::Error for MapError {}

#[derive(Clone, Debug)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: Prot,
    pub name: String,
}

pub struct GuestMemory {
    base: *mut u8,
    size: u64,
    host_page: u64,
    /// Keyed by start address; ranges never overlap.
    vmas: Mutex<BTreeMap<u64, Vma>>,
}

// The reservation is plain memory; synchronisation of guest accesses is the
// guest's business (as on hardware). Bookkeeping is behind a mutex.
unsafe impl Send for GuestMemory {}
unsafe impl Sync for GuestMemory {}

pub fn page_align_down(x: u64) -> u64 {
    x & !(GUEST_PAGE - 1)
}

pub fn page_align_up(x: u64) -> u64 {
    (x + GUEST_PAGE - 1) & !(GUEST_PAGE - 1)
}

/// Plain-old-data values that may be read from / written to guest memory.
pub trait Pod: Copy {}
impl Pod for u8 {}
impl Pod for u16 {}
impl Pod for u32 {}
impl Pod for u64 {}
impl Pod for u128 {}
impl Pod for i8 {}
impl Pod for i16 {}
impl Pod for i32 {}
impl Pod for i64 {}

impl GuestMemory {
    pub fn new(size: u64) -> io::Result<GuestMemory> {
        let host_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        assert!(size % host_page == 0);
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(GuestMemory { base: p as *mut u8, size, host_page, vmas: Mutex::new(BTreeMap::new()) })
    }

    pub fn base(&self) -> *mut u8 {
        self.base
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// True if `host` points into the guest reservation; returns the guest address.
    pub fn guest_addr_of(&self, host: usize) -> Option<u64> {
        let b = self.base as usize;
        (host >= b && host < b + self.size as usize).then(|| (host - b) as u64)
    }

    // ---- mapping ---------------------------------------------------------

    /// Map `[addr, addr+len)` at a fixed address, replacing whatever was there.
    /// The new range reads as zeros.
    pub fn map_fixed(&self, addr: u64, len: u64, prot: Prot, name: &str) -> Result<(), MapError> {
        let len = page_align_up(len);
        if addr % GUEST_PAGE != 0 || len == 0 || addr < MIN_ADDR || addr.checked_add(len).map_or(true, |e| e > self.size) {
            return Err(MapError::Invalid);
        }
        let mut vmas = self.vmas.lock().unwrap();
        Self::remove_range(&mut vmas, addr, addr + len);
        self.commit_zeroed(addr, addr + len)?;
        vmas.insert(addr, Vma { start: addr, end: addr + len, prot, name: name.to_string() });
        Ok(())
    }

    /// Map `len` bytes anywhere at or below `top`, searching downwards
    /// (Linux's default top-down mmap layout).
    pub fn map_anywhere(&self, top: u64, len: u64, prot: Prot, name: &str) -> Result<u64, MapError> {
        let len = page_align_up(len);
        if len == 0 {
            return Err(MapError::Invalid);
        }
        let addr = {
            let vmas = self.vmas.lock().unwrap();
            let mut hi = page_align_down(top.min(self.size));
            let mut found = None;
            // Walk existing mappings from the top down looking for a gap.
            for v in vmas.values().rev() {
                if v.start >= hi {
                    continue;
                }
                if v.end <= hi && hi - v.end >= len {
                    found = Some(hi - len);
                    break;
                }
                hi = hi.min(v.start);
            }
            match found {
                Some(a) => a,
                None if hi >= MIN_ADDR + len => hi - len,
                None => return Err(MapError::NoSpace),
            }
        };
        self.map_fixed(addr, len, prot, name)?;
        Ok(addr)
    }

    pub fn unmap(&self, addr: u64, len: u64) -> Result<(), MapError> {
        let len = page_align_up(len);
        if addr % GUEST_PAGE != 0 || addr.checked_add(len).map_or(true, |e| e > self.size) {
            return Err(MapError::Invalid);
        }
        let mut vmas = self.vmas.lock().unwrap();
        Self::remove_range(&mut vmas, addr, addr + len);
        // Decommit host pages that no longer back any guest mapping.
        let hp = self.host_page;
        let mut p = (addr + hp - 1) & !(hp - 1);
        while p + hp <= addr + len {
            if !Self::overlaps(&vmas, p, p + hp) {
                self.host_mmap(p, hp, libc::PROT_NONE)?;
            }
            p += hp;
        }
        Ok(())
    }

    pub fn protect(&self, addr: u64, len: u64, prot: Prot) -> Result<(), MapError> {
        let len = page_align_up(len);
        let end = addr + len;
        let mut vmas = self.vmas.lock().unwrap();
        let affected: Vec<Vma> = vmas.values().filter(|v| v.start < end && v.end > addr).cloned().collect();
        let covered: u64 = affected.iter().map(|v| v.end.min(end) - v.start.max(addr)).sum();
        if covered != len {
            return Err(MapError::Invalid); // Linux: ENOMEM for unmapped holes
        }
        for v in affected {
            vmas.remove(&v.start);
            let (s, e) = (v.start.max(addr), v.end.min(end));
            if v.start < s {
                vmas.insert(v.start, Vma { end: s, ..v.clone() });
            }
            vmas.insert(s, Vma { start: s, end: e, prot, name: v.name.clone() });
            if e < v.end {
                vmas.insert(e, Vma { start: e, ..v.clone() });
            }
        }
        Ok(())
    }

    pub fn vmas(&self) -> Vec<Vma> {
        self.vmas.lock().unwrap().values().cloned().collect()
    }

    pub fn find_vma(&self, addr: u64) -> Option<Vma> {
        let vmas = self.vmas.lock().unwrap();
        vmas.range(..=addr).next_back().map(|(_, v)| v).filter(|v| addr < v.end).cloned()
    }

    fn overlaps(vmas: &BTreeMap<u64, Vma>, s: u64, e: u64) -> bool {
        vmas.range(..e).next_back().map_or(false, |(_, v)| v.end > s)
    }

    fn remove_range(vmas: &mut BTreeMap<u64, Vma>, s: u64, e: u64) {
        let hit: Vec<Vma> = vmas.values().filter(|v| v.start < e && v.end > s).cloned().collect();
        for v in hit {
            vmas.remove(&v.start);
            if v.start < s {
                vmas.insert(v.start, Vma { end: s, ..v.clone() });
            }
            if v.end > e {
                vmas.insert(e, Vma { start: e, ..v });
            }
        }
    }

    /// Make `[s, e)` accessible on the host and zero it. Whole host pages are
    /// replaced with fresh (lazily zeroed) pages; partial edge pages may still
    /// back a neighbouring mapping, so they are committed and cleared by hand.
    fn commit_zeroed(&self, s: u64, e: u64) -> Result<(), MapError> {
        let hp = self.host_page;
        let (hs, he) = (s & !(hp - 1), (e + hp - 1) & !(hp - 1));
        let mut p = hs;
        while p < he {
            let (ps, pe) = (p.max(s), (p + hp).min(e));
            if ps == p && pe == p + hp {
                // Coalesce a run of whole host pages into one call.
                let mut q = p + hp;
                while q + hp <= e {
                    q += hp;
                }
                self.host_mmap(p, q - p, libc::PROT_READ | libc::PROT_WRITE)?;
                p = q;
                continue;
            }
            let r = unsafe { libc::mprotect(self.base.add(p as usize) as *mut _, hp as usize, libc::PROT_READ | libc::PROT_WRITE) };
            if r != 0 {
                return Err(MapError::Host(io::Error::last_os_error()));
            }
            unsafe { std::ptr::write_bytes(self.base.add(ps as usize), 0, (pe - ps) as usize) };
            p += hp;
        }
        Ok(())
    }

    fn host_mmap(&self, at: u64, len: u64, prot: i32) -> Result<(), MapError> {
        let p = unsafe {
            libc::mmap(
                self.base.add(at as usize) as *mut _,
                len as usize,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(MapError::Host(io::Error::last_os_error()));
        }
        Ok(())
    }

    // ---- access ----------------------------------------------------------

    /// Host pointer for a guest range. Only bounds are checked here: a range
    /// inside the reservation but not mapped faults on the host (SIGSEGV),
    /// exactly like the real hardware would.
    #[inline(always)]
    pub fn ptr(&self, addr: u64, len: usize, write: bool) -> Result<*mut u8, Fault> {
        match addr.checked_add(len as u64) {
            Some(end) if end <= self.size => Ok(unsafe { self.base.add(addr as usize) }),
            _ => Err(Fault { addr, write }),
        }
    }

    #[inline(always)]
    pub fn read<T: Pod>(&self, addr: u64) -> Result<T, Fault> {
        let p = self.ptr(addr, std::mem::size_of::<T>(), false)?;
        Ok(unsafe { (p as *const T).read_unaligned() })
    }

    #[inline(always)]
    pub fn write<T: Pod>(&self, addr: u64, v: T) -> Result<(), Fault> {
        let p = self.ptr(addr, std::mem::size_of::<T>(), true)?;
        unsafe { (p as *mut T).write_unaligned(v) };
        Ok(())
    }

    pub fn read_bytes(&self, addr: u64, out: &mut [u8]) -> Result<(), Fault> {
        let p = self.ptr(addr, out.len(), false)?;
        unsafe { std::ptr::copy_nonoverlapping(p, out.as_mut_ptr(), out.len()) };
        Ok(())
    }

    pub fn write_bytes(&self, addr: u64, data: &[u8]) -> Result<(), Fault> {
        let p = self.ptr(addr, data.len(), true)?;
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()) };
        Ok(())
    }

    /// Borrow a guest range as a host slice (e.g. to pass straight to a host
    /// syscall). The caller must not hold it across guest execution.
    pub fn slice(&self, addr: u64, len: usize) -> Result<&[u8], Fault> {
        let p = self.ptr(addr, len, false)?;
        Ok(unsafe { std::slice::from_raw_parts(p, len) })
    }

    #[allow(clippy::mut_from_ref)]
    pub fn slice_mut(&self, addr: u64, len: usize) -> Result<&mut [u8], Fault> {
        let p = self.ptr(addr, len, true)?;
        Ok(unsafe { std::slice::from_raw_parts_mut(p, len) })
    }

    /// Read a NUL-terminated string (without the NUL), at most `max` bytes.
    pub fn read_cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>, Fault> {
        let mut out = Vec::new();
        for i in 0..max as u64 {
            let b: u8 = self.read(addr + i)?;
            if b == 0 {
                return Ok(out);
            }
            out.push(b);
        }
        Err(Fault { addr: addr + max as u64, write: false })
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base as *mut _, self.size as usize) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> GuestMemory {
        GuestMemory::new(1 << 36).unwrap()
    }

    #[test]
    fn map_read_write() {
        let m = mem();
        m.map_fixed(0x400000, 0x3000, Prot::RW, "t").unwrap();
        m.write::<u64>(0x400ff8, 0x1122334455667788).unwrap();
        assert_eq!(m.read::<u64>(0x400ff8).unwrap(), 0x1122334455667788);
        assert_eq!(m.read::<u32>(0x400ffc).unwrap(), 0x11223344);
        assert!(m.read::<u8>(m.size()).is_err());
    }

    #[test]
    fn remap_zeroes_shared_host_page() {
        // Two 4 KiB guest pages inside one 16 KiB host page.
        let m = mem();
        m.map_fixed(0x400000, 0x1000, Prot::RW, "a").unwrap();
        m.map_fixed(0x401000, 0x1000, Prot::RW, "b").unwrap();
        m.write::<u32>(0x401010, 0xdeadbeef).unwrap();
        m.write::<u32>(0x400010, 7).unwrap();
        m.map_fixed(0x401000, 0x1000, Prot::RW, "b2").unwrap();
        assert_eq!(m.read::<u32>(0x401010).unwrap(), 0);
        assert_eq!(m.read::<u32>(0x400010).unwrap(), 7, "neighbour must survive");
    }

    #[test]
    fn vma_split_and_protect() {
        let m = mem();
        m.map_fixed(0x400000, 0x4000, Prot::RW, "x").unwrap();
        m.protect(0x401000, 0x1000, Prot::R).unwrap();
        let v = m.vmas();
        assert_eq!(v.len(), 3);
        assert_eq!(v[1].start, 0x401000);
        assert_eq!(v[1].prot, Prot::R);
        m.unmap(0x400000, 0x2000).unwrap();
        assert_eq!(m.vmas().len(), 1);
        assert!(m.find_vma(0x400000).is_none());
        assert!(m.find_vma(0x402000).is_some());
    }

    #[test]
    fn map_anywhere_is_top_down() {
        let m = mem();
        let a = m.map_anywhere(0x7000_0000, 0x2000, Prot::RW, "a").unwrap();
        let b = m.map_anywhere(0x7000_0000, 0x1000, Prot::RW, "b").unwrap();
        assert_eq!(a, 0x7000_0000 - 0x2000);
        assert_eq!(b, a - 0x1000);
        m.write::<u8>(b, 1).unwrap();
    }
}
