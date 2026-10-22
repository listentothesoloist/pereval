//! Linux x86-64 system calls implemented on Darwin.
//!
//! Calling convention: number in RAX, arguments in RDI RSI RDX R10 R8 R9,
//! result (or -errno) in RAX. Numbers from arch/x86/entry/syscalls/syscall_64.tbl.

use guest_mem::{page_align_up, Prot, GUEST_PAGE};
use x86_cpu::{Engine, R10, R8, R9, RAX, RDI, RDX, RSI};

use crate::errno::{self, EBADF, EFAULT, EINVAL, ENODEV, ENOMEM, ENOSYS, ENOTTY};
use crate::{Process, MMAP_TOP};

const MAP_SHARED: u64 = 0x01;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x100000;

const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;

const TCGETS: u64 = 0x5401;
const TIOCGWINSZ: u64 = 0x5413;

fn name(nr: u64) -> &'static str {
    match nr {
        0 => "read",
        1 => "write",
        3 => "close",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        16 => "ioctl",
        19 => "readv",
        20 => "writev",
        24 => "sched_yield",
        28 => "madvise",
        39 => "getpid",
        60 => "exit",
        63 => "uname",
        96 => "gettimeofday",
        102 => "getuid",
        104 => "getgid",
        107 => "geteuid",
        108 => "getegid",
        110 => "getppid",
        131 => "sigaltstack",
        158 => "arch_prctl",
        186 => "gettid",
        201 => "time",
        218 => "set_tid_address",
        228 => "clock_gettime",
        229 => "clock_getres",
        231 => "exit_group",
        273 => "set_robust_list",
        302 => "prlimit64",
        318 => "getrandom",
        334 => "rseq",
        _ => "?",
    }
}

/// Result of a host call returning -1 on error.
fn host(r: isize) -> i64 {
    if r < 0 {
        errno::last()
    } else {
        r as i64
    }
}

impl Process {
    /// Service the syscall the guest just executed. Returns `Some(code)` when
    /// the process exits.
    pub(crate) fn syscall(&mut self, engine: &mut dyn Engine) -> Option<i32> {
        let g = self.cpu.gpr;
        let (nr, a) = (g[RAX], [g[RDI], g[RSI], g[RDX], g[R10], g[R8], g[R9]]);
        let ret = match nr {
            60 | 231 => {
                if self.opts.strace {
                    eprintln!("[strace] {}({}) = ?", name(nr), a[0] as i32);
                }
                return Some(a[0] as i32 & 0xff);
            }
            _ => self.dispatch(nr, a, engine),
        };
        if self.opts.strace {
            eprintln!("[strace] {}#{nr}({:#x}, {:#x}, {:#x}, {:#x}) = {ret}", name(nr), a[0], a[1], a[2], a[3]);
        }
        self.cpu.gpr[RAX] = ret as u64;
        None
    }

    fn dispatch(&mut self, nr: u64, a: [u64; 6], engine: &mut dyn Engine) -> i64 {
        let mem = &*self.mem;
        let fd = a[0] as i32;
        match nr {
            0 => match mem.slice_mut(a[1], a[2] as usize) {
                Ok(buf) => host(unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) }),
                Err(_) => -EFAULT,
            },
            1 => match mem.slice(a[1], a[2] as usize) {
                Ok(buf) => host(unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) }),
                Err(_) => -EFAULT,
            },
            3 => host(unsafe { libc::close(fd) } as isize),
            19 | 20 => self.rw_vec(nr == 20, fd, a[1], a[2]),
            9 => self.mmap(a, engine),
            10 => {
                if a[0] % GUEST_PAGE != 0 {
                    return -EINVAL;
                }
                match mem.protect(a[0], a[1], Prot::from_linux(a[2])) {
                    Ok(()) => {
                        engine.invalidate(a[0], a[1]);
                        0
                    }
                    Err(_) => -ENOMEM,
                }
            }
            11 => match mem.unmap(a[0], a[1]) {
                Ok(()) => {
                    engine.invalidate(a[0], a[1]);
                    0
                }
                Err(_) => -EINVAL,
            },
            12 => self.brk(a[0]) as i64,
            // Signals arrive in stage 4. Until then handlers are accepted and
            // never invoked, and every signal stays unblocked.
            13 => {
                if a[2] != 0 && mem.write_bytes(a[2], &[0u8; 32]).is_err() {
                    return -EFAULT;
                }
                0
            }
            14 => {
                if a[2] != 0 && mem.write::<u64>(a[2], 0).is_err() {
                    return -EFAULT;
                }
                0
            }
            131 => {
                // old stack: report "disabled" (SS_DISABLE = 2)
                if a[1] != 0 && mem.write_bytes(a[1], &[0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err() {
                    return -EFAULT;
                }
                0
            }
            16 => self.ioctl(fd, a[1], a[2]),
            24 => {
                std::thread::yield_now();
                0
            }
            28 => 0, // madvise: advisory
            39 => std::process::id() as i64,
            110 => unsafe { libc::getppid() as i64 },
            186 => self.tid as i64,
            102 => unsafe { libc::getuid() as i64 },
            104 => unsafe { libc::getgid() as i64 },
            107 => unsafe { libc::geteuid() as i64 },
            108 => unsafe { libc::getegid() as i64 },
            63 => self.uname(a[0]),
            158 => match a[0] {
                ARCH_SET_FS => {
                    self.cpu.fs_base = a[1];
                    0
                }
                ARCH_SET_GS => {
                    self.cpu.gs_base = a[1];
                    0
                }
                ARCH_GET_FS | ARCH_GET_GS => {
                    let v = if a[0] == ARCH_GET_FS { self.cpu.fs_base } else { self.cpu.gs_base };
                    if mem.write::<u64>(a[1], v).is_err() {
                        -EFAULT
                    } else {
                        0
                    }
                }
                _ => -EINVAL,
            },
            218 => self.tid as i64,
            273 => 0,
            96 => {
                let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
                unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
                if a[0] != 0 && (mem.write::<i64>(a[0], tv.tv_sec).is_err() || mem.write::<i64>(a[0] + 8, tv.tv_usec as i64).is_err()) {
                    return -EFAULT;
                }
                0
            }
            201 => {
                let t = unsafe { libc::time(std::ptr::null_mut()) };
                if a[0] != 0 && mem.write::<i64>(a[0], t).is_err() {
                    return -EFAULT;
                }
                t
            }
            228 | 229 => {
                let clk = match a[0] {
                    0 | 5 => libc::CLOCK_REALTIME,
                    1 | 6 | 7 => libc::CLOCK_MONOTONIC,
                    2 => libc::CLOCK_PROCESS_CPUTIME_ID,
                    3 => libc::CLOCK_THREAD_CPUTIME_ID,
                    4 => libc::CLOCK_MONOTONIC_RAW,
                    _ => return -EINVAL,
                };
                let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                let r = unsafe {
                    if nr == 228 {
                        libc::clock_gettime(clk, &mut ts)
                    } else {
                        libc::clock_getres(clk, &mut ts)
                    }
                };
                if r != 0 {
                    return errno::last();
                }
                if a[1] != 0 && (mem.write::<i64>(a[1], ts.tv_sec).is_err() || mem.write::<i64>(a[1] + 8, ts.tv_nsec).is_err()) {
                    return -EFAULT;
                }
                0
            }
            302 => self.prlimit(a[1], a[3]),
            318 => match mem.slice_mut(a[0], a[1] as usize) {
                Ok(buf) => {
                    unsafe { libc::arc4random_buf(buf.as_mut_ptr() as *mut _, buf.len()) };
                    buf.len() as i64
                }
                Err(_) => -EFAULT,
            },
            _ => {
                if !self.opts.strace {
                    eprintln!("pereval: unimplemented syscall {} ({nr}), returning -ENOSYS", name(nr));
                }
                -ENOSYS
            }
        }
    }

    fn rw_vec(&mut self, write: bool, fd: i32, iov: u64, cnt: u64) -> i64 {
        if cnt > 1024 {
            return -EINVAL;
        }
        let mut v = Vec::with_capacity(cnt as usize);
        for k in 0..cnt {
            let (Ok(base), Ok(len)) = (self.mem.read::<u64>(iov + 16 * k), self.mem.read::<u64>(iov + 16 * k + 8)) else {
                return -EFAULT;
            };
            let Ok(p) = self.mem.ptr(base, len as usize, !write) else { return -EFAULT };
            v.push(libc::iovec { iov_base: p as *mut _, iov_len: len as usize });
        }
        host(unsafe {
            if write {
                libc::writev(fd, v.as_ptr(), cnt as i32)
            } else {
                libc::readv(fd, v.as_ptr(), cnt as i32)
            }
        })
    }

    fn brk(&mut self, want: u64) -> u64 {
        if want < self.brk_start {
            return self.brk;
        }
        let (old_end, new_end) = (page_align_up(self.brk), page_align_up(want));
        let ok = if new_end > old_end {
            // Never clobber an existing mapping.
            let busy = (old_end..new_end).step_by(GUEST_PAGE as usize).any(|p| self.mem.find_vma(p).is_some());
            !busy && self.mem.map_fixed(old_end, new_end - old_end, Prot::RW, "[heap]").is_ok()
        } else {
            new_end == old_end || self.mem.unmap(new_end, old_end - new_end).is_ok()
        };
        if ok {
            self.brk = want;
        }
        self.brk
    }

    fn mmap(&mut self, a: [u64; 6], engine: &mut dyn Engine) -> i64 {
        let (addr, len, prot, flags, fd, off) = (a[0], a[1], Prot::from_linux(a[2]), a[3], a[4] as i32, a[5]);
        if len == 0 || off % GUEST_PAGE != 0 {
            return -EINVAL;
        }
        let len = page_align_up(len);
        let anon = flags & MAP_ANONYMOUS != 0;
        if !anon && flags & MAP_SHARED != 0 && prot.contains(Prot::W) {
            return -ENODEV; // writable shared file mappings: not yet
        }
        let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
        let free = |a: u64| (a..a + len).step_by(GUEST_PAGE as usize).all(|p| self.mem.find_vma(p).is_none());
        let res = if fixed {
            if addr % GUEST_PAGE != 0 {
                return -EINVAL;
            }
            if flags & MAP_FIXED_NOREPLACE != 0 && !free(addr) {
                return -17; // EEXIST
            }
            self.mem.map_fixed(addr, len, prot, "").map(|_| addr)
        } else if addr != 0 && addr % GUEST_PAGE == 0 && addr + len <= MMAP_TOP && free(addr) {
            self.mem.map_fixed(addr, len, prot, "").map(|_| addr)
        } else {
            self.mem.map_anywhere(MMAP_TOP, len, prot, "")
        };
        let Ok(at) = res else { return -ENOMEM };
        engine.invalidate(at, len);
        if !anon {
            // Private file mapping: copy the file contents in.
            let buf = self.mem.slice_mut(at, len as usize).unwrap();
            let mut done = 0usize;
            while done < buf.len() {
                let r = unsafe { libc::pread(fd, buf[done..].as_mut_ptr() as *mut _, buf.len() - done, (off as usize + done) as i64) };
                if r < 0 {
                    let e = errno::last();
                    let _ = self.mem.unmap(at, len);
                    return if e == -libc::EBADF as i64 { -EBADF } else { e };
                }
                if r == 0 {
                    break;
                }
                done += r as usize;
            }
        }
        at as i64
    }

    fn ioctl(&mut self, fd: i32, req: u64, arg: u64) -> i64 {
        match req {
            TIOCGWINSZ => {
                let mut ws = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
                if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } != 0 {
                    return errno::last();
                }
                // struct winsize has the same layout on both systems.
                let b: [u16; 4] = [ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel];
                for (k, v) in b.iter().enumerate() {
                    if self.mem.write::<u16>(arg + 2 * k as u64, *v).is_err() {
                        return -EFAULT;
                    }
                }
                0
            }
            TCGETS => {
                if unsafe { libc::isatty(fd) } == 0 {
                    return -ENOTTY;
                }
                // termios translation lands in stage 2; report a zeroed struct.
                if self.mem.write_bytes(arg, &[0u8; 60]).is_err() {
                    return -EFAULT;
                }
                0
            }
            _ => -ENOTTY,
        }
    }

    fn uname(&mut self, buf: u64) -> i64 {
        let mut host = String::from("localhost");
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut u) } == 0 {
            host = unsafe { std::ffi::CStr::from_ptr(u.nodename.as_ptr()) }.to_string_lossy().into_owned();
        }
        let fields = ["Linux", &host, "6.8.0-pereval", "#1 SMP PREEMPT_DYNAMIC", "x86_64", "(none)"];
        for (k, f) in fields.iter().enumerate() {
            let mut b = [0u8; 65];
            let n = f.len().min(64);
            b[..n].copy_from_slice(&f.as_bytes()[..n]);
            if self.mem.write_bytes(buf + 65 * k as u64, &b).is_err() {
                return -EFAULT;
            }
        }
        0
    }

    fn prlimit(&mut self, res: u64, old: u64) -> i64 {
        const INF: u64 = u64::MAX;
        let (cur, max) = match res {
            3 => (crate::STACK_SIZE, INF), // RLIMIT_STACK
            7 => {
                // RLIMIT_NOFILE
                let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) };
                (r.rlim_cur.min(1 << 20), r.rlim_max.min(1 << 20))
            }
            0..=15 => (INF, INF),
            _ => return -EINVAL,
        };
        if old != 0 && (self.mem.write::<u64>(old, cur).is_err() || self.mem.write::<u64>(old + 8, max).is_err()) {
            return -EFAULT;
        }
        0
    }
}
