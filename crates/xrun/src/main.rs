//! `xrun` — run an x86-64 Linux executable on Apple Silicon.
//!
//! ```text
//! xrun [--strace] [--stats] [--clear-env] [--] program [args...]
//! ```

use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use linux_abi::{ExitStatus, Options, Process};
use x86_cpu::interp::Interpreter;
use x86_cpu::Engine;

static GUEST_BASE: AtomicUsize = AtomicUsize::new(0);
static GUEST_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Host SIGSEGV/SIGBUS: an access to an unmapped part of the guest reservation
/// ends up here. Report it as a guest fault (signal delivery to the guest
/// arrives in stage 4).
extern "C" fn on_fault(sig: i32, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    let addr = unsafe { (*info).si_addr } as usize;
    let (base, size) = (GUEST_BASE.load(Ordering::Relaxed), GUEST_SIZE.load(Ordering::Relaxed));
    let mut msg = [0u8; 96];
    let mut n = 0;
    let mut put = |s: &[u8]| {
        for &b in s {
            if n < msg.len() {
                msg[n] = b;
                n += 1;
            }
        }
    };
    // Darwin reports faults inside the PROT_NONE reservation as SIGBUS; for the
    // guest it is a Linux SIGSEGV (11) either way.
    let guest = addr >= base && addr < base + size;
    if guest {
        put(b"xrun: guest killed by SIGSEGV: access to unmapped guest address 0x");
        let g = addr - base;
        for k in (0..16).rev() {
            put(&[b"0123456789abcdef"[(g >> (4 * k)) & 15]]);
        }
    } else {
        put(b"xrun: host fault (bug in the emulator)");
    }
    put(b"\n");
    unsafe {
        libc::write(2, msg.as_ptr() as *const _, n);
        libc::_exit(128 + if guest { 11 } else { sig });
    }
}

fn install_fault_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_fault as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: xrun [--strace] [--stats] [--clear-env] [--] program [args...]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).peekable();
    let (mut opts, mut stats, mut clear_env) = (Options::default(), false, false);
    while let Some(a) = args.peek() {
        match a.as_bytes() {
            b"--strace" => opts.strace = true,
            b"--stats" => stats = true,
            b"--clear-env" => clear_env = true,
            b"--" => {
                args.next();
                break;
            }
            b"-h" | b"--help" => return usage(),
            _ => break,
        }
        args.next();
    }
    let argv: Vec<Vec<u8>> = args.map(|a| a.as_bytes().to_vec()).collect();
    let Some(path) = argv.first() else { return usage() };
    let path = std::ffi::OsStr::from_bytes(path).to_owned();
    let exe = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("xrun: {}: {e}", path.to_string_lossy());
            return ExitCode::from(127);
        }
    };
    let envp: Vec<Vec<u8>> = if clear_env {
        Vec::new()
    } else {
        std::env::vars_os().map(|(k, v)| [k.as_bytes(), b"=", v.as_bytes()].concat()).collect()
    };

    let mut proc = match Process::new(&exe, &argv, &envp, opts) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("xrun: {}: {e}", path.to_string_lossy());
            return ExitCode::from(126);
        }
    };
    GUEST_BASE.store(proc.mem.base() as usize, Ordering::Relaxed);
    GUEST_SIZE.store(proc.mem.size() as usize, Ordering::Relaxed);
    install_fault_handler();

    let mut engine = Interpreter::new();
    let t = Instant::now();
    let status = proc.run(&mut engine);
    let wall = t.elapsed();

    if stats {
        let s = engine.stats();
        let secs = wall.as_secs_f64();
        eprintln!(
            "[stats] {} guest insns in {:.3} s = {:.1} MIPS; {} blocks / {} insns decoded, decode {:.2} ms ({:.2}% of run time)",
            s.insns,
            secs,
            s.insns as f64 / secs / 1e6,
            s.blocks_decoded,
            s.insns_decoded,
            s.decode_ns as f64 / 1e6,
            s.decode_ns as f64 / 1e9 / secs * 100.0
        );
    }
    if let ExitStatus::Signaled(_, why) = &status {
        eprintln!("xrun: guest killed by signal: {why}");
    }
    ExitCode::from(status.code() as u8)
}
