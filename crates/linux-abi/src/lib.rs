//! Layer 2 — the system.
//!
//! Runs an x86-64 Linux process on macOS: loads the ELF image into the guest
//! address space, builds the initial stack the kernel would build
//! (argc/argv/envp/auxv), and services Linux system calls with Darwin ones.

pub mod elf;
pub mod errno;
mod syscall;

use std::sync::Arc;

use guest_mem::{GuestMemory, Prot};
use x86_cpu::{Cpu, Engine, Exit, RSP};

/// Guest address-space layout (all below `guest_mem::DEFAULT_SIZE`).
pub const STACK_TOP: u64 = 0x0000_1fff_ff00_0000;
pub const STACK_SIZE: u64 = 8 << 20;
/// `mmap` without a hint allocates top-down below this address.
pub const MMAP_TOP: u64 = 0x0000_1f00_0000_0000;

// Auxiliary vector keys (linux/auxvec.h).
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    Exited(i32),
    /// Killed by a signal (number, human readable reason).
    Signaled(i32, String),
}

impl ExitStatus {
    /// Shell convention: 128 + signal number.
    pub fn code(&self) -> i32 {
        match self {
            ExitStatus::Exited(c) => *c,
            ExitStatus::Signaled(s, _) => 128 + s,
        }
    }
}

#[derive(Clone, Default)]
pub struct Options {
    /// Print every system call to stderr.
    pub strace: bool,
}

pub struct Process {
    pub mem: Arc<GuestMemory>,
    pub cpu: Cpu,
    pub opts: Options,
    brk_start: u64,
    brk: u64,
    tid: u64,
}

impl Process {
    /// Load `exe` (contents of the ELF file) and prepare the initial thread.
    pub fn new(exe: &[u8], argv: &[Vec<u8>], envp: &[Vec<u8>], opts: Options) -> Result<Process, String> {
        let mem = Arc::new(GuestMemory::new(guest_mem::DEFAULT_SIZE).map_err(|e| e.to_string())?);
        let execfn = argv.first().cloned().unwrap_or_default();
        let elf = elf::load(&mem, exe, &String::from_utf8_lossy(&execfn))?;
        if let Some(interp) = &elf.interp {
            return Err(format!(
                "dynamically linked executable (interpreter {interp}); only static binaries are supported so far"
            ));
        }
        let mut cpu = Cpu::default();
        cpu.rip = elf.entry;
        cpu.gpr[RSP] = setup_stack(&mem, &elf, argv, envp, &execfn).map_err(|e| e.to_string())?;
        Ok(Process { mem, cpu, opts, brk_start: elf.end, brk: elf.end, tid: std::process::id() as u64 })
    }

    /// Run until the guest exits or dies.
    pub fn run(&mut self, engine: &mut dyn Engine) -> ExitStatus {
        loop {
            let exit = engine.run(&mut self.cpu, &self.mem);
            let (sig, why) = match exit {
                Exit::Syscall => {
                    if let Some(code) = self.syscall(engine) {
                        return ExitStatus::Exited(code);
                    }
                    continue;
                }
                Exit::Fault(f) => (libc::SIGSEGV, f.to_string()),
                Exit::Halt => (libc::SIGSEGV, "hlt in user mode".into()),
                Exit::Breakpoint => (libc::SIGTRAP, "int3".into()),
                Exit::InvalidOpcode => (libc::SIGILL, "invalid opcode".into()),
                Exit::Unimplemented(what) => (libc::SIGILL, format!("unimplemented instruction: {what}")),
                Exit::DivideError => (libc::SIGFPE, "divide error".into()),
            };
            let mut bytes = [0u8; 8];
            let shown = self.mem.read_bytes(self.cpu.rip, &mut bytes).is_ok();
            let bytes = if shown { format!(" bytes {:02x?}", bytes) } else { String::new() };
            return ExitStatus::Signaled(sig, format!("{why} at rip={:#x}{bytes}", self.cpu.rip));
        }
    }
}

/// Build the initial process stack as Linux does (see fs/binfmt_elf.c and the
/// x86-64 psABI, "Process Initialization"):
///
/// ```text
///   rsp -> argc
///          argv[0..argc], NULL
///          envp[..], NULL
///          auxv pairs, AT_NULL
///          ... padding, 16 random bytes, strings ...
/// ```
fn setup_stack(mem: &GuestMemory, elf: &elf::LoadedElf, argv: &[Vec<u8>], envp: &[Vec<u8>], execfn: &[u8]) -> Result<u64, guest_mem::Fault> {
    let base = STACK_TOP - STACK_SIZE;
    mem.map_fixed(base, STACK_SIZE, Prot::RW, "[stack]").expect("stack mapping");
    let mut sp = STACK_TOP;
    let mut put_str = |s: &[u8]| -> Result<u64, guest_mem::Fault> {
        sp -= s.len() as u64 + 1;
        mem.write_bytes(sp, s)?;
        mem.write::<u8>(sp + s.len() as u64, 0)?;
        Ok(sp)
    };
    let execfn_p = put_str(execfn)?;
    let platform_p = put_str(b"x86_64")?;
    let env_p: Vec<u64> = envp.iter().map(|s| put_str(s)).collect::<Result<_, _>>()?;
    let arg_p: Vec<u64> = argv.iter().map(|s| put_str(s)).collect::<Result<_, _>>()?;
    sp &= !15;
    sp -= 16;
    let random_p = sp;
    let mut rnd = [0u8; 16];
    unsafe { libc::arc4random_buf(rnd.as_mut_ptr() as *mut _, 16) };
    mem.write_bytes(random_p, &rnd)?;

    let ids = unsafe { (libc::getuid(), libc::geteuid(), libc::getgid(), libc::getegid()) };
    let auxv: [(u64, u64); 17] = [
        (AT_PHDR, elf.phdr),
        (AT_PHENT, elf.phent),
        (AT_PHNUM, elf.phnum),
        (AT_PAGESZ, guest_mem::GUEST_PAGE),
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, elf.entry),
        (AT_UID, ids.0 as u64),
        (AT_EUID, ids.1 as u64),
        (AT_GID, ids.2 as u64),
        (AT_EGID, ids.3 as u64),
        (AT_HWCAP, x86_cpu::cpuid::LEAF1_EDX as u64),
        (AT_CLKTCK, 100),
        (AT_SECURE, 0),
        (AT_RANDOM, random_p),
        (AT_PLATFORM, platform_p),
        (AT_EXECFN, execfn_p),
    ];
    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(&arg_p);
    words.push(0);
    words.extend(&env_p);
    words.push(0);
    for (k, v) in auxv {
        words.push(k);
        words.push(v);
    }
    words.push(AT_NULL);
    words.push(0);
    sp -= words.len() as u64 * 8;
    sp &= !15; // rsp must be 16-byte aligned at the entry point
    for (k, w) in words.iter().enumerate() {
        mem.write::<u64>(sp + 8 * k as u64, *w)?;
    }
    Ok(sp)
}
