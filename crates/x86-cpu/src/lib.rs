//! Layer 1 — the processor.
//!
//! * [`decode`]: x86-64 instruction decoder.
//! * [`Cpu`]: architectural state of one guest thread.
//! * [`Engine`]: anything that can execute guest code — today the
//!   [`interp::Interpreter`], later the JIT (which keeps the interpreter as its
//!   fallback for blocks still being compiled in the background).
//!
//! The CPU layer knows nothing about Linux or Windows: a `syscall`
//! instruction simply returns [`Exit::Syscall`] to the caller.

pub mod cpuid;
pub mod decode;
pub mod flags;
pub mod insn;
pub mod interp;
mod sse;

use flags::Flags;
pub use guest_mem::{Fault, GuestMemory};

pub const RAX: usize = 0;
pub const RCX: usize = 1;
pub const RDX: usize = 2;
pub const RBX: usize = 3;
pub const RSP: usize = 4;
pub const RBP: usize = 5;
pub const RSI: usize = 6;
pub const RDI: usize = 7;
pub const R8: usize = 8;
pub const R9: usize = 9;
pub const R10: usize = 10;
pub const R11: usize = 11;

/// Architectural state of one guest thread.
#[derive(Clone, Debug)]
pub struct Cpu {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub flags: Flags,
    pub fs_base: u64,
    pub gs_base: u64,
    pub xmm: [u128; 16],
    pub mxcsr: u32,
}

impl Default for Cpu {
    fn default() -> Cpu {
        Cpu { gpr: [0; 16], rip: 0, flags: Flags::default(), fs_base: 0, gs_base: 0, xmm: [0; 16], mxcsr: 0x1f80 }
    }
}

/// Why an engine stopped running guest code.
#[derive(Clone, Debug, PartialEq)]
pub enum Exit {
    /// `syscall` executed; `rip` already points after it.
    Syscall,
    /// `hlt` in user mode (#GP on hardware).
    Halt,
    /// `int3`.
    Breakpoint,
    /// Memory access fault; `rip` points at the faulting instruction.
    Fault(Fault),
    /// #UD: invalid encoding or `ud2`.
    InvalidOpcode,
    /// Valid instruction this engine does not implement yet.
    Unimplemented(String),
    /// #DE from `div`/`idiv`.
    DivideError,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Guest instructions retired.
    pub insns: u64,
    pub blocks_decoded: u64,
    pub insns_decoded: u64,
    /// Time spent decoding new blocks (ns) — the work a background compiler
    /// would take off the hot thread.
    pub decode_ns: u64,
}

pub trait Engine {
    /// Execute guest code starting at `cpu.rip` until something needs the
    /// layer above (a syscall, a fault, ...).
    fn run(&mut self, cpu: &mut Cpu, mem: &GuestMemory) -> Exit;
    /// Guest code in `[addr, addr + len)` may have changed or been unmapped.
    fn invalidate(&mut self, addr: u64, len: u64);
    fn stats(&self) -> Stats;
}
