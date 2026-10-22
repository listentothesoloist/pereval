//! Interpreter engine.
//!
//! Guest code is decoded once into basic blocks (straight-line runs ending in
//! a branch) which are cached by start address; execution walks the decoded
//! instructions. The block is also the unit the JIT will compile, so the cache
//! structure carries over: a block's entry will later point either at
//! decoded instructions (interpret) or at native Arm64 code (run).

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::Instant;

use guest_mem::{Fault, GuestMemory, Prot};

use crate::decode::{decode, DecodeError, MAX_INSN_LEN};
use crate::flags::{self, mask, sext, sign_bit, Kind};
use crate::insn::*;
use crate::{cpuid, Cpu, Engine, Exit, Stats, RAX, RBP, RCX, RDI, RDX, RSI, RSP};

/// Longest block we build; long straight-line code is split.
const MAX_BLOCK_INSNS: usize = 64;
const JCACHE_SIZE: usize = 4096;

pub struct Block {
    pub start: u64,
    pub end: u64,
    pub insns: Box<[Insn]>,
    /// Set when decoding stopped at an instruction we cannot execute; raised
    /// only if execution actually reaches `end`.
    pub error: Option<DecodeError>,
}

/// Fibonacci hashing for guest addresses (std's SipHash is needlessly slow here).
#[derive(Default)]
struct AddrHasher(u64);
impl Hasher for AddrHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!()
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = v.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

pub struct Interpreter {
    blocks: HashMap<u64, Rc<Block>, BuildHasherDefault<AddrHasher>>,
    /// Direct-mapped front cache: avoids the hash lookup on hot loops.
    jcache: Vec<Option<Rc<Block>>>,
    stats: Stats,
}

pub(crate) enum Trap {
    Fault(Fault),
    Exit(Exit),
}

impl From<Fault> for Trap {
    fn from(f: Fault) -> Trap {
        Trap::Fault(f)
    }
}

pub(crate) type R<T> = Result<T, Trap>;

enum Flow {
    Next,
    Jump,
}

/// A resolved operand location (effective address computed once for RMW ops).
#[derive(Clone, Copy)]
pub(crate) enum Loc {
    Gpr(u8, u8),
    High8(u8),
    Mem(u64, u8),
    Imm(u64),
}

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl Interpreter {
    pub fn new() -> Interpreter {
        Interpreter { blocks: HashMap::default(), jcache: vec![None; JCACHE_SIZE], stats: Stats::default() }
    }

    fn lookup(&mut self, rip: u64, mem: &GuestMemory) -> Result<Rc<Block>, Exit> {
        let slot = (rip as usize ^ (rip >> 12) as usize) & (JCACHE_SIZE - 1);
        if let Some(b) = &self.jcache[slot] {
            if b.start == rip {
                return Ok(b.clone());
            }
        }
        let b = match self.blocks.get(&rip) {
            Some(b) => b.clone(),
            None => {
                let t = Instant::now();
                let b = Rc::new(decode_block(rip, mem)?);
                self.stats.decode_ns += t.elapsed().as_nanos() as u64;
                self.stats.blocks_decoded += 1;
                self.stats.insns_decoded += b.insns.len() as u64;
                self.blocks.insert(rip, b.clone());
                b
            }
        };
        self.jcache[slot] = Some(b.clone());
        Ok(b)
    }

    /// Decode and execute exactly one instruction, bypassing the block cache.
    pub fn step(&mut self, cpu: &mut Cpu, mem: &GuestMemory) -> Option<Exit> {
        let mut buf = [0u8; MAX_INSN_LEN];
        let n = fetch(mem, cpu.rip, &mut buf).ok()?;
        let insn = match decode(&buf[..n], cpu.rip) {
            Ok(i) => i,
            Err(e) => return Some(decode_exit(e)),
        };
        let pc = cpu.rip;
        cpu.rip = pc.wrapping_add(insn.len as u64);
        self.stats.insns += 1;
        match cpu.exec(mem, &insn) {
            Ok(_) => None,
            Err(t) => Some(finish_trap(cpu, pc, t)),
        }
    }
}

impl Engine for Interpreter {
    fn run(&mut self, cpu: &mut Cpu, mem: &GuestMemory) -> Exit {
        loop {
            let block = match self.lookup(cpu.rip, mem) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let mut done = 0;
            for insn in block.insns.iter() {
                let pc = cpu.rip;
                cpu.rip = pc.wrapping_add(insn.len as u64);
                match cpu.exec(mem, insn) {
                    Ok(Flow::Next) => done += 1,
                    Ok(Flow::Jump) => {
                        done += 1;
                        break;
                    }
                    Err(t) => {
                        let syscall = matches!(t, Trap::Exit(Exit::Syscall));
                        self.stats.insns += done + syscall as u64;
                        return finish_trap(cpu, pc, t);
                    }
                }
            }
            self.stats.insns += done;
            if let Some(e) = &block.error {
                if cpu.rip == block.end {
                    return decode_exit(e.clone());
                }
            }
        }
    }

    fn invalidate(&mut self, addr: u64, len: u64) {
        let end = addr.saturating_add(len);
        self.blocks.retain(|_, b| b.end <= addr || b.start >= end);
        self.jcache.iter_mut().for_each(|s| *s = None);
    }

    fn stats(&self) -> Stats {
        self.stats.clone()
    }
}

fn finish_trap(cpu: &mut Cpu, pc: u64, t: Trap) -> Exit {
    match t {
        Trap::Exit(Exit::Syscall) => Exit::Syscall,
        Trap::Exit(e) => {
            cpu.rip = pc;
            e
        }
        Trap::Fault(f) => {
            cpu.rip = pc;
            Exit::Fault(f)
        }
    }
}

fn decode_exit(e: DecodeError) -> Exit {
    match e {
        DecodeError::Invalid => Exit::InvalidOpcode,
        DecodeError::Unsupported(what) => Exit::Unimplemented(what.to_string()),
        // Unreachable in practice: fetch() reports the fault first.
        DecodeError::Truncated => Exit::InvalidOpcode,
    }
}

/// Copy up to 15 instruction bytes at `rip`, stopping at the end of the
/// executable mapping. Fails if `rip` itself is not executable.
fn fetch(mem: &GuestMemory, rip: u64, buf: &mut [u8; MAX_INSN_LEN]) -> Result<usize, Exit> {
    let vma = mem.find_vma(rip).filter(|v| v.prot.contains(Prot::X));
    let vma = vma.ok_or(Exit::Fault(Fault { addr: rip, write: false }))?;
    let mut n = ((vma.end - rip) as usize).min(MAX_INSN_LEN);
    // The next mapping may continue the executable range (e.g. split VMAs).
    if n < MAX_INSN_LEN {
        if let Some(next) = mem.find_vma(vma.end).filter(|v| v.prot.contains(Prot::X)) {
            n = ((next.end - rip) as usize).min(MAX_INSN_LEN);
        }
    }
    mem.read_bytes(rip, &mut buf[..n]).map_err(Exit::Fault)?;
    Ok(n)
}

fn decode_block(start: u64, mem: &GuestMemory) -> Result<Block, Exit> {
    let mut insns = Vec::new();
    let mut pc = start;
    let mut buf = [0u8; MAX_INSN_LEN];
    let mut error = None;
    while insns.len() < MAX_BLOCK_INSNS {
        let n = match fetch(mem, pc, &mut buf) {
            Ok(n) => n,
            Err(e) if insns.is_empty() => return Err(e),
            Err(_) => break, // the fault is raised when execution gets there
        };
        match decode(&buf[..n], pc) {
            Ok(i) => {
                pc += i.len as u64;
                let end = i.is_block_end();
                insns.push(i);
                if end {
                    break;
                }
            }
            Err(DecodeError::Truncated) if insns.is_empty() => {
                return Err(Exit::Fault(Fault { addr: pc + n as u64, write: false }));
            }
            Err(DecodeError::Truncated) => break,
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    Ok(Block { start, end: pc, insns: insns.into_boxed_slice(), error })
}

fn rdtsc_now() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

pub(crate) fn op_size(op: &Operand) -> u8 {
    match op {
        Operand::Reg(Reg::Gpr { size, .. }) => *size,
        Operand::Reg(Reg::High8(_)) => 1,
        Operand::Reg(Reg::Xmm(_)) => 16,
        Operand::Mem(m) => m.size,
        _ => 8,
    }
}

impl Cpu {
    #[inline(always)]
    pub(crate) fn ea_noseg(&self, m: &Mem) -> u64 {
        let mut a = m.disp as u64;
        if m.base != NO_REG {
            a = a.wrapping_add(self.gpr[m.base as usize]);
        }
        if m.index != NO_REG {
            a = a.wrapping_add(self.gpr[m.index as usize] << m.scale);
        }
        if m.addr32 {
            a &= 0xffff_ffff;
        }
        a
    }

    #[inline(always)]
    pub(crate) fn ea(&self, m: &Mem) -> u64 {
        let a = self.ea_noseg(m);
        match m.seg {
            Seg::None => a,
            Seg::Fs => a.wrapping_add(self.fs_base),
            Seg::Gs => a.wrapping_add(self.gs_base),
        }
    }

    #[inline(always)]
    pub(crate) fn loc(&self, op: &Operand) -> Loc {
        match *op {
            Operand::Reg(Reg::Gpr { idx, size }) => Loc::Gpr(idx, size),
            Operand::Reg(Reg::High8(i)) => Loc::High8(i),
            Operand::Mem(ref m) => Loc::Mem(self.ea(m), m.size),
            Operand::Imm(v) => Loc::Imm(v),
            // Segment registers read as 0 (null selectors); XMM never reaches here.
            _ => Loc::Imm(0),
        }
    }

    #[inline(always)]
    pub(crate) fn ld(&self, mem: &GuestMemory, l: Loc) -> Result<u64, Fault> {
        Ok(match l {
            Loc::Gpr(i, s) => self.gpr[i as usize] & mask(s),
            Loc::High8(i) => (self.gpr[i as usize] >> 8) & 0xff,
            Loc::Mem(a, s) => read_sized(mem, a, s)?,
            Loc::Imm(v) => v,
        })
    }

    #[inline(always)]
    pub(crate) fn st(&mut self, mem: &GuestMemory, l: Loc, v: u64) -> Result<(), Fault> {
        match l {
            Loc::Gpr(i, s) => self.set_gpr(i as usize, s, v),
            Loc::High8(i) => {
                let r = &mut self.gpr[i as usize];
                *r = (*r & !0xff00) | ((v & 0xff) << 8);
            }
            Loc::Mem(a, s) => write_sized(mem, a, s, v)?,
            Loc::Imm(_) => {}
        }
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn get(&self, mem: &GuestMemory, op: &Operand) -> Result<u64, Fault> {
        self.ld(mem, self.loc(op))
    }

    /// Write a GPR with x86-64 partial-register semantics: 32-bit writes
    /// zero-extend, 8/16-bit writes merge.
    #[inline(always)]
    pub fn set_gpr(&mut self, i: usize, size: u8, v: u64) {
        let r = &mut self.gpr[i];
        *r = match size {
            8 => v,
            4 => v & 0xffff_ffff,
            2 => (*r & !0xffff) | (v & 0xffff),
            _ => (*r & !0xff) | (v & 0xff),
        };
    }

    #[inline(always)]
    fn push(&mut self, mem: &GuestMemory, size: u8, v: u64) -> Result<(), Fault> {
        let sp = self.gpr[RSP].wrapping_sub(size as u64);
        write_sized(mem, sp, size, v)?;
        self.gpr[RSP] = sp;
        Ok(())
    }

    #[inline(always)]
    fn pop(&mut self, mem: &GuestMemory, size: u8) -> Result<u64, Fault> {
        let sp = self.gpr[RSP];
        let v = read_sized(mem, sp, size)?;
        self.gpr[RSP] = sp.wrapping_add(size as u64);
        Ok(v)
    }

    fn modify_flags(&mut self, f: impl FnOnce(u64) -> u64) {
        let bits = self.flags.arith_bits();
        self.flags.set_explicit(f(bits));
    }

    fn set_flag(&mut self, flag: u64, on: bool) {
        self.modify_flags(|b| if on { b | flag } else { b & !flag });
    }

    #[inline(always)]
    fn exec(&mut self, mem: &GuestMemory, i: &Insn) -> R<Flow> {
        use Op::*;
        let s = i.osize;
        match i.op {
            Add | Or | Adc | Sbb | And | Sub | Xor | Cmp | Test => {
                let m = mask(s);
                let d = self.loc(&i.ops[0]);
                let a = self.ld(mem, d)?;
                let b = self.get(mem, &i.ops[1])? & m;
                let r = match i.op {
                    Add => {
                        let r = a.wrapping_add(b);
                        self.flags.set(Kind::Add, s, a, b, r);
                        r
                    }
                    Adc => {
                        let c = self.flags.cf() as u64;
                        let r = a.wrapping_add(b).wrapping_add(c);
                        self.flags.set_c(Kind::Adc, s, a, b, r, c);
                        r
                    }
                    Sub | Cmp => {
                        let r = a.wrapping_sub(b);
                        self.flags.set(Kind::Sub, s, a, b, r);
                        r
                    }
                    Sbb => {
                        let c = self.flags.cf() as u64;
                        let r = a.wrapping_sub(b).wrapping_sub(c);
                        self.flags.set_c(Kind::Sbb, s, a, b, r, c);
                        r
                    }
                    Or => a | b,
                    Xor => a ^ b,
                    _ => a & b, // And, Test
                };
                if matches!(i.op, Or | Xor | And | Test) {
                    self.flags.set(Kind::Logic, s, a, b, r);
                }
                if !matches!(i.op, Cmp | Test) {
                    self.st(mem, d, r & m)?;
                }
            }
            Inc | Dec => {
                let d = self.loc(&i.ops[0]);
                let a = self.ld(mem, d)?;
                let c = self.flags.cf() as u64;
                let (r, k) = if i.op == Inc { (a.wrapping_add(1), Kind::Inc) } else { (a.wrapping_sub(1), Kind::Dec) };
                self.flags.set_c(k, s, a, 1, r, c);
                self.st(mem, d, r & mask(s))?;
            }
            Neg => {
                let d = self.loc(&i.ops[0]);
                let a = self.ld(mem, d)?;
                let r = 0u64.wrapping_sub(a);
                self.flags.set(Kind::Neg, s, a, 0, r);
                self.st(mem, d, r & mask(s))?;
            }
            Not => {
                let d = self.loc(&i.ops[0]);
                let a = self.ld(mem, d)?;
                self.st(mem, d, !a & mask(s))?;
            }
            Mul | Imul1 => self.mul1(mem, i)?,
            Div | Idiv => self.div(mem, i)?,
            Imul => {
                let (a, b) = if let Operand::None = i.ops[2] {
                    (self.get(mem, &i.ops[0])?, self.get(mem, &i.ops[1])?)
                } else {
                    (self.get(mem, &i.ops[1])?, i.ops[2].imm())
                };
                let full = sext(a, s) as i128 * sext(b, s) as i128;
                let r = full as u64 & mask(s);
                let of = full != sext(r, s) as i128;
                self.flags.set_c(Kind::Mul, s, 0, 0, r, of as u64);
                let d = self.loc(&i.ops[0]);
                self.st(mem, d, r)?;
            }
            Rol | Ror | Rcl | Rcr | Shl | Shr | Sar => self.shift(mem, i)?,
            Shld | Shrd => self.shift_double(mem, i)?,
            Bt | Bts | Btr | Btc => self.bit_test(mem, i)?,
            Bsf | Bsr | Tzcnt | Lzcnt | Popcnt => {
                let src = self.get(mem, &i.ops[1])?;
                let d = self.loc(&i.ops[0]);
                let bits = s as u32 * 8;
                match i.op {
                    Bsf | Bsr => {
                        if src == 0 {
                            self.set_flag(flags::ZF, true);
                        } else {
                            let r = if i.op == Bsf { src.trailing_zeros() } else { 63 - src.leading_zeros() };
                            self.st(mem, d, r as u64)?;
                            self.set_flag(flags::ZF, false);
                        }
                    }
                    Tzcnt | Lzcnt => {
                        let r = if src == 0 {
                            bits
                        } else if i.op == Tzcnt {
                            src.trailing_zeros()
                        } else {
                            src.leading_zeros() - (64 - bits)
                        };
                        self.st(mem, d, r as u64)?;
                        let f = self.flags.arith_bits() & !(flags::CF | flags::ZF);
                        self.flags.set_explicit(f | (src == 0) as u64 * flags::CF | (r == 0) as u64 * flags::ZF);
                    }
                    _ => {
                        self.st(mem, d, src.count_ones() as u64)?;
                        self.flags.set_explicit((src == 0) as u64 * flags::ZF);
                    }
                }
            }
            Bswap => {
                let d = self.loc(&i.ops[0]);
                let v = self.ld(mem, d)?;
                let r = match s {
                    8 => v.swap_bytes(),
                    4 => (v as u32).swap_bytes() as u64,
                    _ => 0, // undefined for 16-bit; Intel hardware returns 0
                };
                self.st(mem, d, r)?;
            }
            Mov | Movzx => {
                let v = self.get(mem, &i.ops[1])?;
                let d = self.loc(&i.ops[0]);
                self.st(mem, d, v & mask(s))?;
            }
            Movsx => {
                let v = self.get(mem, &i.ops[1])?;
                let v = sext(v, op_size(&i.ops[1])) as u64;
                let d = self.loc(&i.ops[0]);
                self.st(mem, d, v & mask(s))?;
            }
            Lea => {
                let Operand::Mem(m) = &i.ops[1] else { unreachable!() };
                let a = self.ea_noseg(m);
                let d = self.loc(&i.ops[0]);
                self.st(mem, d, a)?;
            }
            Xchg => {
                let d0 = self.loc(&i.ops[0]);
                let d1 = self.loc(&i.ops[1]);
                let a = self.ld(mem, d0)?;
                let b = self.ld(mem, d1)?;
                self.st(mem, d0, b)?;
                self.st(mem, d1, a)?;
            }
            Cmpxchg => {
                let d = self.loc(&i.ops[0]);
                let dst = self.ld(mem, d)?;
                let acc = self.gpr[RAX] & mask(s);
                self.flags.set(Kind::Sub, s, acc, dst, acc.wrapping_sub(dst));
                if acc == dst {
                    let src = self.get(mem, &i.ops[1])?;
                    self.st(mem, d, src)?;
                } else {
                    // SDM: "accumulator := TEMP; DEST := TEMP" — the destination is
                    // written even on failure, so a 32-bit register is zero-extended.
                    self.set_gpr(RAX, s, dst);
                    self.st(mem, d, dst)?;
                }
            }
            CmpxchgDouble => {
                let Operand::Mem(m) = &i.ops[0] else { unreachable!() };
                let a = self.ea(m);
                let m = mask(s);
                let (lo, hi) = (read_sized(mem, a, s)?, read_sized(mem, a + s as u64, s)?);
                let eq = lo == self.gpr[RAX] & m && hi == self.gpr[RDX] & m;
                if eq {
                    write_sized(mem, a, s, self.gpr[crate::RBX])?;
                    write_sized(mem, a + s as u64, s, self.gpr[RCX])?;
                } else {
                    self.set_gpr(RAX, s, lo);
                    self.set_gpr(RDX, s, hi);
                }
                self.set_flag(flags::ZF, eq);
            }
            Xadd => {
                let d = self.loc(&i.ops[0]);
                let g = self.loc(&i.ops[1]);
                let a = self.ld(mem, d)?;
                let b = self.ld(mem, g)?;
                let r = a.wrapping_add(b);
                self.flags.set(Kind::Add, s, a, b, r);
                self.st(mem, g, a)?;
                self.st(mem, d, r & mask(s))?;
            }
            Push => {
                let v = self.get(mem, &i.ops[0])?;
                self.push(mem, s, v)?;
            }
            Pop => {
                let v = self.pop(mem, s)?;
                let d = self.loc(&i.ops[0]); // address computed after RSP is incremented
                self.st(mem, d, v)?;
            }
            Pushf => {
                let v = self.flags.rflags();
                self.push(mem, s, v)?;
            }
            Popf => {
                let v = self.pop(mem, s)?;
                self.flags.set_rflags(v);
            }
            Lahf => {
                let v = self.flags.rflags() & 0xff;
                self.st(mem, Loc::High8(0), v)?;
            }
            Sahf => {
                let ah = (self.gpr[RAX] >> 8) & 0xff;
                const M: u64 = flags::SF | flags::ZF | flags::AF | flags::PF | flags::CF;
                self.modify_flags(|b| (b & !M) | (ah & M));
            }
            Leave => {
                self.gpr[RSP] = self.gpr[RBP];
                let v = self.pop(mem, s)?;
                self.set_gpr(RBP, s, v);
            }
            Cbw => {
                let half = s / 2;
                let v = sext(self.gpr[RAX] & mask(half), half) as u64;
                self.set_gpr(RAX, s, v);
            }
            Cwd => {
                let neg = self.gpr[RAX] & sign_bit(s) != 0;
                self.set_gpr(RDX, s, if neg { u64::MAX } else { 0 });
            }
            Setcc => {
                let c = self.flags.cond(i.cond);
                let d = self.loc(&i.ops[0]);
                self.st(mem, d, c as u64)?;
            }
            Cmovcc => {
                let v = self.get(mem, &i.ops[1])?; // memory is read even if the condition is false
                let d = self.loc(&i.ops[0]);
                let v = if self.flags.cond(i.cond) { v } else { self.ld(mem, d)? };
                self.st(mem, d, v)?; // a 32-bit destination is zero-extended either way
            }
            Movs | Stos | Lods | Cmps | Scas => self.string_op(mem, i)?,
            Jmp => {
                self.rip = self.get(mem, &i.ops[0])?;
                return Ok(Flow::Jump);
            }
            Jcc => {
                if self.flags.cond(i.cond) {
                    self.rip = i.ops[0].imm();
                    return Ok(Flow::Jump);
                }
            }
            Call => {
                let t = self.get(mem, &i.ops[0])?;
                let ret = self.rip;
                self.push(mem, 8, ret)?;
                self.rip = t;
                return Ok(Flow::Jump);
            }
            Ret => {
                let t = self.pop(mem, 8)?;
                self.gpr[RSP] = self.gpr[RSP].wrapping_add(i.ops[0].imm());
                self.rip = t;
                return Ok(Flow::Jump);
            }
            Jrcxz | Loop | Loope | Loopne => {
                let take = if i.op == Jrcxz {
                    self.gpr[RCX] == 0
                } else {
                    self.gpr[RCX] = self.gpr[RCX].wrapping_sub(1);
                    self.gpr[RCX] != 0
                        && match i.op {
                            Loope => self.flags.zf(),
                            Loopne => !self.flags.zf(),
                            _ => true,
                        }
                };
                if take {
                    self.rip = i.ops[0].imm();
                    return Ok(Flow::Jump);
                }
            }
            Clc => self.set_flag(flags::CF, false),
            Stc => self.set_flag(flags::CF, true),
            Cmc => {
                let c = self.flags.cf();
                self.set_flag(flags::CF, !c);
            }
            Cld => self.flags.df = false,
            Std => self.flags.df = true,
            Nop => {}
            Hlt => return Err(Trap::Exit(Exit::Halt)),
            Int3 => return Err(Trap::Exit(Exit::Breakpoint)),
            Ud2 => return Err(Trap::Exit(Exit::InvalidOpcode)),
            Syscall => {
                self.gpr[RCX] = self.rip;
                self.gpr[crate::R11] = self.flags.rflags();
                return Err(Trap::Exit(Exit::Syscall));
            }
            Cpuid => {
                let (a, b, c, d) = cpuid::cpuid(self.gpr[RAX] as u32, self.gpr[RCX] as u32);
                self.set_gpr(RAX, 4, a as u64);
                self.set_gpr(crate::RBX, 4, b as u64);
                self.set_gpr(RCX, 4, c as u64);
                self.set_gpr(RDX, 4, d as u64);
            }
            Rdtsc => {
                let t = rdtsc_now();
                self.set_gpr(RAX, 4, t & 0xffff_ffff);
                self.set_gpr(RDX, 4, t >> 32);
            }
            Xgetbv => {
                self.set_gpr(RAX, 4, 3); // x87 + SSE state
                self.set_gpr(RDX, 4, 0);
            }
            Fence => std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst),
            Ldmxcsr => self.mxcsr = self.get(mem, &i.ops[0])? as u32,
            Stmxcsr => {
                let d = self.loc(&i.ops[0]);
                self.st(mem, d, self.mxcsr as u64)?;
            }
            Fxsave | Fxrstor => self.fxsave(mem, i)?,
            Sse(op) => self.sse(mem, op, i)?,
        }
        Ok(Flow::Next)
    }

    fn mul1(&mut self, mem: &GuestMemory, i: &Insn) -> R<()> {
        let s = i.osize;
        let bits = s as u32 * 8;
        let src = self.get(mem, &i.ops[0])?;
        let a = self.gpr[RAX] & mask(s);
        let (lo, hi, of) = if i.op == Op::Mul {
            let p = a as u128 * src as u128;
            let (lo, hi) = (p as u64 & mask(s), (p >> bits) as u64 & mask(s));
            (lo, hi, hi != 0)
        } else {
            let p = sext(a, s) as i128 * sext(src, s) as i128;
            let lo = p as u64 & mask(s);
            ((lo), (p >> bits) as u64 & mask(s), p != sext(lo, s) as i128)
        };
        if s == 1 {
            self.set_gpr(RAX, 2, lo | hi << 8);
        } else {
            self.set_gpr(RAX, s, lo);
            self.set_gpr(RDX, s, hi);
        }
        self.flags.set_c(Kind::Mul, s, 0, 0, lo, of as u64);
        Ok(())
    }

    fn div(&mut self, mem: &GuestMemory, i: &Insn) -> R<()> {
        let s = i.osize;
        let bits = s as u32 * 8;
        let m = mask(s);
        let src = self.get(mem, &i.ops[0])?;
        if src == 0 {
            return Err(Trap::Exit(Exit::DivideError));
        }
        let (hi, lo) = if s == 1 {
            ((self.gpr[RAX] >> 8) & 0xff, self.gpr[RAX] & 0xff)
        } else {
            (self.gpr[RDX] & m, self.gpr[RAX] & m)
        };
        let dividend = (hi as u128) << bits | lo as u128;
        let (q, r) = if i.op == Op::Div {
            let q = dividend / src as u128;
            if q > m as u128 {
                return Err(Trap::Exit(Exit::DivideError));
            }
            (q as u64, (dividend % src as u128) as u64)
        } else {
            // Sign-extend the double-width dividend.
            let sh = 128 - 2 * bits;
            let n = ((dividend << sh) as i128) >> sh;
            let d = sext(src, s) as i128;
            let q = n.wrapping_div(d);
            let lim = 1i128 << (bits - 1);
            if q >= lim || q < -lim {
                return Err(Trap::Exit(Exit::DivideError));
            }
            (q as u64 & m, n.wrapping_rem(d) as u64 & m)
        };
        if s == 1 {
            self.set_gpr(RAX, 2, q | r << 8);
        } else {
            self.set_gpr(RAX, s, q);
            self.set_gpr(RDX, s, r);
        }
        Ok(())
    }

    fn shift(&mut self, mem: &GuestMemory, i: &Insn) -> R<()> {
        use Op::*;
        let s = i.osize;
        let bits = s as u64 * 8;
        let m = mask(s);
        let count = self.get(mem, &i.ops[1])? & if s == 8 { 63 } else { 31 };
        let d = self.loc(&i.ops[0]);
        let a = self.ld(mem, d)?;
        if count == 0 {
            // Flags untouched, but a 32-bit register destination is still written.
            self.st(mem, d, a)?;
            return Ok(());
        }
        let msb = |v: u64| v & sign_bit(s) != 0;
        let r = match i.op {
            Shl => {
                let r = if count < bits { (a << count) & m } else { 0 };
                self.flags.set(Kind::Shl, s, a, count, r);
                r
            }
            Shr => {
                let r = if count < bits { a >> count } else { 0 };
                self.flags.set(Kind::Shr, s, a, count, r);
                r
            }
            Sar => {
                let r = (sext(a, s) >> count.min(63)) as u64 & m;
                self.flags.set(Kind::Sar, s, a, count, r);
                r
            }
            Rol | Ror => {
                let c = count % bits;
                let r = if c == 0 {
                    a
                } else if i.op == Rol {
                    ((a << c) | (a >> (bits - c))) & m
                } else {
                    ((a >> c) | (a << (bits - c))) & m
                };
                let (cf, of) = if i.op == Rol {
                    let cf = r & 1 != 0;
                    (cf, msb(r) ^ cf)
                } else {
                    (msb(r), msb(r) ^ (r & (sign_bit(s) >> 1) != 0))
                };
                self.modify_flags(|f| (f & !(flags::CF | flags::OF)) | cf as u64 * flags::CF | of as u64 * flags::OF);
                r
            }
            _ => {
                // RCL/RCR rotate through CF: a (bits + 1)-wide rotation.
                let n = match s {
                    1 => count % 9,
                    2 => count % 17,
                    _ => count,
                } as u32;
                if n == 0 {
                    self.st(mem, d, a)?;
                    return Ok(());
                }
                let w = bits as u32 + 1;
                let wm = (1u128 << w) - 1;
                let v = (self.flags.cf() as u128) << bits | a as u128;
                let v = if i.op == Rcl { (v << n | v >> (w - n)) & wm } else { (v >> n | v << (w - n)) & wm };
                let r = v as u64 & m;
                let cf = (v >> bits) & 1 != 0;
                let of = if i.op == Rcl { msb(r) ^ cf } else { msb(r) ^ (r & (sign_bit(s) >> 1) != 0) };
                self.modify_flags(|f| (f & !(flags::CF | flags::OF)) | cf as u64 * flags::CF | of as u64 * flags::OF);
                r
            }
        };
        self.st(mem, d, r)?;
        Ok(())
    }

    fn shift_double(&mut self, mem: &GuestMemory, i: &Insn) -> R<()> {
        let s = i.osize;
        let bits = s as u32 * 8;
        let m = mask(s);
        let n = (self.get(mem, &i.ops[2])? & if s == 8 { 63 } else { 31 }) as u32;
        let d = self.loc(&i.ops[0]);
        let a = self.ld(mem, d)?;
        let b = self.get(mem, &i.ops[1])?;
        if n == 0 {
            self.st(mem, d, a)?;
            return Ok(());
        }
        if i.op == Op::Shld {
            let cat = (a as u128) << bits | b as u128;
            let r = ((cat << n) >> bits) as u64 & m;
            self.flags.set(Kind::Shl, s, a, n as u64, r);
            self.st(mem, d, r)?;
        } else {
            let cat = (b as u128) << bits | a as u128;
            let r = (cat >> n) as u64 & m;
            self.flags.set(Kind::Shr, s, a, n as u64, r);
            let of = (r ^ a) & sign_bit(s) != 0;
            self.modify_flags(|f| (f & !flags::OF) | of as u64 * flags::OF);
            self.st(mem, d, r)?;
        }
        Ok(())
    }

    fn bit_test(&mut self, mem: &GuestMemory, i: &Insn) -> R<()> {
        let s = i.osize;
        let bits = s as u64 * 8;
        let off = self.get(mem, &i.ops[1])?;
        let d = match (&i.ops[0], &i.ops[1]) {
            // A register bit offset can address memory outside the operand.
            (Operand::Mem(m), Operand::Reg(_)) => {
                let o = sext(off, s);
                let a = self.ea(m).wrapping_add(((o >> (bits.trailing_zeros())) * s as i64) as u64);
                Loc::Mem(a, s)
            }
            (op, _) => self.loc(op),
        };
        let bit = off & (bits - 1);
        let v = self.ld(mem, d)?;
        let cf = (v >> bit) & 1 != 0;
        let nv = match i.op {
            Op::Bts => v | 1 << bit,
            Op::Btr => v & !(1 << bit),
            Op::Btc => v ^ 1 << bit,
            _ => v,
        };
        if i.op != Op::Bt {
            self.st(mem, d, nv)?;
        }
        self.set_flag(flags::CF, cf);
        Ok(())
    }

    fn string_op(&mut self, mem: &GuestMemory, i: &Insn) -> R<()> {
        use Op::*;
        let s = i.osize;
        let step = s as u64;
        let delta = if self.flags.df { step.wrapping_neg() } else { step };
        let rep = i.rep != Rep::None;
        if rep && self.gpr[RCX] == 0 {
            return Ok(());
        }
        // Fast paths for memcpy/memset-style `rep movs` / `rep stos`.
        if rep && !self.flags.df && matches!(i.op, Movs | Stos) {
            let n = self.gpr[RCX];
            if let Some(bytes) = n.checked_mul(step).filter(|&b| b <= 1 << 40) {
                let (src, dst) = (self.gpr[RSI], self.gpr[RDI]);
                let overlap = i.op == Movs && dst > src && dst < src.wrapping_add(bytes);
                if !overlap {
                    let dp = mem.ptr(dst, bytes as usize, true)?;
                    if i.op == Movs {
                        let sp = mem.ptr(src, bytes as usize, false)?;
                        unsafe { std::ptr::copy(sp, dp, bytes as usize) };
                        self.gpr[RSI] = src.wrapping_add(bytes);
                    } else if s == 1 {
                        unsafe { std::ptr::write_bytes(dp, self.gpr[RAX] as u8, bytes as usize) };
                    } else {
                        let v = self.gpr[RAX];
                        for k in 0..n {
                            write_sized(mem, dst + k * step, s, v)?;
                        }
                    }
                    self.gpr[RDI] = dst.wrapping_add(bytes);
                    self.gpr[RCX] = 0;
                    return Ok(());
                }
            }
        }
        loop {
            match i.op {
                Movs => {
                    let v = read_sized(mem, self.gpr[RSI], s)?;
                    write_sized(mem, self.gpr[RDI], s, v)?;
                    self.gpr[RSI] = self.gpr[RSI].wrapping_add(delta);
                    self.gpr[RDI] = self.gpr[RDI].wrapping_add(delta);
                }
                Stos => {
                    write_sized(mem, self.gpr[RDI], s, self.gpr[RAX])?;
                    self.gpr[RDI] = self.gpr[RDI].wrapping_add(delta);
                }
                Lods => {
                    let v = read_sized(mem, self.gpr[RSI], s)?;
                    self.set_gpr(RAX, s, v);
                    self.gpr[RSI] = self.gpr[RSI].wrapping_add(delta);
                }
                Cmps => {
                    let a = read_sized(mem, self.gpr[RSI], s)?;
                    let b = read_sized(mem, self.gpr[RDI], s)?;
                    self.flags.set(Kind::Sub, s, a, b, a.wrapping_sub(b));
                    self.gpr[RSI] = self.gpr[RSI].wrapping_add(delta);
                    self.gpr[RDI] = self.gpr[RDI].wrapping_add(delta);
                }
                _ => {
                    let a = self.gpr[RAX] & mask(s);
                    let b = read_sized(mem, self.gpr[RDI], s)?;
                    self.flags.set(Kind::Sub, s, a, b, a.wrapping_sub(b));
                    self.gpr[RDI] = self.gpr[RDI].wrapping_add(delta);
                }
            }
            if !rep {
                return Ok(());
            }
            self.gpr[RCX] = self.gpr[RCX].wrapping_sub(1);
            if self.gpr[RCX] == 0 {
                return Ok(());
            }
            if matches!(i.op, Cmps | Scas) {
                let zf = self.flags.zf();
                if (i.rep == Rep::Rep && !zf) || (i.rep == Rep::Repne && zf) {
                    return Ok(());
                }
            }
        }
    }

    fn fxsave(&mut self, mem: &GuestMemory, i: &Insn) -> R<()> {
        let Operand::Mem(m) = &i.ops[0] else { unreachable!() };
        let a = self.ea(m);
        if i.op == Op::Fxsave {
            mem.write_bytes(a, &[0u8; 512])?;
            mem.write::<u16>(a, 0x037f)?; // FCW default
            mem.write::<u32>(a + 24, self.mxcsr)?;
            mem.write::<u32>(a + 28, 0xffff)?; // MXCSR_MASK
            for (k, x) in self.xmm.iter().enumerate() {
                mem.write::<u128>(a + 160 + 16 * k as u64, *x)?;
            }
        } else {
            self.mxcsr = mem.read::<u32>(a + 24)?;
            for k in 0..16 {
                self.xmm[k] = mem.read::<u128>(a + 160 + 16 * k as u64)?;
            }
        }
        Ok(())
    }
}

impl Operand {
    #[inline(always)]
    pub(crate) fn imm(&self) -> u64 {
        match *self {
            Operand::Imm(v) => v,
            _ => 0,
        }
    }
}

#[inline(always)]
pub(crate) fn read_sized(mem: &GuestMemory, a: u64, s: u8) -> Result<u64, Fault> {
    Ok(match s {
        1 => mem.read::<u8>(a)? as u64,
        2 => mem.read::<u16>(a)? as u64,
        4 => mem.read::<u32>(a)? as u64,
        _ => mem.read::<u64>(a)?,
    })
}

#[inline(always)]
pub(crate) fn write_sized(mem: &GuestMemory, a: u64, s: u8, v: u64) -> Result<(), Fault> {
    match s {
        1 => mem.write::<u8>(a, v as u8),
        2 => mem.write::<u16>(a, v as u16),
        4 => mem.write::<u32>(a, v as u32),
        _ => mem.write::<u64>(a, v),
    }
}
