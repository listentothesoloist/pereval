//! x86-64 (long mode, 64-bit code segment) instruction decoder.
//!
//! Written from the Intel SDM vol. 2 (chapter 2 "Instruction Format" and the
//! opcode maps in appendix A). Only 64-bit mode is supported: 0x40..0x4F are
//! always REX prefixes, 0xC4/0xC5 are always VEX.

use crate::insn::*;

pub const MAX_INSN_LEN: usize = 15;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Ran out of bytes: the instruction runs into unmapped / non-executable memory.
    Truncated,
    /// An encoding that raises #UD (or #GP for privileged instructions) on hardware.
    Invalid,
    /// A valid encoding we do not implement yet.
    Unsupported(&'static str),
}

const REX_W: u8 = 8;
const REX_R: u8 = 4;
const REX_X: u8 = 2;
const REX_B: u8 = 1;

const ALU: [Op; 8] = [Op::Add, Op::Or, Op::Adc, Op::Sbb, Op::And, Op::Sub, Op::Xor, Op::Cmp];
const SHIFT: [Op; 8] = [Op::Rol, Op::Ror, Op::Rcl, Op::Rcr, Op::Shl, Op::Shr, Op::Shl, Op::Sar];

/// Mandatory-prefix selector for SSE opcodes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pfx {
    Np,
    P66,
    F3,
    F2,
}

struct ModRm {
    md: u8,
    /// reg field including REX.R (use `& 7` for /digit opcode extensions).
    reg: u8,
    /// rm field including REX.B, meaningful when `md == 3`.
    rm: u8,
    mem: Mem,
}

struct Decoder<'a> {
    b: &'a [u8],
    p: usize,
    ip: u64,
    opsize: bool,
    addrsize: bool,
    rep: u8,
    lock: bool,
    seg: Seg,
    rex: u8,
    riprel: bool,
}

struct Out {
    op: Op,
    osize: u8,
    cond: u8,
    ops: [Operand; 3],
}

fn out(op: Op, osize: u8, ops: [Operand; 3]) -> Out {
    Out { op, osize, cond: 0, ops }
}

const N: Operand = Operand::None;

/// Decode one instruction located at guest address `ip`. `bytes` holds the
/// instruction bytes available at `ip` (fewer than 15 near the end of a mapping).
pub fn decode(bytes: &[u8], ip: u64) -> Result<Insn, DecodeError> {
    let mut d = Decoder {
        b: bytes,
        p: 0,
        ip,
        opsize: false,
        addrsize: false,
        rep: 0,
        lock: false,
        seg: Seg::None,
        rex: 0,
        riprel: false,
    };
    let o = d.decode()?;
    let len = d.p as u8;
    let mut ops = o.ops;
    if d.riprel {
        let next = ip.wrapping_add(len as u64);
        for op in ops.iter_mut() {
            if let Operand::Mem(m) = op {
                m.disp = m.disp.wrapping_add(next as i64);
            }
        }
    }
    let rep = match d.rep {
        0xf3 => Rep::Rep,
        0xf2 => Rep::Repne,
        _ => Rep::None,
    };
    Ok(Insn { op: o.op, len, osize: o.osize, cond: o.cond, rep, lock: d.lock, ops })
}

impl<'a> Decoder<'a> {
    fn byte(&mut self) -> Result<u8, DecodeError> {
        if self.p >= MAX_INSN_LEN {
            return Err(DecodeError::Invalid);
        }
        let v = *self.b.get(self.p).ok_or(DecodeError::Truncated)?;
        self.p += 1;
        Ok(v)
    }
    fn imm8(&mut self) -> Result<u64, DecodeError> {
        Ok(self.byte()? as i8 as i64 as u64)
    }
    fn imm16(&mut self) -> Result<u64, DecodeError> {
        let lo = self.byte()? as u16;
        let hi = self.byte()? as u16;
        Ok((lo | hi << 8) as u64)
    }
    fn imm32(&mut self) -> Result<u64, DecodeError> {
        let mut v = 0u32;
        for i in 0..4 {
            v |= (self.byte()? as u32) << (8 * i);
        }
        Ok(v as i32 as i64 as u64)
    }
    fn imm64(&mut self) -> Result<u64, DecodeError> {
        let mut v = 0u64;
        for i in 0..8 {
            v |= (self.byte()? as u64) << (8 * i);
        }
        Ok(v)
    }
    /// Iz: 16-bit immediate for 16-bit operand size, otherwise 32-bit sign extended.
    fn imm_z(&mut self, size: u8) -> Result<u64, DecodeError> {
        if size == 2 {
            Ok(self.imm16()? as i16 as i64 as u64)
        } else {
            self.imm32()
        }
    }
    fn rel_target(&self, rel: u64) -> Operand {
        // Branch displacements are the last bytes of the instruction.
        Operand::Imm(self.ip.wrapping_add(self.p as u64).wrapping_add(rel))
    }

    /// Default operand size: 32 bits, REX.W -> 64, 0x66 -> 16.
    fn osz(&self) -> u8 {
        if self.rex & REX_W != 0 {
            8
        } else if self.opsize {
            2
        } else {
            4
        }
    }
    /// Operand size of instructions that default to 64 bits (push/pop/branches).
    fn osz64(&self) -> u8 {
        if self.opsize && self.rex & REX_W == 0 {
            2
        } else {
            8
        }
    }

    fn gpr(&self, idx: u8, size: u8) -> Operand {
        if size == 1 && self.rex == 0 && (4..8).contains(&idx) {
            Operand::Reg(Reg::High8(idx - 4))
        } else {
            Operand::Reg(Reg::Gpr { idx, size })
        }
    }
    fn acc(&self, size: u8) -> Operand {
        Operand::Reg(Reg::Gpr { idx: 0, size })
    }
    /// Register encoded in the low 3 bits of the opcode byte (+REX.B).
    fn opreg(&self, opc: u8, size: u8) -> Operand {
        self.gpr((opc & 7) | if self.rex & REX_B != 0 { 8 } else { 0 }, size)
    }

    fn modrm(&mut self) -> Result<ModRm, DecodeError> {
        let m = self.byte()?;
        let md = m >> 6;
        let reg = ((m >> 3) & 7) | if self.rex & REX_R != 0 { 8 } else { 0 };
        let rmraw = m & 7;
        let b_ext = if self.rex & REX_B != 0 { 8 } else { 0 };
        let mut mem = Mem { base: NO_REG, index: NO_REG, scale: 0, seg: self.seg, addr32: self.addrsize, size: 0, disp: 0 };
        if md == 3 {
            return Ok(ModRm { md, reg, rm: rmraw | b_ext, mem });
        }
        if rmraw == 4 {
            let sib = self.byte()?;
            let idx = ((sib >> 3) & 7) | if self.rex & REX_X != 0 { 8 } else { 0 };
            if idx != 4 {
                mem.index = idx;
                mem.scale = sib >> 6;
            }
            let base = sib & 7;
            if base == 5 && md == 0 {
                mem.disp = self.imm32()? as i64;
            } else {
                mem.base = base | b_ext;
            }
        } else if rmraw == 5 && md == 0 {
            mem.disp = self.imm32()? as i64;
            self.riprel = true;
        } else {
            mem.base = rmraw | b_ext;
        }
        match md {
            1 => mem.disp = mem.disp.wrapping_add(self.imm8()? as i64),
            2 => mem.disp = mem.disp.wrapping_add(self.imm32()? as i64),
            _ => {}
        }
        Ok(ModRm { md, reg, rm: rmraw | b_ext, mem })
    }

    /// r/m operand as a general purpose register or memory.
    fn e(&self, mr: &ModRm, size: u8) -> Operand {
        if mr.md == 3 {
            self.gpr(mr.rm, size)
        } else {
            Operand::Mem(Mem { size, ..mr.mem })
        }
    }
    /// r/m operand as an XMM register or memory.
    fn ex(&self, mr: &ModRm, size: u8) -> Operand {
        if mr.md == 3 {
            Operand::Reg(Reg::Xmm(mr.rm))
        } else {
            Operand::Mem(Mem { size, ..mr.mem })
        }
    }
    /// Memory-only r/m operand.
    fn m(&self, mr: &ModRm, size: u8) -> Result<Operand, DecodeError> {
        if mr.md == 3 {
            Err(DecodeError::Invalid)
        } else {
            Ok(Operand::Mem(Mem { size, ..mr.mem }))
        }
    }
    fn g(&self, mr: &ModRm, size: u8) -> Operand {
        self.gpr(mr.reg, size)
    }
    fn gx(&self, mr: &ModRm) -> Operand {
        Operand::Reg(Reg::Xmm(mr.reg))
    }

    fn decode(&mut self) -> Result<Out, DecodeError> {
        let opc = loop {
            let b = self.byte()?;
            match b {
                0x66 => self.opsize = true,
                0x67 => self.addrsize = true,
                0xf0 => self.lock = true,
                0xf2 | 0xf3 => self.rep = b,
                0x26 | 0x2e | 0x36 | 0x3e => {} // ES/CS/SS/DS overrides are no-ops in 64-bit mode
                0x64 => self.seg = Seg::Fs,
                0x65 => self.seg = Seg::Gs,
                0x40..=0x4f => {
                    self.rex = b;
                    continue;
                }
                _ => break b,
            }
            // A legacy prefix after REX makes the REX prefix void.
            self.rex = 0;
        };
        if opc == 0x0f {
            let b = self.byte()?;
            return self.two_byte(b);
        }
        self.one_byte(opc)
    }

    fn one_byte(&mut self, b: u8) -> Result<Out, DecodeError> {
        let s = self.osz();
        Ok(match b {
            0x00..=0x3f if b & 7 < 6 => {
                let op = ALU[(b >> 3) as usize];
                match b & 7 {
                    0 => {
                        let mr = self.modrm()?;
                        out(op, 1, [self.e(&mr, 1), self.g(&mr, 1), N])
                    }
                    1 => {
                        let mr = self.modrm()?;
                        out(op, s, [self.e(&mr, s), self.g(&mr, s), N])
                    }
                    2 => {
                        let mr = self.modrm()?;
                        out(op, 1, [self.g(&mr, 1), self.e(&mr, 1), N])
                    }
                    3 => {
                        let mr = self.modrm()?;
                        out(op, s, [self.g(&mr, s), self.e(&mr, s), N])
                    }
                    4 => out(op, 1, [self.acc(1), Operand::Imm(self.imm8()?), N]),
                    _ => out(op, s, [self.acc(s), Operand::Imm(self.imm_z(s)?), N]),
                }
            }
            0x50..=0x57 => {
                let sz = self.osz64();
                out(Op::Push, sz, [self.opreg(b, sz), N, N])
            }
            0x58..=0x5f => {
                let sz = self.osz64();
                out(Op::Pop, sz, [self.opreg(b, sz), N, N])
            }
            0x63 => {
                let mr = self.modrm()?;
                if s == 8 {
                    out(Op::Movsx, 8, [self.g(&mr, 8), self.e(&mr, 4), N])
                } else {
                    out(Op::Mov, s, [self.g(&mr, s), self.e(&mr, s), N])
                }
            }
            0x68 => {
                let sz = self.osz64();
                out(Op::Push, sz, [Operand::Imm(self.imm_z(sz)?), N, N])
            }
            0x6a => {
                let sz = self.osz64();
                out(Op::Push, sz, [Operand::Imm(self.imm8()?), N, N])
            }
            0x69 | 0x6b => {
                let mr = self.modrm()?;
                let imm = if b == 0x69 { self.imm_z(s)? } else { self.imm8()? };
                out(Op::Imul, s, [self.g(&mr, s), self.e(&mr, s), Operand::Imm(imm)])
            }
            0x70..=0x7f => {
                let rel = self.imm8()?;
                Out { op: Op::Jcc, osize: 8, cond: b & 0xf, ops: [self.rel_target(rel), N, N] }
            }
            0x80 | 0x81 | 0x83 => {
                let mr = self.modrm()?;
                let op = ALU[(mr.reg & 7) as usize];
                let sz = if b == 0x80 { 1 } else { s };
                let imm = match b {
                    0x81 => self.imm_z(s)?,
                    _ => self.imm8()?,
                };
                out(op, sz, [self.e(&mr, sz), Operand::Imm(imm), N])
            }
            0x84 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 => {
                let sz = if b & 1 == 0 { 1 } else { s };
                let op = match b {
                    0x84 | 0x85 => Op::Test,
                    0x86 | 0x87 => Op::Xchg,
                    _ => Op::Mov,
                };
                let mr = self.modrm()?;
                out(op, sz, [self.e(&mr, sz), self.g(&mr, sz), N])
            }
            0x8a | 0x8b => {
                let sz = if b == 0x8a { 1 } else { s };
                let mr = self.modrm()?;
                out(Op::Mov, sz, [self.g(&mr, sz), self.e(&mr, sz), N])
            }
            0x8c => {
                let mr = self.modrm()?;
                let sz = if mr.md == 3 { s } else { 2 };
                out(Op::Mov, sz, [self.e(&mr, sz), Operand::Reg(Reg::Seg(mr.reg & 7)), N])
            }
            0x8d => {
                let mr = self.modrm()?;
                let m = self.m(&mr, 0)?;
                out(Op::Lea, s, [self.g(&mr, s), m, N])
            }
            0x8f => {
                let mr = self.modrm()?;
                if mr.reg & 7 != 0 {
                    return Err(DecodeError::Unsupported("XOP"));
                }
                let sz = self.osz64();
                out(Op::Pop, sz, [self.e(&mr, sz), N, N])
            }
            0x90 if self.rex & REX_B == 0 => out(Op::Nop, s, [N; 3]), // also PAUSE (F3 90)
            0x90..=0x97 => out(Op::Xchg, s, [self.opreg(b, s), self.acc(s), N]),
            0x98 => out(Op::Cbw, s, [N; 3]),
            0x99 => out(Op::Cwd, s, [N; 3]),
            0x9b => out(Op::Nop, s, [N; 3]), // FWAIT
            0x9c => out(Op::Pushf, self.osz64(), [N; 3]),
            0x9d => out(Op::Popf, self.osz64(), [N; 3]),
            0x9e => out(Op::Sahf, 1, [N; 3]),
            0x9f => out(Op::Lahf, 1, [N; 3]),
            0xa0..=0xa3 => {
                let addr = if self.addrsize { self.imm32()? & 0xffff_ffff } else { self.imm64()? };
                let sz = if b & 1 == 0 { 1 } else { s };
                let mem = Operand::Mem(Mem {
                    base: NO_REG,
                    index: NO_REG,
                    scale: 0,
                    seg: self.seg,
                    addr32: false,
                    size: sz,
                    disp: addr as i64,
                });
                if b < 0xa2 {
                    out(Op::Mov, sz, [self.acc(sz), mem, N])
                } else {
                    out(Op::Mov, sz, [mem, self.acc(sz), N])
                }
            }
            0xa4..=0xa7 | 0xaa..=0xaf => {
                let sz = if b & 1 == 0 { 1 } else { s };
                let op = match b & !1 {
                    0xa4 => Op::Movs,
                    0xa6 => Op::Cmps,
                    0xaa => Op::Stos,
                    0xac => Op::Lods,
                    _ => Op::Scas,
                };
                if self.addrsize {
                    return Err(DecodeError::Unsupported("32-bit address string op"));
                }
                out(op, sz, [N; 3])
            }
            0xa8 => out(Op::Test, 1, [self.acc(1), Operand::Imm(self.imm8()?), N]),
            0xa9 => out(Op::Test, s, [self.acc(s), Operand::Imm(self.imm_z(s)?), N]),
            0xb0..=0xb7 => out(Op::Mov, 1, [self.opreg(b, 1), Operand::Imm(self.imm8()?), N]),
            0xb8..=0xbf => {
                let imm = match s {
                    8 => self.imm64()?,
                    4 => self.imm32()? & 0xffff_ffff,
                    _ => self.imm16()?,
                };
                out(Op::Mov, s, [self.opreg(b, s), Operand::Imm(imm), N])
            }
            0xc0 | 0xc1 | 0xd0..=0xd3 => {
                let mr = self.modrm()?;
                let sz = if b & 1 == 0 { 1 } else { s };
                let op = SHIFT[(mr.reg & 7) as usize];
                let cnt = match b {
                    0xc0 | 0xc1 => Operand::Imm(self.imm8()?),
                    0xd0 | 0xd1 => Operand::Imm(1),
                    _ => Operand::Reg(Reg::Gpr { idx: 1, size: 1 }),
                };
                out(op, sz, [self.e(&mr, sz), cnt, N])
            }
            0xc2 => out(Op::Ret, 8, [Operand::Imm(self.imm16()?), N, N]),
            0xc3 => out(Op::Ret, 8, [Operand::Imm(0), N, N]),
            0xc6 | 0xc7 => {
                let mr = self.modrm()?;
                if mr.reg & 7 != 0 {
                    return Err(DecodeError::Unsupported("RTM"));
                }
                let sz = if b == 0xc6 { 1 } else { s };
                let imm = if sz == 1 { self.imm8()? } else { self.imm_z(sz)? };
                out(Op::Mov, sz, [self.e(&mr, sz), Operand::Imm(imm), N])
            }
            0xc9 => out(Op::Leave, self.osz64(), [N; 3]),
            0xcc => out(Op::Int3, 8, [N; 3]),
            0xcd => return Err(DecodeError::Unsupported("INT n")),
            0xd8..=0xdf => return Err(DecodeError::Unsupported("x87")),
            0xc4 | 0xc5 => return Err(DecodeError::Unsupported("VEX (AVX)")),
            0x62 => return Err(DecodeError::Unsupported("EVEX (AVX-512)")),
            0xe0..=0xe3 => {
                let rel = self.imm8()?;
                let op = [Op::Loopne, Op::Loope, Op::Loop, Op::Jrcxz][(b & 3) as usize];
                if self.addrsize {
                    return Err(DecodeError::Unsupported("32-bit address loop"));
                }
                out(op, 8, [self.rel_target(rel), N, N])
            }
            0xe8 => {
                let rel = self.imm32()?;
                out(Op::Call, 8, [self.rel_target(rel), N, N])
            }
            0xe9 => {
                let rel = self.imm32()?;
                out(Op::Jmp, 8, [self.rel_target(rel), N, N])
            }
            0xeb => {
                let rel = self.imm8()?;
                out(Op::Jmp, 8, [self.rel_target(rel), N, N])
            }
            0xf4 => out(Op::Hlt, 8, [N; 3]),
            0xf5 => out(Op::Cmc, 8, [N; 3]),
            0xf6 | 0xf7 => {
                let mr = self.modrm()?;
                let sz = if b == 0xf6 { 1 } else { s };
                let e = self.e(&mr, sz);
                match mr.reg & 7 {
                    0 | 1 => {
                        let imm = if sz == 1 { self.imm8()? } else { self.imm_z(sz)? };
                        out(Op::Test, sz, [e, Operand::Imm(imm), N])
                    }
                    r => out([Op::Not, Op::Neg, Op::Mul, Op::Imul1, Op::Div, Op::Idiv][r as usize - 2], sz, [e, N, N]),
                }
            }
            0xf8 => out(Op::Clc, 8, [N; 3]),
            0xf9 => out(Op::Stc, 8, [N; 3]),
            0xfc => out(Op::Cld, 8, [N; 3]),
            0xfd => out(Op::Std, 8, [N; 3]),
            0xfe => {
                let mr = self.modrm()?;
                match mr.reg & 7 {
                    0 => out(Op::Inc, 1, [self.e(&mr, 1), N, N]),
                    1 => out(Op::Dec, 1, [self.e(&mr, 1), N, N]),
                    _ => return Err(DecodeError::Invalid),
                }
            }
            0xff => {
                let mr = self.modrm()?;
                match mr.reg & 7 {
                    0 => out(Op::Inc, s, [self.e(&mr, s), N, N]),
                    1 => out(Op::Dec, s, [self.e(&mr, s), N, N]),
                    2 => out(Op::Call, 8, [self.e(&mr, 8), N, N]),
                    4 => out(Op::Jmp, 8, [self.e(&mr, 8), N, N]),
                    6 => {
                        let sz = self.osz64();
                        out(Op::Push, sz, [self.e(&mr, sz), N, N])
                    }
                    3 | 5 => return Err(DecodeError::Unsupported("far call/jmp")),
                    _ => return Err(DecodeError::Invalid),
                }
            }
            0xc8 => return Err(DecodeError::Unsupported("ENTER")),
            0xca | 0xcb | 0xcf => return Err(DecodeError::Unsupported("far return")),
            0xd7 => return Err(DecodeError::Unsupported("XLAT")),
            // Everything else is invalid in 64-bit mode or privileged (IN/OUT/CLI/STI...).
            _ => return Err(DecodeError::Invalid),
        })
    }

    fn pfx(&self) -> Pfx {
        match self.rep {
            0xf3 => Pfx::F3,
            0xf2 => Pfx::F2,
            _ if self.opsize => Pfx::P66,
            _ => Pfx::Np,
        }
    }

    fn two_byte(&mut self, b: u8) -> Result<Out, DecodeError> {
        let s = self.osz();
        Ok(match b {
            0x01 => {
                let m = self.byte()?;
                match m {
                    0xd0 => out(Op::Xgetbv, 4, [N; 3]),
                    _ => return Err(DecodeError::Unsupported("0F 01 group")),
                }
            }
            0x05 => out(Op::Syscall, 8, [N; 3]),
            0x0b => out(Op::Ud2, 8, [N; 3]),
            0x0d | 0x18..=0x1f => {
                // PREFETCHW / PREFETCHh / hint NOPs (incl. ENDBR64 = F3 0F 1E FA).
                let mr = self.modrm()?;
                out(Op::Nop, s, [self.e(&mr, s), N, N])
            }
            0x31 => out(Op::Rdtsc, 4, [N; 3]),
            0x40..=0x4f => {
                let mr = self.modrm()?;
                Out { op: Op::Cmovcc, osize: s, cond: b & 0xf, ops: [self.g(&mr, s), self.e(&mr, s), N] }
            }
            0x80..=0x8f => {
                let rel = self.imm32()?;
                Out { op: Op::Jcc, osize: 8, cond: b & 0xf, ops: [self.rel_target(rel), N, N] }
            }
            0x90..=0x9f => {
                let mr = self.modrm()?;
                Out { op: Op::Setcc, osize: 1, cond: b & 0xf, ops: [self.e(&mr, 1), N, N] }
            }
            0xa2 => out(Op::Cpuid, 4, [N; 3]),
            0xa3 | 0xab | 0xb3 | 0xbb => {
                let mr = self.modrm()?;
                let op = [Op::Bt, Op::Bts, Op::Btr, Op::Btc][((b >> 3) & 3) as usize];
                out(op, s, [self.e(&mr, s), self.g(&mr, s), N])
            }
            0xba => {
                let mr = self.modrm()?;
                let op = match mr.reg & 7 {
                    4 => Op::Bt,
                    5 => Op::Bts,
                    6 => Op::Btr,
                    7 => Op::Btc,
                    _ => return Err(DecodeError::Invalid),
                };
                let e = self.e(&mr, s);
                out(op, s, [e, Operand::Imm(self.byte()? as u64), N])
            }
            0xa4 | 0xa5 | 0xac | 0xad => {
                let mr = self.modrm()?;
                let op = if b < 0xa8 { Op::Shld } else { Op::Shrd };
                let e = self.e(&mr, s);
                let g = self.g(&mr, s);
                let cnt = if b & 1 == 0 { Operand::Imm(self.byte()? as u64) } else { Operand::Reg(Reg::Gpr { idx: 1, size: 1 }) };
                out(op, s, [e, g, cnt])
            }
            0xae => {
                let mr = self.modrm()?;
                if mr.md == 3 {
                    match mr.reg & 7 {
                        5..=7 => out(Op::Fence, 8, [N; 3]),
                        _ => return Err(DecodeError::Unsupported("0F AE reg group")),
                    }
                } else {
                    match mr.reg & 7 {
                        0 => out(Op::Fxsave, 8, [self.m(&mr, 0)?, N, N]),
                        1 => out(Op::Fxrstor, 8, [self.m(&mr, 0)?, N, N]),
                        2 => out(Op::Ldmxcsr, 4, [self.m(&mr, 4)?, N, N]),
                        3 => out(Op::Stmxcsr, 4, [self.m(&mr, 4)?, N, N]),
                        7 => out(Op::Nop, 8, [N; 3]), // CLFLUSH
                        _ => return Err(DecodeError::Unsupported("XSAVE family")),
                    }
                }
            }
            0xaf => {
                let mr = self.modrm()?;
                out(Op::Imul, s, [self.g(&mr, s), self.e(&mr, s), N])
            }
            0xb0 | 0xb1 | 0xc0 | 0xc1 => {
                let mr = self.modrm()?;
                let sz = if b & 1 == 0 { 1 } else { s };
                let op = if b < 0xc0 { Op::Cmpxchg } else { Op::Xadd };
                out(op, sz, [self.e(&mr, sz), self.g(&mr, sz), N])
            }
            0xb6 | 0xb7 | 0xbe | 0xbf => {
                let mr = self.modrm()?;
                let src = if b & 1 == 0 { 1 } else { 2 };
                let op = if b < 0xb8 { Op::Movzx } else { Op::Movsx };
                out(op, s, [self.g(&mr, s), self.e(&mr, src), N])
            }
            0xb8 if self.rep == 0xf3 => {
                let mr = self.modrm()?;
                out(Op::Popcnt, s, [self.g(&mr, s), self.e(&mr, s), N])
            }
            0xbc | 0xbd => {
                let mr = self.modrm()?;
                let op = match (b, self.rep == 0xf3) {
                    (0xbc, false) => Op::Bsf,
                    (0xbc, true) => Op::Tzcnt,
                    (_, false) => Op::Bsr,
                    (_, true) => Op::Lzcnt,
                };
                out(op, s, [self.g(&mr, s), self.e(&mr, s), N])
            }
            0xc7 => {
                let mr = self.modrm()?;
                match (mr.reg & 7, mr.md) {
                    (1, md) if md != 3 => {
                        let sz = if self.rex & REX_W != 0 { 16 } else { 8 };
                        out(Op::CmpxchgDouble, sz / 2, [self.m(&mr, sz)?, N, N])
                    }
                    _ => return Err(DecodeError::Unsupported("0F C7 group")),
                }
            }
            0xc8..=0xcf => out(Op::Bswap, s, [self.opreg(b, s), N, N]),
            0x38 | 0x3a => return Err(DecodeError::Unsupported("SSSE3/SSE4 (0F 38 / 0F 3A)")),
            0x10..=0x17 | 0x28..=0x2f | 0x50..=0x7f | 0xc2 | 0xc6 | 0xd0..=0xff => return self.sse(b),
            _ => return Err(DecodeError::Unsupported("two-byte opcode")),
        })
    }

    fn sse(&mut self, b: u8) -> Result<Out, DecodeError> {
        use Sse::*;
        let pfx = self.pfx();
        let mr = self.modrm()?;
        let gx = self.gx(&mr);
        let fty = match pfx {
            Pfx::Np => FTy::Ps,
            Pfx::P66 => FTy::Pd,
            Pfx::F3 => FTy::Ss,
            Pfx::F2 => FTy::Sd,
        };
        let fsize = match fty {
            FTy::Ss => 4,
            FTy::Sd => 8,
            _ => 16,
        };
        let w = if self.rex & REX_W != 0 { 8 } else { 4 };
        let sse = |op: Sse, osize: u8, ops: [Operand; 3]| out(Op::Sse(op), osize, ops);
        // Packed-integer opcodes require the 66 prefix (no prefix = MMX, unsupported).
        let int66 = |o: Sse| -> Result<Out, DecodeError> {
            if pfx != Pfx::P66 {
                return Err(DecodeError::Unsupported("MMX"));
            }
            Ok(sse(o, 16, [gx, self.ex(&mr, 16), N]))
        };
        Ok(match b {
            0x10 | 0x11 => {
                let (op, sz) = match pfx {
                    Pfx::F3 => (MovScalar(4), 4),
                    Pfx::F2 => (MovScalar(8), 8),
                    _ => (Mov128, 16),
                };
                let e = self.ex(&mr, sz);
                if b == 0x10 {
                    sse(op, sz, [gx, e, N])
                } else {
                    sse(op, sz, [e, gx, N])
                }
            }
            0x12 | 0x16 if matches!(pfx, Pfx::Np | Pfx::P66) => {
                let op = match (b, mr.md == 3) {
                    (0x12, true) if pfx == Pfx::Np => Movhlps,
                    (0x16, true) if pfx == Pfx::Np => Movlhps,
                    (_, true) => return Err(DecodeError::Invalid),
                    (0x12, false) => MovLow64,
                    _ => MovHigh64,
                };
                sse(op, 8, [gx, self.ex(&mr, 8), N])
            }
            0x13 | 0x17 if matches!(pfx, Pfx::Np | Pfx::P66) => {
                let op = if b == 0x13 { MovLow64 } else { MovHigh64 };
                sse(op, 8, [self.m(&mr, 8)?, gx, N])
            }
            0x14 | 0x15 if matches!(pfx, Pfx::Np | Pfx::P66) => {
                let lane = if pfx == Pfx::Np { 4 } else { 8 };
                let op = if b == 0x14 { Punpckl(lane) } else { Punpckh(lane) };
                sse(op, 16, [gx, self.ex(&mr, 16), N])
            }
            0x28 | 0x29 | 0x2b if matches!(pfx, Pfx::Np | Pfx::P66) => {
                if b == 0x28 {
                    sse(Mov128, 16, [gx, self.ex(&mr, 16), N])
                } else {
                    sse(Mov128, 16, [self.ex(&mr, 16), gx, N])
                }
            }
            0x2a if matches!(pfx, Pfx::F3 | Pfx::F2) => sse(CvtSi2F(pfx == Pfx::F2), w, [gx, self.e(&mr, w), N]),
            0x2c | 0x2d if matches!(pfx, Pfx::F3 | Pfx::F2) => {
                let dbl = pfx == Pfx::F2;
                sse(CvtF2Si(dbl, b == 0x2c), w, [self.g(&mr, w), self.ex(&mr, if dbl { 8 } else { 4 }), N])
            }
            0x2e | 0x2f if matches!(pfx, Pfx::Np | Pfx::P66) => {
                let dbl = pfx == Pfx::P66;
                sse(Ucomi(dbl), 8, [gx, self.ex(&mr, if dbl { 8 } else { 4 }), N])
            }
            0x50 if matches!(pfx, Pfx::Np | Pfx::P66) && mr.md == 3 => {
                let op = if pfx == Pfx::Np { Movmskps } else { Movmskpd };
                sse(op, 4, [self.g(&mr, 4), self.ex(&mr, 16), N])
            }
            0x51 | 0x58 | 0x59 | 0x5c..=0x5f => {
                let fop = match b {
                    0x51 => FOp::Sqrt,
                    0x58 => FOp::Add,
                    0x59 => FOp::Mul,
                    0x5c => FOp::Sub,
                    0x5d => FOp::Min,
                    0x5e => FOp::Div,
                    _ => FOp::Max,
                };
                sse(Arith(fop, fty), fsize, [gx, self.ex(&mr, fsize), N])
            }
            0x54..=0x57 if matches!(pfx, Pfx::Np | Pfx::P66) => {
                let op = [And, Andn, Or, Xor][(b - 0x54) as usize];
                sse(op, 16, [gx, self.ex(&mr, 16), N])
            }
            0x5a if pfx == Pfx::F3 => sse(Cvtss2sd, 4, [gx, self.ex(&mr, 4), N]),
            0x5a if pfx == Pfx::F2 => sse(Cvtsd2ss, 8, [gx, self.ex(&mr, 8), N]),
            0x60 => int66(Punpckl(1))?,
            0x61 => int66(Punpckl(2))?,
            0x62 => int66(Punpckl(4))?,
            0x63 => int66(Packsswb)?,
            0x64 => int66(Pcmpgt(1))?,
            0x65 => int66(Pcmpgt(2))?,
            0x66 => int66(Pcmpgt(4))?,
            0x67 => int66(Packuswb)?,
            0x68 => int66(Punpckh(1))?,
            0x69 => int66(Punpckh(2))?,
            0x6a => int66(Punpckh(4))?,
            0x6b => int66(Packssdw)?,
            0x6c => int66(Punpckl(8))?,
            0x6d => int66(Punpckh(8))?,
            0x6e if pfx == Pfx::P66 => sse(MovToXmm, w, [gx, self.e(&mr, w), N]),
            0x6f if matches!(pfx, Pfx::P66 | Pfx::F3) => sse(Mov128, 16, [gx, self.ex(&mr, 16), N]),
            0x7f if matches!(pfx, Pfx::P66 | Pfx::F3) => sse(Mov128, 16, [self.ex(&mr, 16), gx, N]),
            0x70 if pfx != Pfx::Np => {
                let op = match pfx {
                    Pfx::P66 => Pshufd,
                    Pfx::F2 => Pshuflw,
                    _ => Pshufhw,
                };
                let e = self.ex(&mr, 16);
                sse(op, 16, [gx, e, Operand::Imm(self.byte()? as u64)])
            }
            0x71..=0x73 if pfx == Pfx::P66 && mr.md == 3 => {
                let (lane, kind) = match (b, mr.reg & 7) {
                    (0x71, 2) => (2, 0),
                    (0x71, 4) => (2, 1),
                    (0x71, 6) => (2, 2),
                    (0x72, 2) => (4, 0),
                    (0x72, 4) => (4, 1),
                    (0x72, 6) => (4, 2),
                    (0x73, 2) => (8, 0),
                    (0x73, 3) => (16, 3),
                    (0x73, 6) => (8, 2),
                    (0x73, 7) => (16, 4),
                    _ => return Err(DecodeError::Invalid),
                };
                let e = self.ex(&mr, 16);
                sse(PshiftImm(lane, kind), 16, [e, Operand::Imm(self.byte()? as u64), N])
            }
            0x74 => int66(Pcmpeq(1))?,
            0x75 => int66(Pcmpeq(2))?,
            0x76 => int66(Pcmpeq(4))?,
            0x7e if pfx == Pfx::P66 => sse(MovFromXmm, w, [self.e(&mr, w), gx, N]),
            0x7e if pfx == Pfx::F3 => sse(MovqXmm, 8, [gx, self.ex(&mr, 8), N]),
            0xc2 => {
                let e = self.ex(&mr, fsize);
                sse(Cmp(fty), fsize, [gx, e, Operand::Imm(self.byte()? as u64)])
            }
            0xc6 if matches!(pfx, Pfx::Np | Pfx::P66) => {
                let op = if pfx == Pfx::Np { Shufps } else { Shufpd };
                let e = self.ex(&mr, 16);
                sse(op, 16, [gx, e, Operand::Imm(self.byte()? as u64)])
            }
            0xd4 => int66(Padd(8))?,
            0xd6 if pfx == Pfx::P66 => sse(MovqXmm, 8, [self.ex(&mr, 8), gx, N]),
            0xd7 if pfx == Pfx::P66 && mr.md == 3 => sse(Pmovmskb, 4, [self.g(&mr, 4), self.ex(&mr, 16), N]),
            0xda => int66(Pminub)?,
            0xdb => int66(And)?,
            0xde => int66(Pmaxub)?,
            0xdf => int66(Andn)?,
            0xe7 if pfx == Pfx::P66 => sse(Mov128, 16, [self.m(&mr, 16)?, gx, N]),
            0xeb => int66(Or)?,
            0xef => int66(Xor)?,
            0xf4 => int66(Pmuludq)?,
            0xf8 => int66(Psub(1))?,
            0xf9 => int66(Psub(2))?,
            0xfa => int66(Psub(4))?,
            0xfb => int66(Psub(8))?,
            0xfc => int66(Padd(1))?,
            0xfd => int66(Padd(2))?,
            0xfe => int66(Padd(4))?,
            _ => return Err(DecodeError::Unsupported("SSE opcode")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(bytes: &[u8]) -> Insn {
        decode(bytes, 0x1000).unwrap()
    }

    fn gpr(idx: u8, size: u8) -> Operand {
        Operand::Reg(Reg::Gpr { idx, size })
    }

    #[test]
    fn alu_forms() {
        let i = d(&[0x48, 0x01, 0xd8]); // add rax, rbx
        assert_eq!((i.op, i.osize, i.len), (Op::Add, 8, 3));
        assert_eq!(i.ops[0], gpr(0, 8));
        assert_eq!(i.ops[1], gpr(3, 8));
        let i = d(&[0x83, 0xe8, 0xff]); // sub eax, -1
        assert_eq!((i.op, i.osize), (Op::Sub, 4));
        assert_eq!(i.ops[1], Operand::Imm(u64::MAX));
        let i = d(&[0x66, 0x05, 0x34, 0x12]); // add ax, 0x1234
        assert_eq!((i.op, i.osize, i.len), (Op::Add, 2, 4));
        assert_eq!(i.ops[1], Operand::Imm(0x1234));
    }

    #[test]
    fn high_byte_registers_vs_rex() {
        let i = d(&[0x00, 0xfc]); // add ah, bh
        assert_eq!(i.ops[0], Operand::Reg(Reg::High8(0)));
        assert_eq!(i.ops[1], Operand::Reg(Reg::High8(3)));
        let i = d(&[0x40, 0x00, 0xfc]); // add spl, dil
        assert_eq!(i.ops[0], gpr(4, 1));
        assert_eq!(i.ops[1], gpr(7, 1));
    }

    #[test]
    fn sib_and_disp() {
        // lea rax, [rsi + rbx*4 + 0x10]
        let i = d(&[0x48, 0x8d, 0x44, 0x9e, 0x10]);
        let Operand::Mem(m) = i.ops[1] else { panic!() };
        assert_eq!((m.base, m.index, m.scale, m.disp), (6, 3, 2, 0x10));
        // mov r8, [r12 + r13*8 - 8]  : 4f 8b 44 ec f8
        let i = d(&[0x4f, 0x8b, 0x44, 0xec, 0xf8]);
        assert_eq!(i.ops[0], gpr(8, 8));
        let Operand::Mem(m) = i.ops[1] else { panic!() };
        assert_eq!((m.base, m.index, m.scale, m.disp), (12, 13, 3, -8));
        // mov eax, [rsp] uses SIB with no index
        let i = d(&[0x8b, 0x04, 0x24]);
        let Operand::Mem(m) = i.ops[1] else { panic!() };
        assert_eq!((m.base, m.index), (4, NO_REG));
        // [disp32] without base: mov eax, [0x1234] via SIB base=5 mod=0
        let i = d(&[0x8b, 0x04, 0x25, 0x34, 0x12, 0, 0]);
        let Operand::Mem(m) = i.ops[1] else { panic!() };
        assert_eq!((m.base, m.index, m.disp), (NO_REG, NO_REG, 0x1234));
        // r13 as base with mod=0 needs disp8: mov eax, [r13+0]
        let i = d(&[0x41, 0x8b, 0x45, 0x00]);
        let Operand::Mem(m) = i.ops[1] else { panic!() };
        assert_eq!((m.base, m.disp), (13, 0));
    }

    #[test]
    fn rip_relative_uses_next_ip() {
        // mov rax, [rip + 0x10] ; at 0x1000, len 7 -> 0x1017
        let i = d(&[0x48, 0x8b, 0x05, 0x10, 0, 0, 0]);
        let Operand::Mem(m) = i.ops[1] else { panic!() };
        assert_eq!((m.base, m.disp), (NO_REG, 0x1017));
        // cmp byte [rip+1], 5 : immediate follows the displacement -> next ip includes it
        let i = d(&[0x80, 0x3d, 0x01, 0, 0, 0, 0x05]);
        let Operand::Mem(m) = i.ops[0] else { panic!() };
        assert_eq!(m.disp, 0x1000 + 7 + 1);
    }

    #[test]
    fn branches() {
        let i = d(&[0xeb, 0xfe]); // jmp $
        assert_eq!(i.ops[0], Operand::Imm(0x1000));
        let i = d(&[0x0f, 0x84, 0x10, 0, 0, 0]); // je +0x10
        assert_eq!((i.op, i.cond), (Op::Jcc, 4));
        assert_eq!(i.ops[0], Operand::Imm(0x1016));
        let i = d(&[0xe8, 0xfb, 0xff, 0xff, 0xff]); // call $
        assert_eq!(i.ops[0], Operand::Imm(0x1000));
        let i = d(&[0xff, 0xd0]); // call rax
        assert_eq!((i.op, i.ops[0]), (Op::Call, gpr(0, 8)));
    }

    #[test]
    fn prefixes() {
        let i = d(&[0xf3, 0x48, 0xab]); // rep stosq
        assert_eq!((i.op, i.osize, i.rep), (Op::Stos, 8, Rep::Rep));
        let i = d(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0]); // mov rax, fs:[0x28]
        let Operand::Mem(m) = i.ops[1] else { panic!() };
        assert_eq!((m.seg, m.disp), (Seg::Fs, 0x28));
        // REX followed by a legacy prefix is ignored: 48 66 01 d8 = add ax, bx
        let i = d(&[0x48, 0x66, 0x01, 0xd8]);
        assert_eq!(i.osize, 2);
        let i = d(&[0xf0, 0x0f, 0xb1, 0x0a]); // lock cmpxchg [rdx], ecx
        assert!(i.lock);
        assert_eq!(i.op, Op::Cmpxchg);
        let i = d(&[0xf3, 0x0f, 0x1e, 0xfa]); // endbr64
        assert_eq!(i.op, Op::Nop);
    }

    #[test]
    fn movabs_and_mov_imm() {
        let i = d(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(i.ops[1], Operand::Imm(0x0807060504030201));
        assert_eq!(i.len, 10);
        let i = d(&[0xb8, 0xff, 0xff, 0xff, 0xff]); // mov eax, 0xffffffff (zero extended)
        assert_eq!(i.ops[1], Operand::Imm(0xffff_ffff));
        let i = d(&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff]); // mov rax, -1
        assert_eq!(i.ops[1], Operand::Imm(u64::MAX));
    }

    #[test]
    fn sse_forms() {
        let i = d(&[0x66, 0x0f, 0xef, 0xc0]); // pxor xmm0, xmm0
        assert_eq!(i.op, Op::Sse(Sse::Xor));
        let i = d(&[0xf3, 0x0f, 0x6f, 0x4e, 0x10]); // movdqu xmm1, [rsi+16]
        assert_eq!(i.op, Op::Sse(Sse::Mov128));
        assert_eq!(i.ops[0], Operand::Reg(Reg::Xmm(1)));
        let i = d(&[0x66, 0x44, 0x0f, 0x7e, 0xc0]); // movd eax, xmm8
        assert_eq!(i.op, Op::Sse(Sse::MovFromXmm));
        assert_eq!(i.ops[1], Operand::Reg(Reg::Xmm(8)));
        let i = d(&[0xf2, 0x48, 0x0f, 0x2a, 0xc7]); // cvtsi2sd xmm0, rdi
        assert_eq!((i.op, i.osize), (Op::Sse(Sse::CvtSi2F(true)), 8));
        assert_eq!(decode(&[0x0f, 0xef, 0xc0], 0), Err(DecodeError::Unsupported("MMX")));
    }

    #[test]
    fn errors() {
        assert_eq!(decode(&[0x48], 0), Err(DecodeError::Truncated));
        assert_eq!(decode(&[0x06], 0), Err(DecodeError::Invalid)); // push es: invalid in 64-bit
        assert_eq!(decode(&[0x66; 16], 0), Err(DecodeError::Invalid)); // > 15 bytes
        assert_eq!(decode(&[0xd9, 0xc0], 0), Err(DecodeError::Unsupported("x87")));
    }
}
