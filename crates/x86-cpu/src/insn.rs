//! Decoded instruction representation shared by the interpreter and (later)
//! the JIT front end.

pub const NO_REG: u8 = 0xff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seg {
    None,
    Fs,
    Gs,
}

/// Memory operand: `seg:[base + index << scale + disp]`.
/// RIP-relative operands are resolved by the decoder into an absolute `disp`
/// with no base, because decoded blocks are cached per guest address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mem {
    pub base: u8,
    pub index: u8,
    pub scale: u8, // shift amount 0..=3
    pub seg: Seg,
    pub addr32: bool,
    /// Access width in bytes (1, 2, 4, 8, 10, 16; 0 when only the address is used).
    pub size: u8,
    pub disp: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reg {
    /// General purpose register `idx` (0..16) accessed with `size` bytes.
    /// For size 1 this is AL..R15B (SPL/BPL/SIL/DIL when a REX prefix is present).
    Gpr { idx: u8, size: u8 },
    /// AH, CH, DH, BH: bits 8..16 of RAX/RCX/RDX/RBX.
    High8(u8),
    Xmm(u8),
    Seg(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    None,
    Reg(Reg),
    Mem(Mem),
    /// Immediate, already sign/zero extended to 64 bits as the encoding requires.
    /// Branch targets are stored as absolute addresses.
    Imm(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rep {
    None,
    Rep,   // F3: REP / REPE
    Repne, // F2
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    // integer ALU
    Add, Or, Adc, Sbb, And, Sub, Xor, Cmp, Test,
    Inc, Dec, Neg, Not,
    Mul, Imul1, Imul, Div, Idiv,
    Rol, Ror, Rcl, Rcr, Shl, Shr, Sar, Shld, Shrd,
    Bt, Bts, Btr, Btc, Bsf, Bsr, Tzcnt, Lzcnt, Popcnt, Bswap,
    // data movement
    Mov, Movzx, Movsx, Lea, Xchg, Cmpxchg, CmpxchgDouble, Xadd,
    Push, Pop, Pushf, Popf, Lahf, Sahf, Leave,
    Cbw, Cwd, Setcc, Cmovcc,
    // string ops (size from osize, REP from prefix)
    Movs, Stos, Lods, Cmps, Scas,
    // control flow
    Jmp, Jcc, Call, Ret, Jrcxz, Loop, Loope, Loopne,
    // flags
    Clc, Stc, Cmc, Cld, Std,
    // system
    Nop, Hlt, Int3, Ud2, Syscall, Cpuid, Rdtsc, Fence, Ldmxcsr, Stmxcsr, Fxsave, Fxrstor, Xgetbv,
    // SSE / SSE2
    Sse(Sse),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FTy {
    Ps,
    Pd,
    Ss,
    Sd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FOp {
    Add,
    Sub,
    Mul,
    Div,
    Min,
    Max,
    Sqrt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sse {
    /// Full 128-bit move (movaps/movups/movdqa/movdqu/movntdq...).
    Mov128,
    /// movss / movsd: register form merges the low lane, load zeroes the rest.
    MovScalar(u8),
    MovLow64,
    MovHigh64,
    Movhlps,
    Movlhps,
    /// movd/movq xmm <- r/m (zero extends into the xmm register).
    MovToXmm,
    /// movd/movq r/m <- xmm.
    MovFromXmm,
    /// movq xmm, xmm/m64 (F3 0F 7E) and movq xmm/m64, xmm (66 0F D6): low 64 bits, upper zeroed.
    MovqXmm,
    And,
    Andn,
    Or,
    Xor,
    Padd(u8),
    Psub(u8),
    Pcmpeq(u8),
    Pcmpgt(u8),
    Pminub,
    Pmaxub,
    Pmuludq,
    Punpckl(u8),
    Punpckh(u8),
    Packsswb,
    Packuswb,
    Packssdw,
    Pshufd,
    Pshuflw,
    Pshufhw,
    Shufps,
    Shufpd,
    /// Immediate shifts: (lane size, kind) kind 0=srl 1=sra 2=sll 3=srl-bytes 4=sll-bytes
    PshiftImm(u8, u8),
    Pmovmskb,
    Movmskps,
    Movmskpd,
    Arith(FOp, FTy),
    Cmp(FTy),
    /// cvtsi2ss/sd (bool = double)
    CvtSi2F(bool),
    /// cvt(t)ss2si / cvt(t)sd2si: (double, truncate)
    CvtF2Si(bool, bool),
    Cvtss2sd,
    Cvtsd2ss,
    /// ucomis*/comis* (bool = double)
    Ucomi(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub op: Op,
    pub len: u8,
    /// Operand size in bytes (1, 2, 4, 8; 16 for packed SSE).
    pub osize: u8,
    /// Condition code for Jcc / SETcc / CMOVcc.
    pub cond: u8,
    pub rep: Rep,
    pub lock: bool,
    pub ops: [Operand; 3],
}

impl Insn {
    pub fn is_block_end(&self) -> bool {
        matches!(
            self.op,
            Op::Jmp
                | Op::Jcc
                | Op::Call
                | Op::Ret
                | Op::Jrcxz
                | Op::Loop
                | Op::Loope
                | Op::Loopne
                | Op::Hlt
                | Op::Int3
                | Op::Ud2
                | Op::Syscall
        )
    }
}
