//! Lazy evaluation of the arithmetic flags (CF PF AF ZF SF OF).
//!
//! Most flag results are never read: an `add` is typically followed by another
//! flag-writing instruction. So instead of computing six flags per ALU
//! instruction we record the operation, its operands and result, and derive a
//! flag only when a `jcc`/`setcc`/`adc`/`pushf`... asks for it.

pub const CF: u64 = 1 << 0;
pub const PF: u64 = 1 << 2;
pub const AF: u64 = 1 << 4;
pub const ZF: u64 = 1 << 6;
pub const SF: u64 = 1 << 7;
pub const DF: u64 = 1 << 10;
pub const OF: u64 = 1 << 11;
pub const ARITH: u64 = CF | PF | AF | ZF | SF | OF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Flags stored literally in `res`.
    Explicit,
    Add,
    Adc,
    Sub,
    Sbb,
    Logic,
    /// INC/DEC/NEG: like add/sub with b = 1 (or a = 0), but INC/DEC keep CF (stored in `c`).
    Inc,
    Dec,
    Neg,
    Shl,
    Shr,
    Sar,
    /// MUL/IMUL: CF = OF = `c`; SF/ZF/PF from the low result.
    Mul,
}

#[derive(Clone, Copy, Debug)]
pub struct Flags {
    pub kind: Kind,
    pub size: u8,
    pub a: u64,
    pub b: u64,
    pub res: u64,
    /// Carry-in for ADC/SBB, preserved CF for INC/DEC, overflow for MUL.
    pub c: u64,
    /// Direction flag (the only non-arithmetic flag user code touches).
    pub df: bool,
}

impl Default for Flags {
    fn default() -> Flags {
        Flags { kind: Kind::Explicit, size: 8, a: 0, b: 0, res: 0, c: 0, df: false }
    }
}

#[inline(always)]
pub fn mask(size: u8) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size as u32 * 8)) - 1
    }
}

#[inline(always)]
pub fn sign_bit(size: u8) -> u64 {
    1u64 << (size as u32 * 8 - 1)
}

#[inline(always)]
pub fn sext(v: u64, size: u8) -> i64 {
    let sh = 64 - size as u32 * 8;
    ((v << sh) as i64) >> sh
}

impl Flags {
    #[inline(always)]
    pub fn set(&mut self, kind: Kind, size: u8, a: u64, b: u64, res: u64) {
        self.kind = kind;
        self.size = size;
        self.a = a;
        self.b = b;
        self.res = res & mask(size);
    }

    #[inline(always)]
    pub fn set_c(&mut self, kind: Kind, size: u8, a: u64, b: u64, res: u64, c: u64) {
        self.set(kind, size, a, b, res);
        self.c = c;
    }

    pub fn set_explicit(&mut self, bits: u64) {
        self.kind = Kind::Explicit;
        self.res = bits & ARITH;
    }

    #[inline]
    pub fn cf(&self) -> bool {
        let m = mask(self.size);
        match self.kind {
            Kind::Explicit => self.res & CF != 0,
            Kind::Add => self.res < (self.a & m),
            Kind::Adc => (self.a & m) as u128 + (self.b & m) as u128 + self.c as u128 > m as u128,
            Kind::Sub => (self.a & m) < (self.b & m),
            Kind::Sbb => ((self.a & m) as u128) < (self.b & m) as u128 + self.c as u128,
            Kind::Logic => false,
            Kind::Inc | Kind::Dec | Kind::Mul => self.c != 0,
            Kind::Neg => self.a & m != 0,
            // For shifts `a` is the original value and `b` the masked count (1..=63);
            // CF is the last bit shifted out.
            Kind::Shl => {
                let bits = self.size as u64 * 8;
                self.b <= bits && ((self.a & m) >> (bits - self.b)) & 1 != 0
            }
            Kind::Shr => ((self.a & m) >> (self.b - 1)) & 1 != 0,
            Kind::Sar => (sext(self.a, self.size) >> (self.b - 1)) & 1 != 0,
        }
    }

    #[inline]
    pub fn zf(&self) -> bool {
        match self.kind {
            Kind::Explicit => self.res & ZF != 0,
            _ => self.res == 0,
        }
    }

    #[inline]
    pub fn sf(&self) -> bool {
        match self.kind {
            Kind::Explicit => self.res & SF != 0,
            _ => self.res & sign_bit(self.size) != 0,
        }
    }

    #[inline]
    pub fn pf(&self) -> bool {
        match self.kind {
            Kind::Explicit => self.res & PF != 0,
            _ => (self.res as u8).count_ones() % 2 == 0,
        }
    }

    #[inline]
    pub fn af(&self) -> bool {
        match self.kind {
            Kind::Explicit => self.res & AF != 0,
            Kind::Add | Kind::Adc | Kind::Sub | Kind::Sbb => (self.a ^ self.b ^ self.res) & 0x10 != 0,
            Kind::Inc | Kind::Dec => (self.a ^ 1 ^ self.res) & 0x10 != 0,
            Kind::Neg => (self.a ^ self.res) & 0x10 != 0,
            _ => false,
        }
    }

    #[inline]
    pub fn of(&self) -> bool {
        let sb = sign_bit(self.size);
        match self.kind {
            Kind::Explicit => self.res & OF != 0,
            Kind::Add | Kind::Adc => (self.a ^ self.res) & (self.b ^ self.res) & sb != 0,
            Kind::Sub | Kind::Sbb => (self.a ^ self.b) & (self.a ^ self.res) & sb != 0,
            Kind::Logic => false,
            Kind::Inc => self.res == sb,
            Kind::Dec => self.res == sb - 1,
            Kind::Neg => self.res == sb,
            Kind::Shl => ((self.res & sb != 0) as u8 ^ self.cf() as u8) != 0,
            Kind::Shr => self.a & sb != 0,
            Kind::Sar => false,
            Kind::Mul => self.c != 0,
        }
    }

    /// All six arithmetic flags as an RFLAGS fragment.
    pub fn arith_bits(&self) -> u64 {
        if self.kind == Kind::Explicit {
            return self.res & ARITH;
        }
        (self.cf() as u64) * CF
            | (self.pf() as u64) * PF
            | (self.af() as u64) * AF
            | (self.zf() as u64) * ZF
            | (self.sf() as u64) * SF
            | (self.of() as u64) * OF
    }

    /// Full RFLAGS value as `pushf` would see it (IF and the reserved bit 1 set).
    pub fn rflags(&self) -> u64 {
        self.arith_bits() | if self.df { DF } else { 0 } | 0x202
    }

    pub fn set_rflags(&mut self, v: u64) {
        self.set_explicit(v);
        self.df = v & DF != 0;
    }

    /// Evaluate condition code `cc` (the low nibble of Jcc/SETcc/CMOVcc).
    #[inline]
    pub fn cond(&self, cc: u8) -> bool {
        // Fast path for the overwhelmingly common `cmp` + `jcc` pair.
        if self.kind == Kind::Sub {
            let m = mask(self.size);
            let (a, b) = (self.a & m, self.b & m);
            let r = match cc >> 1 {
                1 => a < b,                                       // B
                2 => a == b,                                      // E
                3 => a <= b,                                      // BE
                6 => sext(a, self.size) < sext(b, self.size),     // L
                7 => sext(a, self.size) <= sext(b, self.size),    // LE
                _ => return self.cond_slow(cc),
            };
            return r ^ (cc & 1 != 0);
        }
        self.cond_slow(cc)
    }

    fn cond_slow(&self, cc: u8) -> bool {
        let r = match cc >> 1 {
            0 => self.of(),
            1 => self.cf(),
            2 => self.zf(),
            3 => self.cf() || self.zf(),
            4 => self.sf(),
            5 => self.pf(),
            6 => self.sf() != self.of(),
            _ => self.zf() || (self.sf() != self.of()),
        };
        r ^ (cc & 1 != 0)
    }
}
