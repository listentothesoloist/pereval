//! SSE/SSE2 subset used by compiler-generated x86-64 baseline code.

use guest_mem::GuestMemory;

use crate::flags;
use crate::insn::*;
use crate::interp::{op_size, read_sized, write_sized, Trap, R};
use crate::Cpu;

const LO64: u128 = u64::MAX as u128;

#[inline(always)]
fn lanes<T: Copy, const N: usize>(v: u128) -> [T; N] {
    debug_assert_eq!(std::mem::size_of::<[T; N]>(), 16);
    unsafe { std::mem::transmute_copy(&v) }
}

#[inline(always)]
fn pack<T: Copy, const N: usize>(a: [T; N]) -> u128 {
    debug_assert_eq!(std::mem::size_of::<[T; N]>(), 16);
    unsafe { std::mem::transmute_copy(&a) }
}

fn map2<T: Copy + Default, const N: usize>(a: u128, b: u128, f: impl Fn(T, T) -> T) -> u128 {
    let (x, y): ([T; N], [T; N]) = (lanes(a), lanes(b));
    let mut r = [T::default(); N];
    for k in 0..N {
        r[k] = f(x[k], y[k]);
    }
    pack(r)
}

macro_rules! per_lane {
    ($lane:expr, $a:expr, $b:expr, |$x:ident, $y:ident| $e:expr) => {
        match $lane {
            1 => map2::<u8, 16>($a, $b, |$x, $y| $e),
            2 => map2::<u16, 8>($a, $b, |$x, $y| $e),
            4 => map2::<u32, 4>($a, $b, |$x, $y| $e),
            _ => map2::<u64, 2>($a, $b, |$x, $y| $e),
        }
    };
}

/// Interleave lanes of the low (`high == false`) or high halves of a and b.
fn unpack(lane: u8, a: u128, b: u128, high: bool) -> u128 {
    let (x, y) = (a.to_le_bytes(), b.to_le_bytes());
    let l = lane as usize;
    let base = if high { 8 } else { 0 };
    let mut r = [0u8; 16];
    for k in 0..(8 / l) {
        let src = base + k * l;
        r[2 * k * l..2 * k * l + l].copy_from_slice(&x[src..src + l]);
        r[2 * k * l + l..2 * k * l + 2 * l].copy_from_slice(&y[src..src + l]);
    }
    u128::from_le_bytes(r)
}

fn float_op<T: num::Float>(op: FOp, a: T, b: T) -> T {
    match op {
        FOp::Add => a + b,
        FOp::Sub => a - b,
        FOp::Mul => a * b,
        FOp::Div => a / b,
        // x86 MIN/MAX return the second (source) operand if either is NaN or both are zero.
        FOp::Min => {
            if a < b {
                a
            } else {
                b
            }
        }
        FOp::Max => {
            if a > b {
                a
            } else {
                b
            }
        }
        FOp::Sqrt => b.sqrt(),
    }
}

fn cmp_pred<T: PartialOrd>(p: u8, a: T, b: T) -> bool {
    let unord = a.partial_cmp(&b).is_none();
    match p & 7 {
        0 => a == b,
        1 => a < b,
        2 => a <= b,
        3 => unord,
        4 => a != b,
        5 => !(a < b),
        6 => !(a <= b),
        _ => !unord,
    }
}

mod num {
    pub trait Float: Copy + PartialOrd + std::ops::Add<Output = Self> + std::ops::Sub<Output = Self> + std::ops::Mul<Output = Self> + std::ops::Div<Output = Self> {
        fn sqrt(self) -> Self;
    }
    impl Float for f32 {
        fn sqrt(self) -> f32 {
            f32::sqrt(self)
        }
    }
    impl Float for f64 {
        fn sqrt(self) -> f64 {
            f64::sqrt(self)
        }
    }
}

/// Float -> integer with x86 "integer indefinite" (MIN) on NaN / overflow.
fn f2i(v: f64, size: u8, trunc: bool) -> u64 {
    let v = if trunc { v.trunc() } else { v.round_ties_even() };
    if size == 4 {
        if v.is_nan() || v >= 2147483648.0 || v < -2147483648.0 {
            0x8000_0000
        } else {
            v as i32 as u32 as u64
        }
    } else if v.is_nan() || v >= 9.223372036854775808e18 || v < -9.223372036854775808e18 {
        0x8000_0000_0000_0000
    } else {
        v as i64 as u64
    }
}

impl Cpu {
    fn xget(&self, mem: &GuestMemory, op: &Operand) -> Result<u128, Trap> {
        Ok(match *op {
            Operand::Reg(Reg::Xmm(r)) => self.xmm[r as usize],
            Operand::Mem(ref m) => {
                let a = self.ea(m);
                match m.size {
                    16 => mem.read::<u128>(a)?,
                    s => read_sized(mem, a, s)? as u128,
                }
            }
            _ => self.get(mem, op)? as u128,
        })
    }

    fn xreg(op: &Operand) -> usize {
        match *op {
            Operand::Reg(Reg::Xmm(r)) => r as usize,
            _ => unreachable!("expected xmm operand"),
        }
    }

    /// Store `v` to an XMM register (whole) or memory (operand-sized).
    fn xput(&mut self, mem: &GuestMemory, op: &Operand, v: u128) -> R<()> {
        match *op {
            Operand::Reg(Reg::Xmm(r)) => self.xmm[r as usize] = v,
            Operand::Mem(ref m) => {
                let a = self.ea(m);
                match m.size {
                    16 => mem.write::<u128>(a, v)?,
                    s => write_sized(mem, a, s, v as u64)?,
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    pub(crate) fn sse(&mut self, mem: &GuestMemory, op: Sse, i: &Insn) -> R<()> {
        use Sse::*;
        let (d, sr) = (&i.ops[0], &i.ops[1]);
        match op {
            Mov128 => {
                let v = self.xget(mem, sr)?;
                self.xput(mem, d, v)?;
            }
            MovScalar(sz) => {
                let lm: u128 = if sz == 4 { 0xffff_ffff } else { LO64 };
                match (d, sr) {
                    (Operand::Reg(Reg::Xmm(x)), Operand::Reg(Reg::Xmm(y))) => {
                        let (x, y) = (*x as usize, *y as usize);
                        self.xmm[x] = (self.xmm[x] & !lm) | (self.xmm[y] & lm);
                    }
                    (Operand::Reg(Reg::Xmm(x)), _) => self.xmm[*x as usize] = self.xget(mem, sr)?,
                    _ => {
                        let v = self.xget(mem, sr)?;
                        self.xput(mem, d, v)?;
                    }
                }
            }
            MovLow64 | MovHigh64 => match d {
                Operand::Reg(Reg::Xmm(x)) => {
                    let v = self.xget(mem, sr)? & LO64;
                    let x = *x as usize;
                    self.xmm[x] = if op == MovLow64 { (self.xmm[x] & !LO64) | v } else { (self.xmm[x] & LO64) | v << 64 };
                }
                _ => {
                    let v = self.xmm[Self::xreg(sr)];
                    self.xput(mem, d, if op == MovLow64 { v } else { v >> 64 })?;
                }
            },
            Movhlps => {
                let x = Self::xreg(d);
                self.xmm[x] = (self.xmm[x] & !LO64) | (self.xmm[Self::xreg(sr)] >> 64);
            }
            Movlhps => {
                let x = Self::xreg(d);
                self.xmm[x] = (self.xmm[x] & LO64) | (self.xmm[Self::xreg(sr)] << 64);
            }
            MovToXmm => {
                let v = self.get(mem, sr)?;
                self.xmm[Self::xreg(d)] = v as u128;
            }
            MovFromXmm => {
                let v = self.xmm[Self::xreg(sr)] as u64;
                let l = self.loc(d);
                self.st(mem, l, v & flags::mask(i.osize))?;
            }
            MovqXmm => match d {
                Operand::Reg(Reg::Xmm(x)) => self.xmm[*x as usize] = self.xget(mem, sr)? & LO64,
                _ => {
                    let v = self.xmm[Self::xreg(sr)];
                    self.xput(mem, d, v)?;
                }
            },
            Movmskps | Movmskpd | Pmovmskb => {
                let v = self.xget(mem, sr)?;
                let (lane, n) = match op {
                    Movmskps => (32, 4),
                    Movmskpd => (64, 2),
                    _ => (8, 16),
                };
                let mut r = 0u64;
                for k in 0..n {
                    r |= (((v >> (k * lane + lane - 1)) & 1) as u64) << k;
                }
                let l = self.loc(d);
                self.st(mem, l, r)?;
            }
            Pshufd | Pshuflw | Pshufhw | Shufps | Shufpd | PshiftImm(..) | Cmp(_) => self.sse_imm(mem, op, i)?,
            Arith(fop, ty) => {
                let x = Self::xreg(d);
                let (a, b) = (self.xmm[x], self.xget(mem, sr)?);
                self.xmm[x] = match ty {
                    FTy::Ps => {
                        let (p, q): ([f32; 4], [f32; 4]) = (lanes(a), lanes(b));
                        pack([0, 1, 2, 3].map(|k| float_op(fop, p[k], q[k])))
                    }
                    FTy::Pd => {
                        let (p, q): ([f64; 2], [f64; 2]) = (lanes(a), lanes(b));
                        pack([0, 1].map(|k| float_op(fop, p[k], q[k])))
                    }
                    FTy::Ss => {
                        let r = float_op(fop, f32::from_bits(a as u32), f32::from_bits(b as u32));
                        (a & !0xffff_ffff) | r.to_bits() as u128
                    }
                    FTy::Sd => {
                        let r = float_op(fop, f64::from_bits(a as u64), f64::from_bits(b as u64));
                        (a & !LO64) | r.to_bits() as u128
                    }
                };
            }
            CvtSi2F(dbl) => {
                let v = flags::sext(self.get(mem, sr)?, op_size(sr));
                let x = Self::xreg(d);
                self.xmm[x] = if dbl {
                    (self.xmm[x] & !LO64) | (v as f64).to_bits() as u128
                } else {
                    (self.xmm[x] & !0xffff_ffff) | (v as f32).to_bits() as u128
                };
            }
            CvtF2Si(dbl, trunc) => {
                let v = self.xget(mem, sr)?;
                let f = if dbl { f64::from_bits(v as u64) } else { f32::from_bits(v as u32) as f64 };
                let r = f2i(f, i.osize, trunc);
                let l = self.loc(d);
                self.st(mem, l, r)?;
            }
            Cvtss2sd => {
                let v = f32::from_bits(self.xget(mem, sr)? as u32) as f64;
                let x = Self::xreg(d);
                self.xmm[x] = (self.xmm[x] & !LO64) | v.to_bits() as u128;
            }
            Cvtsd2ss => {
                let v = f64::from_bits(self.xget(mem, sr)? as u64) as f32;
                let x = Self::xreg(d);
                self.xmm[x] = (self.xmm[x] & !0xffff_ffff) | v.to_bits() as u128;
            }
            Ucomi(dbl) => {
                let (a, b) = (self.xmm[Self::xreg(d)], self.xget(mem, sr)?);
                let ord = if dbl {
                    f64::from_bits(a as u64).partial_cmp(&f64::from_bits(b as u64))
                } else {
                    f32::from_bits(a as u32).partial_cmp(&f32::from_bits(b as u32))
                };
                use std::cmp::Ordering::*;
                let f = match ord {
                    None => flags::ZF | flags::PF | flags::CF,
                    Some(Less) => flags::CF,
                    Some(Equal) => flags::ZF,
                    Some(Greater) => 0,
                };
                self.flags.set_explicit(f);
            }
            _ => {
                // Packed integer / bitwise binary ops: xmm = op(xmm, xmm/m128).
                let x = Self::xreg(d);
                let (a, b) = (self.xmm[x], self.xget(mem, sr)?);
                self.xmm[x] = match op {
                    And => a & b,
                    Andn => !a & b,
                    Or => a | b,
                    Xor => a ^ b,
                    Padd(l) => per_lane!(l, a, b, |x, y| x.wrapping_add(y)),
                    Psub(l) => per_lane!(l, a, b, |x, y| x.wrapping_sub(y)),
                    Pcmpeq(l) => per_lane!(l, a, b, |x, y| if x == y { !0 } else { 0 }),
                    Pcmpgt(1) => map2::<i8, 16>(a, b, |x, y| if x > y { -1 } else { 0 }),
                    Pcmpgt(2) => map2::<i16, 8>(a, b, |x, y| if x > y { -1 } else { 0 }),
                    Pcmpgt(_) => map2::<i32, 4>(a, b, |x, y| if x > y { -1 } else { 0 }),
                    Pminub => map2::<u8, 16>(a, b, |x, y| x.min(y)),
                    Pmaxub => map2::<u8, 16>(a, b, |x, y| x.max(y)),
                    Pmuludq => {
                        let (p, q): ([u64; 2], [u64; 2]) = (lanes(a), lanes(b));
                        pack([(p[0] as u32 as u64) * (q[0] as u32 as u64), (p[1] as u32 as u64) * (q[1] as u32 as u64)])
                    }
                    Punpckl(l) => unpack(l, a, b, false),
                    Punpckh(l) => unpack(l, a, b, true),
                    Packsswb | Packuswb => {
                        let (p, q): ([i16; 8], [i16; 8]) = (lanes(a), lanes(b));
                        let mut r = [0u8; 16];
                        for k in 0..16 {
                            let v = if k < 8 { p[k] } else { q[k - 8] };
                            r[k] = if op == Packsswb { v.clamp(-128, 127) as i8 as u8 } else { v.clamp(0, 255) as u8 };
                        }
                        u128::from_le_bytes(r)
                    }
                    Packssdw => {
                        let (p, q): ([i32; 4], [i32; 4]) = (lanes(a), lanes(b));
                        let mut r = [0i16; 8];
                        for k in 0..8 {
                            let v = if k < 4 { p[k] } else { q[k - 4] };
                            r[k] = v.clamp(-32768, 32767) as i16;
                        }
                        pack(r)
                    }
                    _ => return Err(Trap::Exit(crate::Exit::Unimplemented(format!("{op:?}")))),
                };
            }
        }
        Ok(())
    }

    fn sse_imm(&mut self, mem: &GuestMemory, op: Sse, i: &Insn) -> R<()> {
        use Sse::*;
        let x = Self::xreg(&i.ops[0]);
        let a = self.xmm[x];
        let (b, imm) = match op {
            PshiftImm(..) => (a, i.ops[1].imm() as u8),
            _ => (self.xget(mem, &i.ops[1])?, i.ops[2].imm() as u8),
        };
        let sel = |k: usize| ((imm >> (2 * k)) & 3) as usize;
        self.xmm[x] = match op {
            Pshufd => {
                let s: [u32; 4] = lanes(b);
                pack([s[sel(0)], s[sel(1)], s[sel(2)], s[sel(3)]])
            }
            Pshuflw | Pshufhw => {
                let s: [u16; 8] = lanes(b);
                let mut r = s;
                let o = if op == Pshuflw { 0 } else { 4 };
                for k in 0..4 {
                    r[o + k] = s[o + sel(k)];
                }
                pack(r)
            }
            Shufps => {
                let (p, q): ([u32; 4], [u32; 4]) = (lanes(a), lanes(b));
                pack([p[sel(0)], p[sel(1)], q[sel(2)], q[sel(3)]])
            }
            Shufpd => {
                let (p, q): ([u64; 2], [u64; 2]) = (lanes(a), lanes(b));
                pack([p[(imm & 1) as usize], q[((imm >> 1) & 1) as usize]])
            }
            PshiftImm(lane, kind) => {
                let c = imm as u32;
                match (lane, kind) {
                    (16, 3) => if c > 15 { 0 } else { a >> (c * 8) },
                    (16, _) => if c > 15 { 0 } else { a << (c * 8) },
                    (2, 0) => map2::<u16, 8>(a, 0, |v, _| v.checked_shr(c).unwrap_or(0)),
                    (2, 1) => map2::<i16, 8>(a, 0, |v, _| v >> c.min(15)),
                    (2, _) => map2::<u16, 8>(a, 0, |v, _| v.checked_shl(c).unwrap_or(0)),
                    (4, 0) => map2::<u32, 4>(a, 0, |v, _| v.checked_shr(c).unwrap_or(0)),
                    (4, 1) => map2::<i32, 4>(a, 0, |v, _| v >> c.min(31)),
                    (4, _) => map2::<u32, 4>(a, 0, |v, _| v.checked_shl(c).unwrap_or(0)),
                    (_, 0) => map2::<u64, 2>(a, 0, |v, _| v.checked_shr(c).unwrap_or(0)),
                    (_, _) => map2::<u64, 2>(a, 0, |v, _| v.checked_shl(c).unwrap_or(0)),
                }
            }
            Cmp(ty) => {
                let m = |t: bool| if t { !0u64 } else { 0 };
                match ty {
                    FTy::Ps => {
                        let (p, q): ([f32; 4], [f32; 4]) = (lanes(a), lanes(b));
                        pack([0, 1, 2, 3].map(|k| m(cmp_pred(imm, p[k], q[k])) as u32))
                    }
                    FTy::Pd => {
                        let (p, q): ([f64; 2], [f64; 2]) = (lanes(a), lanes(b));
                        pack([0, 1].map(|k| m(cmp_pred(imm, p[k], q[k]))))
                    }
                    FTy::Ss => {
                        let r = m(cmp_pred(imm, f32::from_bits(a as u32), f32::from_bits(b as u32))) as u32;
                        (a & !0xffff_ffff) | r as u128
                    }
                    FTy::Sd => {
                        let r = m(cmp_pred(imm, f64::from_bits(a as u64), f64::from_bits(b as u64)));
                        (a & !LO64) | r as u128
                    }
                }
            }
            _ => unreachable!(),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_bytes() {
        let a = u128::from_le_bytes(core::array::from_fn(|k| k as u8));
        let b = u128::from_le_bytes(core::array::from_fn(|k| 0x10 + k as u8));
        let r = unpack(1, a, b, false).to_le_bytes();
        assert_eq!(&r[..6], &[0, 0x10, 1, 0x11, 2, 0x12]);
        let r = unpack(8, a, b, true).to_le_bytes();
        assert_eq!(r[0], 8);
        assert_eq!(r[8], 0x18);
    }

    #[test]
    fn float_to_int_indefinite() {
        assert_eq!(f2i(f64::NAN, 4, true), 0x8000_0000);
        assert_eq!(f2i(-1.5, 4, true), (-1i32) as u32 as u64);
        assert_eq!(f2i(2.5, 8, false), 2);
        assert_eq!(f2i(1e300, 8, true), 0x8000_0000_0000_0000);
    }
}
