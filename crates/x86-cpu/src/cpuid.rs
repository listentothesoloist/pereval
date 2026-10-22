//! CPUID: what the guest is told about "its" processor.
//!
//! Must advertise exactly what the engine implements, nothing more: software
//! picks code paths (SSE4, AVX, BMI...) from these bits.

pub const VENDOR: &[u8; 12] = b"GenuineIntel";
pub const BRAND: &[u8; 48] = b"x86-64 on Apple Silicon (emulated)\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// Leaf 1 EDX: FPU TSC CX8 CMOV CLFSH FXSR SSE SSE2.
/// (FPU is part of the x86-64 baseline and software assumes it unconditionally;
/// the x87 instructions themselves arrive in stage 2.)
pub const LEAF1_EDX: u32 = 1 | 1 << 4 | 1 << 8 | 1 << 15 | 1 << 19 | 1 << 24 | 1 << 25 | 1 << 26;
/// Leaf 1 ECX: CMPXCHG16B, POPCNT.
pub const LEAF1_ECX: u32 = 1 << 13 | 1 << 23;

fn le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Returns (eax, ebx, ecx, edx) for the given leaf / sub-leaf.
pub fn cpuid(leaf: u32, _sub: u32) -> (u32, u32, u32, u32) {
    match leaf {
        0 => (7, le(&VENDOR[0..4]), le(&VENDOR[8..12]), le(&VENDOR[4..8])),
        // Family 6; CLFLUSH line 8*8 = 64 bytes; one logical processor.
        1 => (0x000906ea, 0x0001_0800, LEAF1_ECX, LEAF1_EDX),
        0x8000_0000 => (0x8000_0004, 0, 0, 0),
        // ECX: LAHF/SAHF, LZCNT. EDX: SYSCALL, NX, long mode.
        0x8000_0001 => (0, 0, 1 | 1 << 5, 1 << 11 | 1 << 20 | 1 << 29),
        0x8000_0002..=0x8000_0004 => {
            let o = (leaf - 0x8000_0002) as usize * 16;
            let b = &BRAND[o..o + 16];
            (le(&b[0..]), le(&b[4..]), le(&b[8..]), le(&b[12..]))
        }
        _ => (0, 0, 0, 0),
    }
}
