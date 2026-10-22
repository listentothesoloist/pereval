//! Differential test against Rosetta 2.
//!
//! `tests/data/oracle.txt` is produced by tools/oracle (real x86-64 execution
//! under Rosetta). Every line is one instruction with concrete inputs; the
//! interpreter must produce the same registers and the same architecturally
//! defined flags (the per-instruction mask excludes "undefined" flags).

use std::collections::BTreeMap;

use guest_mem::{GuestMemory, Prot};
use x86_cpu::interp::Interpreter;
use x86_cpu::{Cpu, RAX, RBX, RCX, RDI, RDX, RSI, RSP};

const ORDER: [usize; 6] = [RAX, RBX, RCX, RDX, RSI, RDI];
const CODE: u64 = 0x10000;

/// Register bits compared per instruction form (default: all 64).
/// 32-bit `cmpxchg r32, r32`: what happens to the upper halves of RAX / the
/// destination differs between Rosetta 2, QEMU and a literal reading of the
/// SDM pseudocode; real x86 hardware has to decide (docs/decisions/stage1.md).
fn reg_mask(hex: &str) -> [u64; 6] {
    match hex {
        "0f b1 d9" => [0xffff_ffff, !0, 0xffff_ffff, !0, !0, !0],
        _ => [!0; 6],
    }
}

fn hex_list(s: &str) -> Vec<u64> {
    s.split_whitespace().map(|v| u64::from_str_radix(v, 16).unwrap()).collect()
}

#[test]
fn matches_rosetta() {
    let data = include_str!("data/oracle.txt");
    let mem = GuestMemory::new(1 << 32).unwrap();
    mem.map_fixed(CODE, 0x1000, Prot::RWX, "code").unwrap();
    mem.map_fixed(0x20000, 0x1000, Prot::RW, "stack").unwrap();
    let mut interp = Interpreter::new();
    let mut failures: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut cases = 0;
    for line in data.lines() {
        let f: Vec<&str> = line.split('|').collect();
        let (hex, mask) = (f[0], u64::from_str_radix(f[1], 16).unwrap());
        let (inp, out) = (hex_list(f[2]), hex_list(f[3]));
        let mut code: Vec<u8> = hex_list(hex).iter().map(|&b| b as u8).collect();
        code.resize(16, 0x90);
        mem.write_bytes(CODE, &code).unwrap();

        let mut cpu = Cpu::default();
        for (k, &r) in ORDER.iter().enumerate() {
            cpu.gpr[r] = inp[k];
        }
        cpu.gpr[RSP] = 0x20800;
        cpu.flags.set_rflags(inp[6]);
        cpu.rip = CODE;
        cases += 1;
        let exit = interp.step(&mut cpu, &mem);
        let got: Vec<u64> = ORDER.iter().map(|&r| cpu.gpr[r]).collect();
        let gflags = cpu.flags.rflags() & mask;
        let rm = reg_mask(hex);
        let same_regs = (0..6).all(|k| got[k] & rm[k] == out[k] & rm[k]);
        let ok = exit.is_none() && same_regs && gflags == out[6] & mask;
        if !ok {
            let e = failures.entry(hex.to_string()).or_insert((0, String::new()));
            if e.0 == 0 {
                e.1 = format!(
                    "in  {:x?} fl={:#x}\n      want {:x?} fl={:#x}\n      got  {:x?} fl={:#x} exit={exit:?}",
                    &inp[..6],
                    inp[6],
                    &out[..6],
                    out[6] & mask,
                    got,
                    gflags
                );
            }
            e.0 += 1;
        }
    }
    let mut report = String::new();
    for (hex, (n, first)) in &failures {
        report += &format!("[{hex}] {n} mismatches, first:\n      {first}\n");
    }
    assert!(cases > 10_000, "oracle data looks truncated ({cases} cases)");
    assert!(failures.is_empty(), "{} of {} instruction forms disagree with Rosetta:\n{report}", failures.len(), cases);
}
