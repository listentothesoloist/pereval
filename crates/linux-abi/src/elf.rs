//! ELF64 loader (System V gABI + x86-64 psABI).

use std::collections::BTreeMap;

use guest_mem::{page_align_down, page_align_up, GuestMemory, Prot, GUEST_PAGE};

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;

/// Where position-independent executables are placed.
pub const PIE_BASE: u64 = 0x0000_0055_5555_0000;

#[derive(Debug, Clone)]
pub struct LoadedElf {
    pub entry: u64,
    /// Load bias (0 for ET_EXEC).
    pub bias: u64,
    pub phdr: u64,
    pub phnum: u64,
    pub phent: u64,
    /// First page after the highest segment: where `brk` starts.
    pub end: u64,
    pub interp: Option<String>,
}

#[derive(Clone, Copy)]
struct Phdr {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

pub fn load(mem: &GuestMemory, data: &[u8], name: &str) -> Result<LoadedElf, String> {
    if data.len() < 64 || &data[..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    if data[4] != 2 || data[5] != 1 {
        return Err("only 64-bit little-endian ELF is supported".into());
    }
    let e_type = u16_at(data, 16);
    if u16_at(data, 18) != EM_X86_64 {
        return Err(format!("not an x86-64 binary (e_machine = {})", u16_at(data, 18)));
    }
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(format!("unsupported ELF type {e_type}"));
    }
    let entry = u64_at(data, 24);
    let phoff = u64_at(data, 32) as usize;
    let phent = u16_at(data, 54) as usize;
    let phnum = u16_at(data, 56) as usize;
    if phent != 56 || phoff + phent * phnum > data.len() {
        return Err("bad program header table".into());
    }
    let phdrs: Vec<Phdr> = (0..phnum)
        .map(|k| {
            let o = phoff + k * phent;
            Phdr {
                p_type: u32_at(data, o),
                flags: u32_at(data, o + 4),
                offset: u64_at(data, o + 8),
                vaddr: u64_at(data, o + 16),
                filesz: u64_at(data, o + 32),
                memsz: u64_at(data, o + 40),
            }
        })
        .collect();

    let interp = phdrs.iter().find(|p| p.p_type == PT_INTERP).map(|p| {
        let s = &data[p.offset as usize..(p.offset + p.filesz) as usize];
        String::from_utf8_lossy(s.split(|&b| b == 0).next().unwrap_or(&[])).into_owned()
    });
    let loads: Vec<Phdr> = phdrs.iter().copied().filter(|p| p.p_type == PT_LOAD && p.memsz > 0).collect();
    if loads.is_empty() {
        return Err("no loadable segments".into());
    }
    let bias = if e_type == ET_DYN { PIE_BASE } else { 0 };

    // Map the whole image span once, copy the segments in, then fix up page
    // protections. Adjacent segments may share a 4 KiB page, so the page gets
    // the union of their permissions.
    let lo = page_align_down(loads.iter().map(|p| p.vaddr).min().unwrap() + bias);
    let hi = page_align_up(loads.iter().map(|p| p.vaddr + p.memsz).max().unwrap() + bias);
    mem.map_fixed(lo, hi - lo, Prot::RW, name).map_err(|e| format!("mapping {lo:#x}..{hi:#x}: {e}"))?;
    let mut page_prot: BTreeMap<u64, Prot> = BTreeMap::new();
    for p in &loads {
        if p.filesz > p.memsz || (p.offset + p.filesz) as usize > data.len() {
            return Err("segment exceeds file".into());
        }
        let va = p.vaddr + bias;
        mem.write_bytes(va, &data[p.offset as usize..(p.offset + p.filesz) as usize]).map_err(|e| e.to_string())?;
        // ELF p_flags: X=1 W=2 R=4.
        let prot = Prot(((p.flags & 4) >> 2 | (p.flags & 2) | (p.flags & 1) << 2) as u8);
        let mut pg = page_align_down(va);
        while pg < va + p.memsz {
            let e = page_prot.entry(pg).or_insert(Prot::NONE);
            *e = *e | prot;
            pg += GUEST_PAGE;
        }
    }
    // Apply protections in runs of equal pages (None = gap between segments).
    let mut pg = lo;
    while pg < hi {
        let cur = page_prot.get(&pg).copied();
        let mut run_end = pg + GUEST_PAGE;
        while run_end < hi && page_prot.get(&run_end).copied() == cur {
            run_end += GUEST_PAGE;
        }
        match cur {
            Some(prot) => mem.protect(pg, run_end - pg, prot),
            None => mem.unmap(pg, run_end - pg),
        }
        .map_err(|e| e.to_string())?;
        pg = run_end;
    }

    let phdr = match phdrs.iter().find(|p| p.p_type == PT_PHDR) {
        Some(p) => p.vaddr + bias,
        None => {
            // The header table usually lives in the first segment, which maps file offset 0.
            let first = loads.iter().find(|p| p.offset == 0).ok_or("cannot locate program headers")?;
            first.vaddr + bias + phoff as u64
        }
    };
    Ok(LoadedElf { entry: entry + bias, bias, phdr, phnum: phnum as u64, phent: phent as u64, end: hi, interp })
}
