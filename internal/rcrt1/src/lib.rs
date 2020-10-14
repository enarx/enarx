// SPDX-License-Identifier: Apache-2.0

//! relocate dynamic symbols
//!
//! Has to be included with
//!
//! ```toml
//! [profile.dev.package.rcrt1]
//! opt-level = 3
//! ```

#![no_std]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![no_builtins]

const R_TYPE_MASK: u64 = 0x7fffffff;

use goblin::elf::dynamic::dyn64::Dyn;
use goblin::elf::dynamic::{DT_REL, DT_RELA, DT_RELASZ, DT_RELSZ};
use goblin::elf::reloc::reloc64::Rel;
use goblin::elf::reloc::reloc64::Rela;
use goblin::elf::reloc::R_X86_64_RELATIVE;

/// Dynamic relocation for a static PIE
///
/// This is normally called early in the _start function:
///     # %rdi - address of _DYNAMIC section
///     # %rsi - base load offset
///     mov    BASE,                    %rsi
///     lea    _DYNAMIC(%rip),          %rdi
///     call   _dyn_reloc
///
/// C version: https://git.musl-libc.org/cgit/musl/tree/ldso/dlstart.c
///
/// # Safety
///
/// This function is unsafe, because the caller has to ensure the dynamic section
/// points to the correct memory.
#[no_mangle]
pub unsafe extern "C" fn _dyn_reloc(dynamic_section: *const u64, base: u64) {
    let mut dt_rel: Option<u64> = None;
    let mut dt_relsz: usize = 0;
    let mut dt_rela: Option<u64> = None;
    let mut dt_relasz: usize = 0;

    let mut dynv = dynamic_section as *const Dyn;

    while (*dynv).d_tag != 0 {
        match (*dynv).d_tag {
            DT_REL => dt_rel = Some((*dynv).d_val),
            DT_RELSZ => dt_relsz = (*dynv).d_val as usize / core::mem::size_of::<Rel>(),
            DT_RELA => dt_rela = Some((*dynv).d_val),
            DT_RELASZ => dt_relasz = (*dynv).d_val as usize / core::mem::size_of::<Rela>(),
            _ => {}
        }
        dynv = ((dynv as usize) + core::mem::size_of::<Dyn>()) as *const Dyn;
    }

    if let Some(dt_rel) = dt_rel {
        let rels = core::slice::from_raw_parts((base + dt_rel) as *const Rel, dt_relsz);

        rels.iter()
            .filter(|rel| rel.r_info & R_TYPE_MASK == R_X86_64_RELATIVE as u64)
            .for_each(|rel| {
                let rel_addr = (base + rel.r_offset) as *mut u64;
                rel_addr.write(rel_addr.read() + base);
            });
    }

    if let Some(dt_rela) = dt_rela {
        let relas = core::slice::from_raw_parts((base + dt_rela) as *const Rela, dt_relasz);

        relas
            .iter()
            .filter(|rela| rela.r_info & R_TYPE_MASK == R_X86_64_RELATIVE as u64)
            .for_each(|rela| {
                let rel_addr_0 = (base + rela.r_offset) as *mut u64;
                rel_addr_0.write((base as i64 + rela.r_addend) as u64);
            });
    }
}
