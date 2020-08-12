// SPDX-License-Identifier: Apache-2.0

//! This module provides functions for reading symbols from the Linux vDSO.

#![deny(missing_docs)]
#![deny(clippy::all)]

use crt0stack::{auxv::Entry, Reader};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice::from_raw_parts;

#[cfg(target_pointer_width = "64")]
mod elf {
    pub use goblin::elf64::dynamic::*;
    pub use goblin::elf64::header::*;
    pub use goblin::elf64::program_header::*;
    pub use goblin::elf64::section_header::*;
    pub use goblin::elf64::sym::Sym;

    pub const CLASS: u8 = ELFCLASS64;
    pub type Word = u64;
}

#[cfg(target_pointer_width = "32")]
mod elf {
    pub use goblin::elf32::dynamic::*;
    pub use goblin::elf32::header::*;
    pub use goblin::elf32::program_header::*;
    pub use goblin::elf32::section_header::*;
    pub use goblin::elf32::sym::Sym;

    pub const CLASS: u8 = ELFCLASS32;
    pub type Word = u32;
}

#[repr(transparent)]
struct Header(elf::Header);

impl Header {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub unsafe fn from_ptr(ptr: &()) -> Option<&Self> {
        let hdr = &*(ptr as *const _ as *const Self);

        if hdr.0.e_ident[..elf::ELFMAG.len()] != elf::ELFMAG[..] {
            return None;
        }

        if hdr.0.e_ident[elf::EI_CLASS] != elf::CLASS {
            return None;
        }

        Some(hdr)
    }

    unsafe fn ptr<T>(&self, off: impl Into<elf::Word>) -> *const T {
        let addr = self as *const _ as *const u8;
        addr.add(off.into() as usize) as *const T
    }

    unsafe fn slice<T>(&self, off: impl Into<elf::Word>, len: impl Into<elf::Word>) -> &[T] {
        from_raw_parts::<u8>(self.ptr(off), len.into() as usize)
            .align_to()
            .1
    }

    unsafe fn shtab(&self) -> &[elf::SectionHeader] {
        self.slice(self.0.e_shoff, self.0.e_shentsize * self.0.e_shnum)
    }

    unsafe fn section<T>(&self, kind: u32) -> Option<&[T]> {
        for sh in self.shtab() {
            if sh.sh_type == kind {
                return Some(self.slice(sh.sh_offset, sh.sh_size));
            }
        }

        None
    }

    unsafe fn symbol(&self, name: &str) -> Option<&Symbol> {
        let symstrtab: &[c_char] = self.section(elf::SHT_STRTAB)?;
        let symtab: &[elf::Sym] = self.section(elf::SHT_DYNSYM)?;

        // Yes, we could spead up the lookup by checking against the hash
        // table. But the reality is that there is less than a dozen symbols
        // in the vDSO, so the gains are trivial.

        for sym in symtab {
            let cstr = CStr::from_ptr(&symstrtab[sym.st_name as usize]);
            if let Ok(s) = cstr.to_str() {
                if s == name {
                    let addr = self.ptr(sym.st_value) as *const Symbol;
                    return Some(&*addr);
                }
            }
        }

        None
    }
}

/// A resolved symbol
///
/// Since vDSO symbols have no type information, this type is opaque.
/// Generally, you will cast a `&Symbol` to the appropriate reference type.
pub enum Symbol {}

/// This structure represents the Linux vDSO
pub struct Vdso<'a>(&'a Header);

impl Vdso<'static> {
    /// Locates the vDSO by parsing the auxiliary vectors
    pub fn locate() -> Option<Self> {
        for aux in Reader::from_environ().done() {
            if let Entry::SysInfoEHdr(addr) = aux {
                let hdr = unsafe { Header::from_ptr(&*(addr as *const _))? };
                return Some(Self(hdr));
            }
        }

        None
    }
}

impl<'a> Vdso<'a> {
    /// Find a vDSO symbol by its name
    ///
    /// The return type is essentially a void pointer. You will need to cast
    /// it for the type of the symbol you are looking up.
    pub fn lookup(&'a self, name: &str) -> Option<&'a Symbol> {
        unsafe { self.0.symbol(name) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::time_t;
    use std::mem::transmute;
    use std::ptr::null_mut;

    #[test]
    fn time() {
        let vdso = Vdso::locate().unwrap();
        let func = vdso.lookup("time").unwrap();
        let func: extern "C" fn(*mut time_t) -> time_t = unsafe { transmute(func) };

        let libc = unsafe { libc::time(null_mut()) };
        let vdso = func(null_mut());
        assert!(vdso - libc <= 1);
    }
}
