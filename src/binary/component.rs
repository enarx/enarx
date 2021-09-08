// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use goblin::elf::{header::*, program_header::*, Elf};

use sallyport::SALLYPORT_ABI_VERSION_BASE;

use std::ops::Range;

#[allow(dead_code)]
pub enum ComponentType {
    Shim,
    Payload,
}

/// The sallyport program header type
#[cfg(any(feature = "backend-kvm"))]
pub const PT_ENARX_SALLYPORT: u32 = PT_LOOS + 0x34a0001;

/// The enarx code program header type
pub const PT_ENARX_CODE: u32 = PT_LOOS + 0x34a0003;

/// This segment contains TCS pages.
#[cfg(feature = "backend-sgx")]
pub const PF_ENARX_SGX_TCS: u32 = 1 << 20;

/// This segment contains unmeasured pages.
#[cfg(feature = "backend-sgx")]
pub const PF_ENARX_SGX_UNMEASURED: u32 = 1 << 21;

/// This note indicates the SGX enclave size (u32; in powers of 2)
#[cfg(feature = "backend-sgx")]
pub const NOTE_ENARX_SGX_SIZE: u32 = 0x73677800;

/// This note indicates the number of pages in an SSA frame (u32)
#[cfg(feature = "backend-sgx")]
pub const NOTE_ENARX_SGX_SSAP: u32 = 0x73677801;

pub struct Component<'a> {
    pub bytes: &'a [u8],
    pub elf: Elf<'a>,
    pub component_type: ComponentType,
}

impl<'a> Component<'a> {
    /// Loads a binary from bytes
    pub fn from_bytes(
        bytes: &'a (impl AsRef<[u8]> + ?Sized),
        component_type: ComponentType,
    ) -> Result<Self> {
        let bytes = bytes.as_ref();

        // Parse the file.
        let elf = Elf::parse(bytes).unwrap();

        // Validate identity assumptions.
        assert_eq!(elf.header.e_ident[EI_CLASS], ELFCLASS64);
        assert_eq!(elf.header.e_ident[EI_DATA], ELFDATA2LSB);
        assert_eq!(elf.header.e_ident[EI_VERSION], EV_CURRENT);

        // Validate header assumptions.
        assert_eq!(elf.header.e_machine, EM_X86_64);
        assert_eq!(elf.header.e_version, EV_CURRENT as _);

        // Validate that there is no interpreter.
        assert!(!elf
            .program_headers
            .iter()
            .fold(false, |a, ph| a | (ph.p_type == PT_INTERP)));

        // Validate that the entry point is in one of the loaded sections.
        assert_eq!(
            1,
            elf.program_headers
                .iter()
                .filter(|ph| {
                    ph.p_type == PT_LOAD
                        && elf.header.e_entry >= ph.p_vaddr
                        && elf.header.e_entry < ph.p_vaddr + ph.p_memsz
                })
                .count()
        );

        if matches!(component_type, ComponentType::Shim) {
            // There shouldn't be any symbols in the shim, except this one.
            let strtab = elf.strtab.to_vec()?;
            let ver = strtab
                .iter()
                .find(|x| x.starts_with(SALLYPORT_ABI_VERSION_BASE))
                .ok_or_else(|| anyhow!("Couldn't find sallyport version in shim executable."))?;

            sallyport::check_abi_version(ver)
                .map_err(|_| anyhow!("Sallyport version mismatch in shim executable."))?;
        }

        let component = Self {
            bytes,
            elf,
            component_type,
        };

        Ok(component)
    }

    pub fn filter_header(&self, type_: u32) -> impl Iterator<Item = &ProgramHeader> {
        self.elf
            .program_headers
            .iter()
            .filter(move |ph| ph.p_type == type_)
    }

    pub fn find_header(&self, type_: u32) -> Option<&ProgramHeader> {
        self.elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == type_)
    }

    /// Find the total memory region for the binary.
    pub fn region(&self) -> Range<usize> {
        let lo = self
            .filter_header(PT_LOAD)
            .map(|phdr| phdr.vm_range().start)
            .min();

        let hi = self
            .filter_header(PT_LOAD)
            .map(|phdr| phdr.vm_range().end)
            .max();

        lo.unwrap_or_default()..hi.unwrap_or_default()
    }

    /// Read a note from the note section
    #[cfg(feature = "backend-sgx")]
    pub unsafe fn read_note<T: Copy>(&self, name: &str, kind: u32) -> Result<Option<T>> {
        use std::mem::size_of;

        let headers = match self.elf.iter_note_headers(self.bytes) {
            Some(headers) => headers,
            None => return Ok(None),
        };

        for note in headers {
            let note = note?;
            if note.name == name && note.n_type == kind && note.desc.len() == size_of::<T>() {
                return Ok(Some(note.desc.as_ptr().cast::<T>().read_unaligned()));
            }
        }

        Ok(None)
    }
}
