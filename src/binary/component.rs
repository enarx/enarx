// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use goblin::elf::{header::*, note::NoteIterator, program_header::*, Elf};

use std::ops::Range;

pub struct Component<'a> {
    pub bytes: &'a [u8],
    pub elf: Elf<'a>,
}

impl<'a> Component<'a> {
    /// Loads a binary from bytes
    pub fn from_bytes(bytes: &'a (impl AsRef<[u8]> + ?Sized)) -> Result<Self> {
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

        Ok(Self { bytes, elf })
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

    pub fn filter_notes(&'a self, name: &'a str, kind: u32) -> impl Iterator<Item = &'a [u8]> {
        let empty = NoteIterator {
            iters: vec![],
            index: 0,
        };

        self.elf
            .iter_note_headers(self.bytes)
            .unwrap_or(empty)
            .filter_map(Result::ok)
            .filter(move |n| n.n_type == kind)
            .filter(move |n| n.name == name)
            .map(|n| n.desc)
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
        use core::mem::size_of;

        for note in self.filter_notes(name, kind) {
            if note.len() == size_of::<T>() {
                return Ok(Some(note.as_ptr().cast::<T>().read_unaligned()));
            }
        }

        Ok(None)
    }
}
