// SPDX-License-Identifier: Apache-2.0

//! This code has multiple purposes.
//!
//! 1. It wraps the elf parsing library so we don't export it everywhere.
//!    This means we can choose a new library in the future without much fuss.
//!
//! 2. It collects into a single place the sanity checking for the elf binary
//!    inputs. We don't want to litter the code with these kinds of sanity
//!    checks, so we do it all at once on load.
//!
//! 3. It allows us to replace the possibly unaligned input data with `Paged`
//!    input data.

use super::paged::Paged;

use addr::{Address, Offset};
use goblin::elf::{header::*, program_header::*, Elf};
use mmap::Protections;
use span::Span;

use std::cmp::{max, min};
use std::ops::Range;
use std::path::Path;

/// A loadable segment of code
///
/// This type mostly just wraps a `ProgramHeader` with `Paged` data.
pub struct Segment {
    pub src: crate::paged::Paged,
    pub dst: Span<Address<usize>, Offset<usize>>,
    pub prt: Protections,
}

impl<'a> Segment {
    /// Creates a segment from a `ProgramHeader`.
    fn from_ph(data: impl AsRef<[u8]>, ph: &ProgramHeader) -> Option<Self> {
        if ph.p_type != PT_LOAD {
            return None;
        }

        let mut prt = Protections::empty();

        if ph.p_flags & PF_R != 0 {
            prt |= Protections::READ;
        }

        if ph.p_flags & PF_W != 0 {
            prt |= Protections::WRITE;
        }

        if ph.p_flags & PF_X != 0 {
            prt |= Protections::EXEC;
        }

        let (src, dst) = Paged::expand(
            &data.as_ref()[ph.p_offset as _..][..ph.p_filesz as _],
            Span {
                start: Address::new(ph.p_vaddr as _),
                count: Offset::new(ph.p_memsz as _),
            },
        );

        Some(Self { prt, src, dst })
    }
}

/// A collection of code segments and the entry point.
pub struct Component {
    pub segments: Vec<Segment>,
    pub entry: Address<usize>,
}

impl<'a> Component {
    /// Loads a binary from a file.
    pub fn from_path(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        Ok(Self::from_data(&data))
    }

    /// Parses a binary from in-memory data.
    pub fn from_data(data: impl AsRef<[u8]>) -> Self {
        let elf = Elf::parse(data.as_ref()).unwrap();

        // Validate identity assumptions.
        assert_eq!(elf.header.e_ident[EI_CLASS], ELFCLASS64);
        assert_eq!(elf.header.e_ident[EI_DATA], ELFDATA2LSB);
        assert_eq!(elf.header.e_ident[EI_VERSION], EV_CURRENT);
        //assert_eq!(elf.header.e_ident[EI_OSABI], ELFOSABI_NONE);
        //assert_eq!(elf.header.e_ident[EI_ABIVERSION], 0);

        // Validate header assumptions.
        assert_eq!(elf.header.e_type, ET_EXEC);
        assert_eq!(elf.header.e_machine, EM_X86_64);
        assert_eq!(elf.header.e_version, EV_CURRENT as _);

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

        Self {
            entry: Address::from(elf.entry as usize),
            segments: elf
                .program_headers
                .iter()
                .filter_map(|ph| Segment::from_ph(&data, ph))
                .collect(),
        }
    }

    /// Find the bottom and top of the binary segments.
    pub fn range(&self) -> Range<Address<usize>> {
        self.segments.iter().map(|x| Range::from(x.dst)).fold(
            Range {
                start: usize::max_value().into(),
                end: usize::min_value().into(),
            },
            |l, r| Range {
                start: min(l.start, r.start),
                end: max(l.end, r.end),
            },
        )
    }
}
