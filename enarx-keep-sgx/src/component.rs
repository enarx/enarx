// SPDX-License-Identifier: Apache-2.0

use super::contents::Contents;
use super::page::size as pagesize;
use sgx_types::page::Flags;

use goblin::elf::{header::*, program_header::*, Elf};
use span::Span;

use std::cmp::{max, min};
use std::fs::File;
use std::io::{Read, Result};
use std::ops::Range;
use std::path::Path;

/// A loadable segment of code
pub struct Segment {
    pub src: Contents,
    pub dst: Span<usize, usize>,
    pub rwx: Flags,
}

impl<'a> Segment {
    /// Creates a segment from a `ProgramHeader`.
    fn from_ph(file: &File, ph: &ProgramHeader) -> Result<Option<Self>> {
        if ph.p_type != PT_LOAD {
            return Ok(None);
        }

        let mut rwx = Flags::empty();

        if ph.p_flags & PF_R != 0 {
            rwx |= Flags::R;
        }

        if ph.p_flags & PF_W != 0 {
            rwx |= Flags::W;
        }

        if ph.p_flags & PF_X != 0 {
            rwx |= Flags::X;
        }

        let page = pagesize()?;
        let mask = page - 1;

        let src = Span {
            start: ph.p_offset as _,
            count: ph.p_filesz as _,
        };

        let dst = Span {
            start: ph.p_vaddr as _,
            count: (ph.p_memsz as usize + mask) & !mask,
        };

        assert_eq!(dst.start & mask, 0);

        Ok(Some(Self {
            rwx,
            dst,
            src: Contents::from_file(dst.count, file, src)?,
        }))
    }
}

/// A collection of code segments and the entry point
pub struct Component {
    pub segments: Vec<Segment>,
    pub entry: usize,
}

impl<'a> Component {
    /// Loads a binary from a file
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        // Open the file.
        let mut file = File::open(path)?;

        // Read in the whole file.
        let mut data = Vec::new();
        let size = file.read_to_end(&mut data)?;
        data.truncate(size);

        // Parse the file.
        let elf = Elf::parse(data.as_ref()).unwrap();

        // Validate identity assumptions.
        assert_eq!(elf.header.e_ident[EI_CLASS], ELFCLASS64);
        assert_eq!(elf.header.e_ident[EI_DATA], ELFDATA2LSB);
        assert_eq!(elf.header.e_ident[EI_VERSION], EV_CURRENT);

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

        let mut segments = Vec::new();
        for ph in elf.program_headers.iter() {
            if let Some(seg) = Segment::from_ph(&file, ph)? {
                segments.push(seg);
            }
        }

        Ok(Self {
            entry: elf.entry as _,
            segments,
        })
    }

    /// Find the bottom and top of the binary segments.
    pub fn range(&self) -> Range<usize> {
        self.segments.iter().map(|x| Range::from(x.dst)).fold(
            Range {
                start: usize::max_value(),
                end: usize::min_value(),
            },
            |l, r| Range {
                start: min(l.start, r.start),
                end: max(l.end, r.end),
            },
        )
    }
}
