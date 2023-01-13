// SPDX-License-Identifier: Apache-2.0

use super::Config;

use std::convert::TryInto;
use std::fmt::Formatter;

use anyhow::{anyhow, Error, Result};
use goblin::elf::{header::*, note::NoteIterator, program_header::*, Elf};
use mmarinus::{perms, Map};
use primordial::Page;

use crate::backend::Signatures;
use std::ops::Range;
use tracing::{trace, trace_span};

#[derive(Clone)]
struct Segment<'a> {
    bytes: &'a [u8],
    range: Range<usize>,
    skipb: usize,
    flags: u32,
}

impl std::fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("range", &format!("{:x?}", &self.range))
            .field("skipb", &self.skipb)
            .field("flags", &self.flags)
            .finish()
    }
}

pub struct Binary<'a>(&'a [u8], Elf<'a>);

impl<'a> Binary<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        let elf = Elf::parse(bytes)?;

        if elf.header.e_ident[EI_CLASS] != ELFCLASS64 {
            return Err(anyhow!("unsupported ELF header: e_ident[EI_CLASS]"));
        }

        if elf.header.e_ident[EI_DATA] != ELFDATA2LSB {
            return Err(anyhow!("unsupported ELF header: e_ident[EI_DATA]",));
        }

        if elf.header.e_ident[EI_VERSION] != EV_CURRENT {
            return Err(anyhow!("unsupported ELF header: e_ident[EI_VERSION]",));
        }

        if elf.header.e_machine != EM_X86_64 {
            return Err(anyhow!("unsupported ELF header: e_machine"));
        }

        if elf.header.e_version != EV_CURRENT as u32 {
            return Err(anyhow!("unsupported ELF header: e_version"));
        }

        if elf.program_headers.iter().any(|ph| ph.p_type == PT_INTERP) {
            return Err(anyhow!("unsupported ELF header: p_type == PT_INTERP",));
        }

        if !elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .filter(|ph| elf.header.e_entry >= ph.p_vaddr)
            .any(|ph| elf.header.e_entry < ph.p_vaddr + ph.p_memsz)
        {
            return Err(anyhow!("unsupported ELF header: e_entry"));
        }

        Ok(Self(bytes, elf))
    }

    fn segments(&self, relocate: usize) -> impl Iterator<Item = Segment<'_>> {
        assert_eq!(relocate % Page::SIZE, 0);

        self.headers(PT_LOAD).map(move |phdr| {
            let range = phdr.vm_range();
            let align = phdr.p_align as usize;
            let range = range.start + relocate..range.end + relocate + Page::SIZE - 1;

            let segment = Segment {
                bytes: &self.0[phdr.file_range()],
                skipb: range.start % align,
                flags: phdr.p_flags,
                range: Range {
                    start: range.start / align * align,
                    end: range.end / Page::SIZE * Page::SIZE,
                },
            };
            trace!(?phdr, ?relocate, ?segment);
            segment
        })
    }

    /// Find the total memory region for the binary.
    fn range(&self) -> Range<usize> {
        let lo = self
            .headers(PT_LOAD)
            .map(|phdr| phdr.vm_range().start)
            .min();

        let hi = self.headers(PT_LOAD).map(|phdr| phdr.vm_range().end).max();

        lo.unwrap_or_default()..hi.unwrap_or_default()
    }

    pub fn headers(&self, kind: u32) -> impl Iterator<Item = &ProgramHeader> {
        self.1
            .program_headers
            .iter()
            .filter(move |ph| ph.p_type == kind)
    }

    pub fn notes(&self, name: &'a str, kind: u32) -> impl Iterator<Item = &[u8]> {
        let empty = NoteIterator {
            iters: vec![],
            index: 0,
        };

        self.1
            .iter_note_headers(self.0)
            .unwrap_or(empty)
            .filter_map(Result::ok)
            .filter(move |n| n.n_type == kind)
            .filter(move |n| n.name == name)
            .map(|n| n.desc)
    }

    /// Read a note from the note section
    ///
    /// # Safety
    ///
    /// This function transmutes the bytes into the specified type. Beware!
    #[allow(dead_code)]
    pub unsafe fn note<T: Copy>(&self, name: &str, kind: u32) -> Option<T> {
        use core::mem::size_of;

        for note in self.notes(name, kind) {
            if note.len() == size_of::<T>() {
                return Some(note.as_ptr().cast::<T>().read_unaligned());
            }
        }

        None
    }
}

impl<T: Mapper> Loader for T {
    fn load(
        shim: impl AsRef<[u8]>,
        exec: impl AsRef<[u8]>,
        signatures: Option<Signatures>,
    ) -> Result<Self::Output> {
        use sallyport::elf;

        // Parse the ELF files.
        let sbin = Binary::new(shim.as_ref())?;
        let ebin = Binary::new(exec.as_ref())?;

        // Find the offset for loading the code.
        let slot = sbin
            .headers(elf::pt::EXEC)
            .next()
            .ok_or_else(|| anyhow!("Shim is missing the executable slot!"))?
            .vm_range();

        // Check the bounds of the executable.
        let range = ebin.range();
        if range.start != 0 || range.end > slot.end - slot.start {
            return Err(anyhow!("The executable doesn't fit in the slot!"));
        }

        // Check sallyport compatibility
        let version = semver::Version::parse(sallyport::VERSION).unwrap();
        let supported = sbin
            .notes(elf::note::NAME, elf::note::REQUIRES)
            .filter_map(|n| std::str::from_utf8(n).ok())
            .filter_map(|n| semver::VersionReq::parse(n).ok())
            .any(|req| req.matches(&version));
        if !supported {
            return Err(anyhow!("Unable to satisfy sallyport version requirement!"));
        }

        // Parse the config and create a builder.
        let mut loader: Self = Self::Config::new(&sbin, &ebin, signatures)?.try_into()?;

        // Get an array of all final segment locations (relocated).
        let ssegs: Vec<Segment<'_>> =
            trace_span!("shim segments").in_scope(|| sbin.segments(0).collect());

        let esegs: Vec<Segment<'_>> =
            trace_span!("exec segments").in_scope(|| ebin.segments(slot.start).collect());

        // Ensure no segments overlap in memory.
        let mut sorted: Vec<_> = ssegs.iter().chain(esegs.iter()).collect();
        sorted.sort_unstable_by_key(|seg| seg.range.start);
        for pair in sorted.windows(2) {
            if pair[0].range.end > pair[1].range.start {
                return Err(anyhow!("Segments overlap!"));
            }
        }

        // Load segments.
        for seg in ssegs.iter().chain(esegs.iter()) {
            // Create the mapping and copy the bytes.
            let mut map = Map::bytes(seg.range.end - seg.range.start)
                .anywhere()
                .anonymously()
                .with(perms::ReadWrite)?;
            map[seg.skipb..][..seg.bytes.len()].copy_from_slice(seg.bytes);

            // Pass the region to the builder.
            let flags = Self::Config::flags(seg.flags);
            loader.map(map, seg.range.start, flags)?;
        }

        loader.try_into()
    }
}

pub(crate) trait Mapper: Sized + TryFrom<Self::Config, Error = Error> {
    type Config: Config;
    type Output: TryFrom<Self, Error = Error>;

    fn map(
        &mut self,
        pages: Map<perms::ReadWrite>,
        to: usize,
        with: <Self::Config as Config>::Flags,
    ) -> Result<()>;
}

pub(crate) trait Loader: Mapper {
    fn load(
        shim: impl AsRef<[u8]>,
        exec: impl AsRef<[u8]>,
        signatures: Option<Signatures>,
    ) -> Result<Self::Output>;
}
