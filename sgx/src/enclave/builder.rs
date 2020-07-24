// SPDX-License-Identifier: Apache-2.0

use super::{enclave::Enclave, ioctls};
use crate::{
    crypto::{Hasher, Signer},
    types::{
        page::{Class, Flags, SecInfo},
        {secs::*, sig::*, ssa::StateSaveArea},
    },
};

use bounds::Span;
use memory::Page;
use openssl::{bn, rsa};

use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::Result;

/// A loadable segment of code
pub struct Segment {
    /// Segment data
    pub src: Vec<Page>,
    /// The address where this segment starts
    pub dst: usize,
    /// The security information (`SecInfo`) about a page
    pub si: SecInfo,
}

fn f2p(flags: Flags) -> libc::c_int {
    let mut prot = libc::PROT_NONE;
    if flags.contains(Flags::R) {
        prot |= libc::PROT_READ;
    }

    if flags.contains(Flags::W) {
        prot |= libc::PROT_WRITE;
    }

    if flags.contains(Flags::X) {
        prot |= libc::PROT_EXEC;
    }

    prot
}

/// An SGX enclave builder
///
/// TODO add more comprehensive docs.
pub struct Builder {
    sign: Parameters,
    file: File,
    mmap: mmap::Unmap,
    hash: Hasher,
    perm: Vec<(Span<usize>, SecInfo)>,
}

impl Builder {
    /// Creates a new `Builder` instance. The input linear memory `span` is mapped
    /// into SGX's EPC. This function issues `ECREATE` instruction.
    ///
    /// TODO add more comprehensive docs
    pub fn new(span: impl Into<Span<usize>>) -> Result<Self> {
        let span = span.into();

        // Open the device.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx/enclave")?;

        // Map the memory for the enclave
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE;
        let mmap = unsafe {
            mmap::map(span.start, span.count, libc::PROT_NONE, flags, None, 0)?;
            mmap::Unmap::new(span)
        };

        // Create the hasher.
        let hash = Hasher::new(span.count, StateSaveArea::frame_size());

        // Create the enclave.
        let sign = Parameters::default();
        let secs = Secs::new(span, StateSaveArea::frame_size(), sign);
        let create = ioctls::Create::new(&secs);
        ioctls::ENCLAVE_CREATE.ioctl(&mut file, &create)?;

        Ok(Self {
            sign,
            file,
            mmap,
            hash,
            perm: Vec::new(),
        })
    }

    /// Loads a segment of memory into the SGX enclave. This function issues `EADD`
    /// instruction.
    ///
    /// TODO add more comprehensive docs.
    pub fn load(&mut self, segs: &[Segment]) -> Result<()> {
        const FLAGS: ioctls::Flags = ioctls::Flags::MEASURE;

        for seg in segs {
            // Ignore segments with no pages.
            if seg.src.len() == 0 {
                continue;
            }

            let off = seg.dst - self.mmap.span().start;

            // Update the enclave.
            let mut ap = ioctls::AddPages::new(&seg.src, off, &seg.si, FLAGS);
            ioctls::ENCLAVE_ADD_PAGES.ioctl(&mut self.file, &mut ap)?;

            // Update the hash.
            self.hash.add(&seg.src, off, seg.si, true);

            // Save permissions fixups for later.
            self.perm.push((
                Span {
                    start: seg.dst,
                    count: seg.src.len() * Page::size(),
                },
                seg.si,
            ));
        }

        Ok(())
    }

    /// Consumes this `Builder` and finalizes SGX enclave by generating
    /// signing keys, initializing the enclave, etc. This function issues
    /// `EINIT` instruction.
    ///
    /// TODO add more comprehensive docs.
    pub fn build(mut self, tcs: usize) -> Result<Enclave> {
        // Generate a signing key.
        let exp = bn::BigNum::try_from(3u32)?;
        let key = rsa::Rsa::generate_with_e(3072, &exp)?;

        // Create the enclave signature
        let vendor = Author::new(0, 0);
        let sig = key.sign(vendor, self.hash.finish(self.sign))?;

        // Initialize the enclave.
        let init = ioctls::Init::new(&sig);
        ioctls::ENCLAVE_INIT.ioctl(&mut self.file, &init)?;

        // Fix up mapped permissions.
        self.perm.sort_by(|l, r| l.0.start.cmp(&r.0.start));
        for (span, si) in self.perm {
            let rwx = match si.class {
                Class::Tcs => libc::PROT_READ | libc::PROT_WRITE,
                Class::Reg => f2p(si.flags),
                _ => panic!("Unsupported class!"),
            };

            // Change the permissions on an existing region of memory.
            unsafe {
                mmap::map(
                    span.start,
                    span.count,
                    rwx,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    Some(&self.file),
                    0,
                )?;
            }

            //let line = bounds::Line::from(span);
            //eprintln!("{:016x}-{:016x} {:?}", line.start, line.end, si);
        }

        Ok(Enclave::new(self.mmap, tcs))
    }
}
