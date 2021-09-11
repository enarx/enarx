// SPDX-License-Identifier: Apache-2.0

use super::{ioctls, Enclave};

use lset::Span;
use mmarinus::{perms, Kind, Map};
use primordial::Page;
use sgx::loader::{Flags, Loader};
use sgx::types::page::{self, Class, SecInfo};
use sgx::types::{secs::*, sig::*};

use std::fs::{File, OpenOptions};
use std::io::{Error, Result};
use std::mem::forget;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};

/// A structs which assists in enclave creation
///
/// 1. Instantiate the `Builder` using `Builder::new()` or `Builder::new_at()`.
/// 2. Add pages to the enclave using `Builder::load()` (see the `Loader` trait).
/// 3. Finalize the enclave contents using `Builder::build()`.
pub struct Builder {
    file: File,
    mmap: Map<perms::Unknown>,
    perm: Vec<(Span<usize>, SecInfo)>,
    tcsp: Vec<usize>,
}

impl Builder {
    /// Creates a new `Builder` instance at the given location
    ///
    /// The enclave will be placed in the provided memory map, which must be
    /// sized to a power of two and naturally aligned.
    ///
    /// This call also defines the enclave signature `Parameters` as well as
    /// the number of pages in each SSA frame. Note that while this call
    /// defines the size of each SSA frame, each thread (i.e. TCS page) can
    /// have a different number of SSA frames.
    ///
    /// For those familiar with the Intel documentation, this function wraps
    /// the call to the kernel to issue the `ECREATE` instruction.
    pub fn new_at(
        mmap: Map<perms::None>,
        ssa_frame_pages: NonZeroU32,
        parameters: Parameters,
    ) -> Result<Self> {
        let span = Span {
            start: mmap.addr(),
            count: mmap.size(),
        };

        // Validate the mapping constraints
        if span.count == 0 || !span.count.is_power_of_two() || span.start % span.count != 0 {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        // Open the device.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx_enclave")?;

        // Create the enclave.
        let secs = Secs::new(span, ssa_frame_pages, parameters);
        let create = ioctls::Create::new(&secs);
        ioctls::ENCLAVE_CREATE.ioctl(&mut file, &create)?;

        Ok(Self {
            file,
            mmap: mmap.into(), // Discard typed permissions
            perm: Vec::new(),
            tcsp: Vec::new(),
        })
    }

    /// Creates a new `Builder` instance at the given location
    ///
    /// A memory mapping for this enclave will be automatically created with
    /// the specified size. The location for this mapping will be determined
    /// by the kernel.
    ///
    /// This call also defines the enclave signature `Parameters` as well as
    /// the number of pages in each SSA frame. Note that while this call
    /// defines the size of each SSA frame, each thread (i.e. TCS page) can
    /// have a different number of SSA frames.
    ///
    /// For those familiar with the Intel documentation, this function wraps
    /// the call to the kernel to issue the `ECREATE` instruction.
    pub fn new(size: usize, ssa_frame_pages: NonZeroU32, parameters: Parameters) -> Result<Self> {
        // Map the memory for the enclave
        // We map twice as much as we need so that we can naturally align it.
        let map = Map::map(size * 2)
            .anywhere()
            .anonymously()
            .known::<perms::None>(Kind::Private)?;

        // Naturally align the mapping.
        let addr = (map.addr() + size - 1) / size * size;
        let (_, r) = map.split_at(addr)?;
        let (l, _) = r.split(size)?;

        Self::new_at(l, ssa_frame_pages, parameters)
    }

    /// Finalizes the SGX enclave
    ///
    /// This function finalizes the SGX enclave and prepares it for execution.
    ///
    /// For those familiar with the Intel documentation, this function wraps
    /// the call to the kernel to issue the `EINIT` instruction.
    pub fn build(mut self, signature: &Signature) -> Result<Arc<Enclave>> {
        // Initialize the enclave.
        let init = ioctls::Init::new(signature);
        ioctls::ENCLAVE_INIT.ioctl(&mut self.file, &init)?;

        // Fix up mapped permissions.
        self.perm.sort_by(|l, r| l.0.start.cmp(&r.0.start));
        for (span, si) in self.perm {
            let rwx = match si.class {
                Class::Tcs => libc::PROT_READ | libc::PROT_WRITE,
                Class::Reg => {
                    let mut prot = libc::PROT_NONE;

                    if si.flags.contains(page::Flags::R) {
                        prot |= libc::PROT_READ;
                    }

                    if si.flags.contains(page::Flags::W) {
                        prot |= libc::PROT_WRITE;
                    }

                    if si.flags.contains(page::Flags::X) {
                        prot |= libc::PROT_EXEC;
                    }

                    prot
                }
                _ => panic!("Unsupported class!"),
            };

            // Change the permissions on an existing region of memory.
            forget(unsafe {
                Map::map(span.count)
                    .onto(span.start)
                    .from(&mut self.file, 0)
                    .unknown(Kind::Shared, rwx)?
            });

            //let line = lset::Line::from(span);
            //eprintln!("{:016x}-{:016x} {:?}", line.start, line.end, si);
        }

        Ok(Arc::new(Enclave {
            _mem: self.mmap,
            tcs: RwLock::new(self.tcsp),
        }))
    }
}

impl Loader for Builder {
    type Error = std::io::Error;

    /// Adds pages to an enclave
    ///
    /// For those familiar with the Intel documentation, this function wraps
    /// the call to the kernel to issue the `EADD` instruction.
    fn load(
        &mut self,
        pages: impl AsRef<[Page]>,
        offset: usize,
        secinfo: SecInfo,
        flags: impl Into<flagset::FlagSet<Flags>>,
    ) -> Result<()> {
        let offset = offset * Page::SIZE;
        let pages = pages.as_ref();
        let flags = flags.into();

        // Ignore regions with no pages.
        if pages.is_empty() {
            return Ok(());
        }

        // Update the enclave.
        let mut ap = ioctls::AddPages::new(pages, offset, &secinfo, flags);
        ioctls::ENCLAVE_ADD_PAGES.ioctl(&mut self.file, &mut ap)?;

        // Calculate an absolute span for this region.
        let span = Span {
            start: self.mmap.addr() + offset,
            count: pages.len() * Page::SIZE,
        };

        // Save permissions fixups for later.
        self.perm.push((span, secinfo));

        // Keep track of TCS pages.
        if secinfo.class == page::Class::Tcs {
            for i in 0..pages.len() {
                self.tcsp.push(span.start + i * Page::SIZE);
            }
        }

        Ok(())
    }
}
