// SPDX-License-Identifier: Apache-2.0

//! Host <-> Shim Communication

use crate::allocator::{ALLOCATOR, ZERO_PAGE_FRAME};
use crate::debug::_enarx_asm_triple_fault;
use crate::exec::{BRK_LINE, NEXT_MMAP_RWLOCK};
use crate::paging::SHIM_PAGETABLE;
use crate::snp::attestation::asn1_encode_report_vcek;
use crate::snp::ghcb::{GHCB, GHCB_EXT, SNP_ATTESTATION_LEN_MAX, SNP_KEY_LEN};
use crate::snp::snp_active;
use crate::spin::{RacyCell, RwLocked};

use const_default::ConstDefault;
use core::ffi::{c_int, c_size_t, c_ulong, c_void};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::slice;
use core::sync::atomic::AtomicU32;

use sallyport::guest::syscall::types::MremapFlags;
use sallyport::guest::{self, Handler, Platform, ThreadLocalStorage};
use sallyport::item::enarxcall::sev::TECH;
use sallyport::item::syscall;
use sallyport::libc::{
    off_t, CloneFlags, EAGAIN, EFAULT, EINVAL, EIO, EMSGSIZE, ENOMEM, ENOSYS, ENOTSUP,
    MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE,
};
use sallyport::util::ptr::is_aligned_non_null;
use sallyport::{libc, KVM_SYSCALL_TRIGGER_PORT};
use spin::Lazy;
use x86_64::instructions::port::Port;
use x86_64::instructions::segmentation::{Segment64, FS, GS};
use x86_64::instructions::tlb::flush_all;
use x86_64::structures::paging::mapper::{TranslateError, TranslateResult};
use x86_64::structures::paging::{Mapper, Page, PageTableFlags, Size4KiB, Translate};
use x86_64::{align_up, VirtAddr};

/// The sallyport block size
pub const BLOCK_SIZE: usize = 69632;
/// The number of sallyport blocks
pub const NUM_BLOCKS: usize = 2;

const BLOCK_SIZE_USIZE: usize = BLOCK_SIZE / core::mem::size_of::<usize>();

/// Global TLS for the SHIM
pub static SHIM_LOCAL_STORAGE: Lazy<RwLocked<guest::ThreadLocalStorage>> =
    Lazy::new(|| RwLocked::<guest::ThreadLocalStorage>::new(guest::ThreadLocalStorage::new()));

const SNP_VCEK_BUF_SIZE: usize = 4096;

/// SNP VCEK buffer
pub static SNP_VCEK: Lazy<Result<&[u8], c_int>> = Lazy::new(|| {
    static SNP_VCEK_BUFFER: RacyCell<[u8; SNP_VCEK_BUF_SIZE]> =
        RacyCell::new([0; SNP_VCEK_BUF_SIZE]);

    let buffer_mut = unsafe { &mut *SNP_VCEK_BUFFER.get() };

    let mut tls = SHIM_LOCAL_STORAGE.write();
    let mut host_call = HostCall::try_new(&mut tls).ok_or(EAGAIN)?;
    let vcek_len = host_call.get_snp_vcek(buffer_mut)?;

    if vcek_len == 0 {
        Err(libc::EIO)
    } else {
        Ok(&buffer_mut[..vcek_len])
    }
});

/// Host file descriptor
#[derive(Copy, Clone)]
pub struct HostFd(c_int);

impl HostFd {
    /// Extracts the raw file descriptor.
    ///
    /// This method does **not** pass ownership of the raw file descriptor
    /// to the caller. The descriptor is only guaranteed to be valid while
    /// the original object has not yet been destroyed.
    pub fn as_raw_fd(self) -> c_int {
        self.0
    }

    /// Constructs a new instance of `Self` from the given raw file
    /// descriptor.
    ///
    /// # Safety
    ///
    /// This function is unsafe as the primitives currently returned
    /// have the contract that they are the sole owner of the file
    /// descriptor they are wrapping. Usage of this function could
    /// accidentally allow violating this contract which can cause memory
    /// unsafety in code that relies on it being true.
    pub unsafe fn from_raw_fd(fd: c_int) -> Self {
        Self(fd)
    }
}

#[repr(C, align(4096))]
struct FixedSallyBlock([usize; BLOCK_SIZE_USIZE * NUM_BLOCKS]);

impl ConstDefault for FixedSallyBlock {
    const DEFAULT: Self = Self([0usize; BLOCK_SIZE_USIZE * NUM_BLOCKS]);
}

/// The static HostCall RwLocked
///
/// # Safety
/// `HOST_CALL_ALLOC` is  the only way to get access to `_ENARX_SALLYPORT` and
/// is guarded with a `RwLocked`
pub static HOST_CALL_ALLOC: Lazy<RwLocked<HostCallAllocator>> = Lazy::new(|| {
    #[link_section = ".sallyport"]
    static SALLYPORT: RacyCell<FixedSallyBlock> = RacyCell::new(FixedSallyBlock::DEFAULT);

    if snp_active() {
        // For SEV-SNP mark the sallyport pages as shared/unencrypted
        let npages = BLOCK_SIZE * NUM_BLOCKS / Page::<Size4KiB>::SIZE as usize;
        GHCB.set_memory_shared(VirtAddr::from_ptr(SALLYPORT.get()), npages);
    }

    let mut hostcall_allocator = HostCallAllocator::default();

    // Safety: Split up mutable references to `SALLYPORT`, which can only be handed out
    // via the `RwLocked` `HostCallAllocator`
    let block_mut = &mut unsafe { &mut *SALLYPORT.get() }.0;

    let hostcall_iter = hostcall_allocator.0.iter_mut();

    for (store, chunk) in hostcall_iter.zip(block_mut.chunks_mut(BLOCK_SIZE_USIZE)) {
        store.replace(chunk);
    }

    RwLocked::<HostCallAllocator>::new(hostcall_allocator)
});

/// Allocator for all `sallyport::Block`
#[derive(Default)]
pub struct HostCallAllocator([Option<&'static mut [usize]>; NUM_BLOCKS]);

impl RwLocked<HostCallAllocator> {
    /// Try to allocate a `HostCall` object to use a `sallyport::Block`
    pub fn try_alloc(&self) -> Option<BlockGuard> {
        let mut this = self.write();
        this.0
            .iter_mut()
            .enumerate()
            .find(|(_i, x)| x.is_some())
            .map(|(i, ele)| BlockGuard {
                block_index: i as _,
                block: ele.take(),
            })
    }
}

/// Communication with the Host
pub struct BlockGuard {
    block_index: u16,
    block: Option<&'static mut [usize]>,
}

impl Drop for BlockGuard {
    fn drop(&mut self) {
        HOST_CALL_ALLOC.write().0[self.block_index as usize] = self.block.take();
    }
}

/// The syscall Handler
pub struct HostCall<'a> {
    block_guard: BlockGuard,
    tls: &'a mut ThreadLocalStorage,
}

impl<'a> HostCall<'a> {
    /// Try to get a new instance
    pub fn try_new(tls: &'a mut ThreadLocalStorage) -> Option<HostCall<'a>> {
        let bg = HOST_CALL_ALLOC.try_alloc()?;

        Some(Self {
            block_guard: bg,
            tls,
        })
    }

    /// get an SNP derived key
    ///
    /// See https://github.com/enarx/enarx/issues/2110
    pub fn get_key(
        &mut self,
        platform: &impl Platform,
        buf: usize,
        buf_len: usize,
    ) -> Result<usize, c_int> {
        if !snp_active() {
            return Ok(0);
        }

        if buf == 0 {
            return Ok(SNP_KEY_LEN);
        }

        if buf_len > isize::MAX as usize {
            return Err(EINVAL);
        }

        if buf_len < SNP_KEY_LEN {
            return Err(EMSGSIZE);
        }

        let user_buf = platform.validate_slice_mut::<u8>(buf, buf_len)?;

        let u = GHCB_EXT.get_key(1, 0).map_err(|_| EIO)?;

        user_buf[0..SNP_KEY_LEN].copy_from_slice(&u);

        Ok(SNP_KEY_LEN)
    }

    /// get an SNP attestation report
    ///
    /// See https://github.com/enarx/enarx/issues/966
    pub fn get_attestation(
        &mut self,
        platform: &impl Platform,
        nonce: usize,
        nonce_len: usize,
        buf: usize,
        buf_len: usize,
    ) -> Result<[usize; 2], c_int> {
        if !snp_active() {
            return Ok([0, 0]);
        }

        let vcek = (*SNP_VCEK.deref())?;

        if buf == 0 {
            // if the unwrap panics, it is totally worthy
            let len = SNP_ATTESTATION_LEN_MAX.checked_add(vcek.len()).unwrap();
            return Ok([len, TECH]);
        }

        if buf_len > isize::MAX as usize {
            return Err(EINVAL);
        }

        if buf_len < SNP_ATTESTATION_LEN_MAX {
            return Err(EMSGSIZE);
        }

        if nonce_len != 64 {
            return Err(EINVAL);
        }

        let nonce = platform.validate_slice::<u8>(nonce, nonce_len)?;
        let user_buf = platform.validate_slice_mut::<u8>(buf, buf_len)?;

        let mut report_buf = [0u8; SNP_ATTESTATION_LEN_MAX];
        let (skip, report_len) = GHCB_EXT.get_report(1, nonce, &mut report_buf)?;

        let report_data = &report_buf[skip..][..report_len];

        let len = asn1_encode_report_vcek(user_buf, report_data, vcek).ok_or(EIO)?;

        Ok([len, TECH])
    }
}

impl Handler for HostCall<'_> {
    /// Causes a `#VMEXIT` for the host to process the data in the shared memory
    ///
    /// Returns the contents of the shared memory reply status, the host might have
    /// written.
    fn sally(&mut self) -> Result<(), c_int> {
        if !snp_active() {
            let mut port = Port::<u16>::new(KVM_SYSCALL_TRIGGER_PORT);

            // prevent earlier writes from being moved beyond this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

            unsafe {
                // Safety: this I/O port does not violate memory safety
                port.write(self.block_guard.block_index);
            }

            // prevent later reads from being moved before this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);
        } else {
            // prevent earlier writes from being moved beyond this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

            GHCB.do_io_out(KVM_SYSCALL_TRIGGER_PORT, self.block_guard.block_index);

            // prevent later reads from being moved before this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);
        }
        Ok(())
    }

    #[inline(always)]
    fn block(&self) -> &[usize] {
        self.block_guard.block.as_ref().unwrap()
    }

    #[inline(always)]
    fn block_mut(&mut self) -> &mut [usize] {
        self.block_guard.block.as_mut().unwrap()
    }

    #[inline(always)]
    fn thread_local_storage(&mut self) -> &mut ThreadLocalStorage {
        self.tls
    }

    fn arch_prctl(
        &mut self,
        platform: &impl Platform,
        code: c_int,
        addr: c_ulong,
    ) -> sallyport::Result<()> {
        match code {
            syscall::ARCH_SET_FS => {
                // FIXME: check `addr` value
                unsafe {
                    FS::write_base(VirtAddr::new(addr));
                }
                eprintln!("SC> arch_prctl(ARCH_SET_FS, {addr:#x}) = 0");
                Ok(())
            }
            syscall::ARCH_GET_FS => {
                let addr: &mut u64 = platform.validate_mut(addr as _)?;
                *addr = FS::read_base().as_u64();
                Ok(())
            }
            syscall::ARCH_SET_GS => {
                // FIXME: check `addr` value
                unsafe {
                    GS::write_base(VirtAddr::new(addr));
                }
                eprintln!("SC> arch_prctl(ARCH_SET_GS, {addr:#x}) = 0");
                Ok(())
            }
            syscall::ARCH_GET_GS => {
                let addr: &mut u64 = platform.validate_mut(addr as _)?;
                *addr = GS::read_base().as_u64();
                Ok(())
            }
            x => {
                eprintln!("SC> arch_prctl({x:#x}, {addr:#x}) = -EINVAL");
                Err(EINVAL)
            }
        }
    }

    fn brk(
        &mut self,
        _platform: &impl Platform,
        addr: Option<NonNull<c_void>>,
    ) -> sallyport::Result<NonNull<c_void>> {
        let mut brk_line = BRK_LINE.write();
        let brk_end_u64 = brk_line.end.as_u64();

        eprintln!("SC> brk({addr:#?}) ...");

        match addr.map(|a| a.as_ptr() as u64) {
            None => {
                eprintln!("SC> brk({addr:#?}) = {brk_end_u64:#x}");
                Ok(NonNull::new(brk_line.end.as_mut_ptr()).unwrap())
            }

            // out of range
            Some(addr_u64) if addr_u64 < brk_line.start.as_u64() => Err(EINVAL),

            // below the last mapped page
            Some(addr_u64)
                if addr_u64 < brk_end_u64.checked_sub(Page::<Size4KiB>::SIZE).unwrap() =>
            {
                let addr_u64_aligned = align_up(addr_u64, Page::<Size4KiB>::SIZE);
                let len = (brk_line.end - addr_u64_aligned).as_u64();

                // unmap the rest
                ALLOCATOR
                    .lock()
                    .unmap_memory(VirtAddr::new(addr_u64_aligned), len as usize)
                    .unwrap();

                brk_line.end = VirtAddr::new(addr_u64_aligned);

                eprintln!("SC> brk({addr:#?}) = {addr_u64:#x}");
                Ok(NonNull::new(addr_u64 as _).unwrap())
            }

            // inside the last mapped page
            Some(addr_u64) if addr_u64 < brk_end_u64 => {
                eprintln!("SC> brk({addr:#?}) = {addr_u64:#x}");
                Ok(NonNull::new(addr_u64 as _).unwrap())
            }

            // above the last mapped page
            Some(addr_u64) => {
                let addr_u64_aligned = align_up(addr_u64, Page::<Size4KiB>::SIZE);
                let len = addr_u64_aligned.checked_sub(brk_line.end.as_u64()).unwrap();

                ALLOCATOR
                    .lock()
                    .allocate_and_map_memory(
                        brk_line.end,
                        len as usize,
                        PageTableFlags::PRESENT
                            | PageTableFlags::USER_ACCESSIBLE
                            | PageTableFlags::WRITABLE,
                        PageTableFlags::PRESENT
                            | PageTableFlags::WRITABLE
                            | PageTableFlags::USER_ACCESSIBLE,
                    )
                    .map_err(|_| {
                        eprintln!("SC> brk({addr:#?}) = ENOMEM");
                        ENOMEM
                    })?;

                brk_line.end = VirtAddr::new(addr_u64_aligned);

                eprintln!("SC> brk({addr:#?}) = {addr_u64:#x}");
                Ok(NonNull::new(addr_u64 as _).unwrap())
            }
        }
    }

    fn clone(
        &mut self,
        _flags: CloneFlags,
        _stack: NonNull<c_void>,
        _ptid: Option<&AtomicU32>,
        _ctid: Option<&AtomicU32>,
        _tls: NonNull<c_void>,
    ) -> sallyport::Result<c_int> {
        Err(ENOSYS)
    }

    fn madvise(
        &mut self,
        _platform: &impl Platform,
        _addr: NonNull<c_void>,
        _length: c_size_t,
        _advice: c_int,
    ) -> sallyport::Result<()> {
        // FIXME
        Ok(())
    }

    /// Executes [`mremap`](https://man7.org/linux/man-pages/man2/mremap.2.html) syscall akin to [`libc::mremap`].
    /// If `flags` is `Some`, `[libc::MREMAP_MAYMOVE]` is implied.
    fn mremap(
        &mut self,
        platform: &impl Platform,
        old_address: NonNull<c_void>,
        old_size: c_size_t,
        new_size: c_size_t,
        flags: Option<MremapFlags>,
    ) -> sallyport::Result<NonNull<c_void>> {
        fn normalize_flags(flags: PageTableFlags) -> PageTableFlags {
            let mut new_flags = flags.intersection(
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::BIT_10,
            );

            if new_flags.contains(PageTableFlags::BIT_10) {
                new_flags.remove(PageTableFlags::BIT_10);
                new_flags |= PageTableFlags::WRITABLE;
            }

            new_flags
        }

        eprintln!("SC> mremap({old_address:?}, {old_size:?}, {new_size:?}, {flags:#?}) ...");

        match flags {
            None | Some(MremapFlags { FIXED: None, .. }) if new_size == old_size => Ok(old_address),
            Some(MremapFlags {
                FIXED: None,
                DONTUNMAP: false,
            }) if new_size < old_size => {
                // Make sure old address range is owned by process
                let source_slice =
                    platform.validate_slice::<u8>(old_address.as_ptr() as _, old_size)?;

                // simply unmap the tail
                let addr = &source_slice[new_size] as *const _;
                // It is not an error if the indicated range does not contain any mapped pages.
                let _ = self.munmap(
                    platform,
                    NonNull::new(addr as *mut c_void).ok_or(EINVAL)?,
                    old_size.checked_sub(new_size).ok_or(EINVAL)?,
                );
                Ok(old_address)
            }
            Some(MremapFlags {
                FIXED: None,
                DONTUNMAP,
            }) if new_size > old_size => {
                // Make sure old address range is owned by process
                let source_slice =
                    platform.validate_slice::<u8>(old_address.as_ptr() as _, old_size)?;

                let old_start_addr = VirtAddr::from_ptr(old_address.as_ptr());
                let old_end_page: Page = Page::containing_address(old_start_addr + old_size - 1u64);
                let old_page_range =
                    Page::range_inclusive(Page::containing_address(old_start_addr), old_end_page);

                let start_addr = VirtAddr::from_ptr(old_address.as_ptr()) + old_size;
                let start_page: Page = Page::containing_address(start_addr);
                let end_page: Page = Page::containing_address(start_addr + new_size - 1u64);
                let page_range = Page::range_inclusive(start_page, end_page);

                let mut shim_page_table = SHIM_PAGETABLE.write();

                let TranslateResult::Mapped { flags, .. } = shim_page_table.translate(VirtAddr::from_ptr(old_address.as_ptr())) else {
                    return Err(EINVAL);
                };

                let new_flags = normalize_flags(flags);

                // check that the old address range is mapped
                if !new_flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE) {
                    return Err(EFAULT);
                }

                // Check, that all pages have the same permissions as the first
                for page in old_page_range.skip(1) {
                    let TranslateResult::Mapped { flags, .. } = shim_page_table.translate(page.start_address()) else {
                        return Err(EINVAL);
                    };

                    let flags = normalize_flags(flags);

                    if flags != new_flags {
                        return Err(EFAULT);
                    }
                }

                // Check, if the region can be extended, if all pages beneath are free
                let check_mem_unmapped = page_range.into_iter().all(|page| {
                    matches!(
                        shim_page_table.translate_page(page),
                        Err(TranslateError::PageNotMapped)
                    )
                });

                if check_mem_unmapped {
                    eprintln!("SC> mremap: adding to the end of the mapping");

                    let len_aligned =
                        align_up((new_size - old_size) as _, Page::<Size4KiB>::SIZE) as _;

                    let _ = ALLOCATOR
                        .lock()
                        .map_memory_zero(
                            &mut shim_page_table,
                            start_addr,
                            len_aligned,
                            new_flags,
                            PageTableFlags::PRESENT
                                | PageTableFlags::WRITABLE
                                | PageTableFlags::USER_ACCESSIBLE,
                        )
                        .map_err(|_| {
                            eprintln!("SC> mmap(0, {len_aligned}, ...) = ENOMEM");
                            ENOMEM
                        })?;

                    let mut nmmap = NEXT_MMAP_RWLOCK.write();

                    if *nmmap < start_addr + len_aligned {
                        *nmmap = start_addr + len_aligned;
                    }

                    Ok(old_address)
                } else {
                    drop(shim_page_table);
                    // FIXME: copy the physical pages in the page table

                    // simply copy the old data to a new location
                    let mut prot = PROT_READ;

                    if new_flags.intersects(PageTableFlags::WRITABLE | PageTableFlags::BIT_10) {
                        prot |= PROT_WRITE;
                    }

                    if !new_flags.contains(PageTableFlags::NO_EXECUTE) {
                        prot |= PROT_EXEC;
                    }

                    let new_addr = self.mmap(
                        platform,
                        None,
                        new_size,
                        prot,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0,
                    )?;
                    // SAFETY: we successfully mmap'ed the memory
                    let new_slice = unsafe {
                        slice::from_raw_parts_mut(new_addr.as_ptr() as *mut u8, new_size)
                    };
                    new_slice[..old_size].copy_from_slice(source_slice);

                    if !DONTUNMAP {
                        // It is not an error if the indicated range does not contain any mapped pages.
                        let _ = self.munmap(platform, old_address, old_size);
                    }

                    Ok(NonNull::new(new_slice.as_ptr() as *mut _).unwrap())
                }
            }
            _ => Err(ENOTSUP),
        }
    }

    fn mmap(
        &mut self,
        _platform: &impl Platform,
        addr: Option<NonNull<c_void>>,
        length: c_size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> sallyport::Result<NonNull<c_void>> {
        const PA: i32 = MAP_PRIVATE | MAP_ANONYMOUS;

        eprintln!("SC> mmap({addr:#?}, {length}, {prot}, ...)");

        match (addr, length, prot, flags, fd, offset) {
            (None, _, _, PA, -1, 0) => {
                let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

                if prot & PROT_WRITE != 0 {
                    flags |= PageTableFlags::WRITABLE;
                }

                if prot & PROT_EXEC == 0 {
                    flags |= PageTableFlags::NO_EXECUTE;
                }

                let virt_addr = *NEXT_MMAP_RWLOCK.read().deref();
                let len_aligned = align_up(length as _, Page::<Size4KiB>::SIZE) as _;

                let mem_slice = ALLOCATOR
                    .lock()
                    .map_memory_zero(
                        &mut SHIM_PAGETABLE.write(),
                        virt_addr,
                        len_aligned,
                        flags,
                        PageTableFlags::PRESENT
                            | PageTableFlags::WRITABLE
                            | PageTableFlags::USER_ACCESSIBLE,
                    )
                    .map_err(|_| {
                        eprintln!("SC> mmap(0, {length}, ...) = ENOMEM");
                        ENOMEM
                    })?;

                eprintln!("SC> mmap(0, {}, ...) = {:#?}", length, mem_slice.as_ptr());

                *NEXT_MMAP_RWLOCK.write().deref_mut() = virt_addr + (len_aligned as u64);
                Ok(NonNull::new(mem_slice.as_mut_ptr() as *mut c_void).unwrap())
            }
            (addr, ..) => {
                eprintln!("SC> mmap({addr:#?}, {length}, ...)");
                unimplemented!()
            }
        }
    }

    fn mprotect(
        &mut self,
        _platform: &impl Platform,
        addr: NonNull<c_void>,
        len: c_size_t,
        prot: c_int,
    ) -> sallyport::Result<()> {
        // FIXME: check, that addr points to userspace address
        let addr = addr.as_ptr();

        let mut page_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

        if prot & PROT_WRITE != 0 {
            page_flags |= PageTableFlags::WRITABLE;
        }

        if prot & PROT_EXEC == 0 {
            page_flags |= PageTableFlags::NO_EXECUTE;
        }

        let start_addr = VirtAddr::from_ptr(addr);
        let start_page: Page = Page::containing_address(start_addr);
        let end_page: Page = Page::containing_address(start_addr + len - 1u64);
        let page_range = Page::range_inclusive(start_page, end_page);

        let mut shim_page_table = SHIM_PAGETABLE.write();

        for page in page_range {
            match shim_page_table.translate(page.start_address()) {
                TranslateResult::Mapped { flags, .. }
                    if flags.contains(PageTableFlags::USER_ACCESSIBLE) => {}
                _ => {
                    eprintln!(
                        "SC> mprotect({addr:#?}, {len}, {prot}, ...) = EINVAL !USER_ACCESSIBLE"
                    );
                    return Err(EINVAL);
                }
            }
        }

        for page in page_range {
            match shim_page_table.translate(page.start_address()) {
                TranslateResult::Mapped { frame, flags, .. }
                    if flags.contains(PageTableFlags::USER_ACCESSIBLE) =>
                {
                    if frame.start_address() == ZERO_PAGE_FRAME.start_address()
                        && page_flags.contains(PageTableFlags::WRITABLE)
                        && !flags.contains(PageTableFlags::BIT_10)
                    {
                        page_flags.remove(PageTableFlags::WRITABLE);
                        page_flags |= PageTableFlags::BIT_10;
                    }
                    let ret = unsafe {
                        // Safety: only read and write access is modified
                        shim_page_table.update_flags(page, page_flags)
                    };
                    match ret {
                        Ok(flush) => flush.ignore(),
                        Err(e) => {
                            eprintln!(
                                "SC> mprotect({addr:#?}, {len}, {prot}, ...) = EINVAL ({e:#?})"
                            );
                            return Err(EINVAL);
                        }
                    }
                }
                _ => {
                    eprintln!(
                        "SC> mprotect({addr:#?}, {len}, {prot}, ...) = EINVAL !USER_ACCESSIBLE"
                    );
                    return Err(EINVAL);
                }
            }
        }

        flush_all();

        eprintln!("SC> mprotect({addr:#?}, {len}, {prot}, ...) = 0");

        Ok(())
    }

    fn munmap(
        &mut self,
        platform: &impl Platform,
        addr: NonNull<c_void>,
        length: c_size_t,
    ) -> sallyport::Result<()> {
        eprintln!("SC> munmap({addr:#?}, {length}) = 0");

        let addr: &[u8] = platform.validate_slice(addr.as_ptr() as _, length)?;

        // It is not an error if the indicated range does not contain any mapped pages.
        let _ = ALLOCATOR
            .lock()
            .unmap_memory(VirtAddr::from_ptr(addr.as_ptr()), length);

        Ok(())
    }
}

/// Memory validation scope
pub struct UserMemScope;

impl Platform for UserMemScope {
    /// Validates that the memory pointed to by `ptr` of the type `T` is:
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed mutably.
    ///
    /// Returns a mutable borrow if valid, otherwise [`EINVAL`](https://man7.org/linux/man-pages/man3/errno.3.html).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    #[inline]
    fn validate_mut<T>(&self, ptr: usize) -> Result<&mut T, c_int> {
        is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;

        // Safety: The pointer is now non-null aligned.
        // FIXME: ensure the lifetime and that it is not borrowed multiple times.
        // FIXME: ensure valid address space and writable https://github.com/enarx/enarx/issues/964
        unsafe { (ptr as *mut T).as_mut().ok_or(EINVAL) }
    }

    /// Validates that the memory pointed to by `ptr` of the type `T` is:
    /// * in valid address space and readable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed.
    ///
    /// Returns an immutable borrow if valid, otherwise [`EINVAL`](https://man7.org/linux/man-pages/man3/errno.3.html).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    #[inline]
    fn validate<T>(&self, ptr: usize) -> Result<&T, c_int> {
        is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;

        // Safety: The pointer is now non-null aligned.
        // FIXME: ensure the lifetime and that it is not borrowed writeable.
        // FIXME: ensure valid address space and readable https://github.com/enarx/enarx/issues/964
        unsafe { (ptr as *const T).as_ref().ok_or(EINVAL) }
    }

    /// Validates that a region for `len` elements of type `T` is:
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed mutably.
    ///
    /// Returns a mutable borrow if valid, otherwise [`EINVAL`](https://man7.org/linux/man-pages/man3/errno.3.html).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    #[inline]
    fn validate_slice_mut<T: Sized>(
        &self,
        ptr: usize,
        count: usize,
    ) -> sallyport::Result<&mut [T]> {
        is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;

        // Safety: The pointer is now non-null aligned.
        // FIXME: ensure the lifetime and that it is not borrowed already.
        // FIXME: ensure valid address space and writable https://github.com/enarx/enarx/issues/964
        unsafe { Ok(slice::from_raw_parts_mut(ptr as *mut T, count)) }
    }

    /// Validates that a region of memory is valid for read-only access for `len` elements of type `T`.
    /// * in valid address space and writable for the lifetime of `self`.
    /// * "dereferenceable" in the sense defined in [the ptr module documentation].
    /// * ptr is non-null and aligned
    /// * not borrowed already
    /// and registers the memory as borrowed.
    ///
    /// Returns an immutable borrow if valid, otherwise [`EINVAL`](https://man7.org/linux/man-pages/man3/errno.3.html).
    ///
    /// [the ptr module documentation]: core::ptr#safety
    #[inline]
    fn validate_slice<T: Sized>(&self, ptr: usize, count: usize) -> sallyport::Result<&[T]> {
        is_aligned_non_null::<T>(ptr).ok_or(EINVAL)?;

        // Safety: The pointer is now non-null aligned.
        // FIXME: ensure the lifetime and that it is not borrowed writeable.
        // FIXME: ensure valid address space and readable https://github.com/enarx/enarx/issues/964
        unsafe { Ok(slice::from_raw_parts(ptr as *const T, count)) }
    }
}

/// Write all `bytes` to a host file descriptor `fd`
#[inline(always)]
pub fn shim_write_all(fd: HostFd, bytes: &[u8]) -> Result<(), c_int> {
    let bytes_len = bytes.len();
    let mut to_write = bytes_len;

    let mut tls = SHIM_LOCAL_STORAGE.write();
    let mut host_call = HostCall::try_new(&mut tls).ok_or(EAGAIN)?;

    loop {
        let next = bytes_len.checked_sub(to_write).ok_or(EFAULT)?;
        let written = host_call.write(fd.as_raw_fd(), &bytes[next..])?;
        // be careful with `written` as it is untrusted
        to_write = to_write.checked_sub(written).ok_or(EIO)?;
        if to_write == 0 {
            break;
        }
    }

    Ok(())
}

/// Exit the shim with a `status` code
///
/// Reverts to a triple fault, which causes a `#VMEXIT` and a KVM shutdown,
/// if it cannot talk to the host.
pub fn shim_exit(status: i32) -> ! {
    if let Some(mut host_call) = HostCall::try_new(SHIM_LOCAL_STORAGE.write().deref_mut()) {
        let _ = host_call.exit_group(status);
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() }
}
