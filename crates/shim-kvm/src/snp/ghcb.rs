// SPDX-License-Identifier: Apache-2.0

//! Guest Hypervisor Communication Block (GHCB)
//!
//! This module provides methods to communicate with the host (hypervisor)
//! and the SEV-SNP firmware via a shared memory GHCB.

use crate::addr::SHIM_VIRT_OFFSET;
use crate::pagetables::{clear_c_bit_address_range, smash};
use crate::snp::secrets_page::SECRETS;
use crate::snp::{pvalidate, ByteSized, PvalidateSize};
use crate::spin::{Locked, RacyCell, RwLocked};

use core::arch::asm;
use core::mem::size_of;
use core::ptr;

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use bitflags::bitflags;
use const_default::ConstDefault;
use sallyport::libc::{EINVAL, EIO};
use spin::Lazy;
use x86_64::registers::model_specific::Msr;
use x86_64::structures::paging::{Page, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

/// The GHCB MSR
pub struct GhcbMsr;

impl GhcbMsr {
    /// The underlying model specific register.
    pub const MSR: Msr = Msr::new(0xC001_0130);

    const GPA_REQ: u64 = 0x12;
    const GPA_RESP: u64 = 0x13;
    const PSC_REQ: u64 = 0x14;
    const PSC_RESP: u64 = 0x15;

    /// Request an VM exit via the GHCB MSR protocol
    pub const EXIT_REQ: u64 = 0x100;

    const PSC_OP_POS: u64 = 52;
    const PSC_ERROR_POS: u64 = 32;
    const PSC_ERROR_MASK: u64 = u64::MAX >> Self::PSC_ERROR_POS;
}

const SNP_GUEST_MSG_PAYLOAD_LEN: usize = 4000;

/// Maximum length of an attestation report
pub const SNP_ATTESTATION_LEN_MAX: usize = SNP_GUEST_MSG_PAYLOAD_LEN;

#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
enum SnpMsgType {
    /*
       TypeInvalid = 0,
       CpuidReq,
       CpuidRsp,
    */
    KeyReq = 3,
    KeyRsp = 4,
    ReportReq = 5,
    ReportRsp = 6,
    /*
       ExportReq,
       ExportRsp,
       ImportReq,
       ImportRsp,
       AbsorbReq,
       AbsorbRsp,
       VmrkReq,
       VmrkRsp,
    */
}

#[derive(Copy, Clone)]
#[repr(u8)]
#[non_exhaustive]
enum AeadAlgo {
    // SnpAeadInvalid = 0,
    SnpAeadAes256Gcm = 1,
}

const MSG_HDR_VER: u8 = 1;

const MAX_AUTHTAG_LEN: usize = 32;

/// Header of a SnpGuestMsg
#[derive(Copy, Clone, Debug, ConstDefault)]
#[repr(C)]
pub struct SnpGuestMsgHdr {
    authtag: [u8; MAX_AUTHTAG_LEN],
    msg_seqno: u64,
    rsvd1: [u8; 8],
    algo: u8,
    hdr_version: u8,
    hdr_sz: u16,
    msg_type: u8,
    msg_version: u8,
    msg_sz: u16,
    rsvd2: u32,
    msg_vmpck: u8,
    rsvd3: [u8; 35],
}

impl Default for SnpGuestMsgHdr {
    fn default() -> Self {
        <Self as ConstDefault>::DEFAULT
    }
}

/// GHCB GUEST_REQUEST Message
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C, align(4096))]
pub struct SnpGuestMsg {
    hdr: SnpGuestMsgHdr,
    payload: [u8; SNP_GUEST_MSG_PAYLOAD_LEN],
}

impl Default for SnpGuestMsg {
    fn default() -> Self {
        <Self as ConstDefault>::DEFAULT
    }
}

/// SnpReport Request
#[repr(C)]
#[derive(Debug, Copy, Clone, ConstDefault)]
pub struct SnpReportRequest {
    /// Guest-provided data to be included into the attestation report
    pub report_data: [u8; 64],
    /// VMPL
    pub vmpl: u32,
    rsvd: [u8; 28],
}

impl Default for SnpReportRequest {
    fn default() -> Self {
        <Self as ConstDefault>::DEFAULT
    }
}

// SAFETY: SnpReportRequest is a C struct with no UD states and pointers.
unsafe impl ByteSized for SnpReportRequest {}

/// Header of the SnpReport Response
#[repr(C)]
pub struct SnpReportResponseHeader {
    /// 0 if valid
    pub status: u32,
    /// size of the report after this header
    pub size: u32,
    rsvd: [u8; 24],
}

// SAFETY: SnpReportResponseHeader is a C struct with no UD states and pointers.
unsafe impl ByteSized for SnpReportResponseHeader {}

/// GHCB page sizes
#[derive(Copy, Clone)]
#[repr(C)]
#[non_exhaustive]
enum RmpPgSize {
    Size4k = 0,
    // Size2m,
}

/// GHCB page operation
#[derive(Copy, Clone)]
#[repr(C)]
#[non_exhaustive]
enum RmpPgOp {
    // Private = 1,
    Shared = 2,
    // PSmash,
    // UnSmash,
}

/// GHCB page state entry
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C)]
pub struct PscEntry {
    entry: u64,
}

impl PscEntry {
    #[inline(always)]
    #[allow(clippy::integer_arithmetic)]
    fn set_entry(&mut self, cur_page: u64, operation: RmpPgOp, pagesize: RmpPgSize) {
        self.entry = cur_page | ((operation as u64) << 52) | ((pagesize as u64) << 56)
    }
}

/// GHCB page state description
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C)]
struct SnpPscDesc {
    pub cur_entry: u16,
    pub end_entry: u16,
    pub reserved: u32,
    pub entries: [PscEntry; 253],
}

/// GHCB Save Area
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C, packed)]
pub struct GhcbSaveArea {
    reserved1: [u8; 203],
    cpl: u8,
    reserved8: [u8; 300],
    rax: u64,
    reserved4: [u8; 264],
    rcx: u64,
    rdx: u64,
    rbx: u64,
    reserved5: [u8; 112],
    sw_exit_code: u64,
    sw_exit_info1: u64,
    sw_exit_info2: u64,
    sw_scratch: u64,
    reserved6: [u8; 56],
    xcr0: u64,
    valid_bitmap: [u8; 16],
    x87state_gpa: u64,
    reserved7: [u8; 1016],
}

/// GHCB
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C, align(4096))]
pub struct Ghcb {
    save_area: GhcbSaveArea,
    shared_buffer: [u8; 2032],
    reserved1: [u8; 10],
    protocol_version: u16,
    ghcb_usage: u32,
}

#[derive(Copy, Clone)]
#[non_exhaustive]
enum GhcbError {
    /// Unexpected state from the VMM
    VmmError,
    /// Instruction caused exception
    Exception,
}

/// make a page shared with the GHCB MSR Protocol
#[cfg_attr(coverage, no_coverage)]
fn ghcb_msr_make_page_shared(page_virt: VirtAddr) {
    // const SNP_PAGE_STATE_PRIVATE: u64 = 1;
    const SNP_PAGE_STATE_SHARED: u64 = 2;

    smash(page_virt).unwrap();

    pvalidate(page_virt, PvalidateSize::Size4K, false).unwrap();

    if clear_c_bit_address_range(page_virt, page_virt + Page::<Size4KiB>::SIZE).is_err() {
        unsafe {
            crate::debug::_early_debug_panic(4, 0x30);
        }
    }

    let gpa = page_virt - SHIM_VIRT_OFFSET;

    const SHARED_BIT: u64 = SNP_PAGE_STATE_SHARED << GhcbMsr::PSC_OP_POS;

    let val = gpa.as_u64() | SHARED_BIT;

    unsafe {
        let ret = vmgexit_msr(GhcbMsr::PSC_REQ, val, GhcbMsr::PSC_RESP);

        if (ret & GhcbMsr::PSC_ERROR_MASK) != 0 {
            crate::debug::_early_debug_panic(4, 0x33);
        }
    }
}

/// SNP vmgexit with the GHCB MSR Protocol
///
/// # Safety
/// Unknown request codes can trigger exceptions
#[cfg_attr(coverage, no_coverage)]
#[inline(always)]
pub unsafe fn vmgexit_msr(request_code: u64, value: u64, expected_response: u64) -> u64 {
    let val = request_code | value;

    let mut msr = GhcbMsr::MSR;

    msr.write(val);

    asm!("rep vmmcall", options(nostack));

    let retcode = msr.read();

    if expected_response != retcode & 0xFFF {
        crate::debug::_early_debug_panic(1, 2);
    }

    retcode & (!0xFFF)
}

/// A handle to the GHCB block
pub struct GhcbHandle<'a> {
    ghcb: &'a mut Ghcb,
}

#[cfg_attr(coverage, no_coverage)]
fn lazy_ghcb() -> RwLocked<GhcbHandle<'static>> {
    #[link_section = ".ghcb"]
    static GHCB: RacyCell<Ghcb> = RacyCell::new(<Ghcb as ConstDefault>::DEFAULT);

    // Safety: The above static `RacyCell` can only be accessed via the `RwLocked handle.
    let ghcb_mut_ref = unsafe { &mut *GHCB.get() };
    RwLocked::<GhcbHandle<'_>>::new(GhcbHandle::new(ghcb_mut_ref))
}

/// The global Enarx guest hypervisor communication block - GHCB
pub static GHCB: Lazy<RwLocked<GhcbHandle<'_>>> = Lazy::new(lazy_ghcb);

impl<'a> GhcbHandle<'a> {
    #[cfg_attr(coverage, no_coverage)]
    fn new(ghcb: &'a mut Ghcb) -> Self {
        let ghcb_virt = VirtAddr::from_ptr(ghcb);

        ghcb_msr_make_page_shared(ghcb_virt);

        unsafe {
            let gpa = (ghcb_virt - SHIM_VIRT_OFFSET).as_u64();

            let ret = vmgexit_msr(GhcbMsr::GPA_REQ, gpa, GhcbMsr::GPA_RESP);

            if ret != gpa {
                crate::debug::_early_debug_panic(4, 0x34);
            }
        }

        *ghcb = <Ghcb as ConstDefault>::DEFAULT;

        Self { ghcb }
    }

    /// do a vmgexit with the ghcb block
    ///
    /// # Safety
    /// undefined behaviour if not everything is setup according to the GHCB protocol
    #[cfg_attr(coverage, no_coverage)]
    unsafe fn vmgexit(
        &mut self,
        exit_code: u64,
        exit_info_1: u64,
        exit_info_2: u64,
    ) -> Result<(), GhcbError> {
        // const GHCB_PROTOCOL_MIN: u16 = 1;
        const GHCB_PROTOCOL_MAX: u16 = 2;
        const GHCB_DEFAULT_USAGE: u32 = 0;

        self.ghcb.save_area.sw_exit_code = exit_code;
        self.set_offset_valid(ptr::addr_of!(self.ghcb.save_area.sw_exit_code) as _);

        self.ghcb.save_area.sw_exit_info1 = exit_info_1;
        self.set_offset_valid(ptr::addr_of!(self.ghcb.save_area.sw_exit_info1) as _);

        self.ghcb.save_area.sw_exit_info2 = exit_info_2;
        self.set_offset_valid(ptr::addr_of!(self.ghcb.save_area.sw_exit_info2) as _);

        self.ghcb.ghcb_usage = GHCB_DEFAULT_USAGE;
        // FIXME: do protocol negotiation
        self.ghcb.protocol_version = GHCB_PROTOCOL_MAX;

        // prevent earlier writes from being moved beyond this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

        let gpa = (VirtAddr::from_ptr(self.ghcb) - SHIM_VIRT_OFFSET).as_u64();
        let mut msr = GhcbMsr::MSR;

        msr.write(gpa);

        asm!("rep vmmcall", options(nostack));

        // prevent later reads from being moved before this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

        if (self.ghcb.save_area.sw_exit_info1 & 0xffff_ffff) == 1 {
            const SVM_EVTINJ_VALID: u64 = 1 << 31;
            const SVM_EVTINJ_TYPE_SHIFT: u64 = 8;
            const SVM_EVTINJ_TYPE_MASK: u64 = 7 << SVM_EVTINJ_TYPE_SHIFT;
            const SVM_EVTINJ_TYPE_EXEPT: u64 = 3 << SVM_EVTINJ_TYPE_SHIFT;
            const SVM_EVTINJ_VEC_MASK: u64 = 0xff;
            const UD: u64 = 6;
            const GP: u64 = 13;

            // VmgExitErrorCheck, see
            // https://github.com/AMDESE/ovmf/blob/sev-snp-v6/OvmfPkg/Library/VmgExitLib/VmgExitLib.c
            // or linux kernel arch/x86/kernel/sev-shared.c
            let exit_info2 = self.ghcb.save_area.sw_exit_info2;
            let vector = exit_info2 & SVM_EVTINJ_VEC_MASK;

            if (exit_info2 & SVM_EVTINJ_VALID != 0)
                && (exit_info2 & SVM_EVTINJ_TYPE_MASK == SVM_EVTINJ_TYPE_EXEPT)
                && (vector == GP || vector == UD)
            {
                return Err(GhcbError::Exception);
            }

            Err(GhcbError::VmmError)
        } else {
            Ok(())
        }
    }

    /// clear all bits in the valid offset bitfield
    #[cfg_attr(coverage, no_coverage)]
    pub fn invalidate(&mut self) {
        self.ghcb.save_area.sw_exit_code = 0;
        self.ghcb
            .save_area
            .valid_bitmap
            .iter_mut()
            .for_each(|e| *e = 0);
    }

    /// set a bit in the valid offset bitfield
    pub fn set_offset_valid(&mut self, offset: usize) {
        let offset = offset.checked_sub(self.ghcb as *const _ as usize).unwrap();
        let offset = offset / 8;
        self.ghcb.save_area.valid_bitmap[offset / 8] |=
            1u8.checked_shl((offset & 0x7) as u32).unwrap();
    }
}

impl RwLocked<GhcbHandle<'_>> {
    /// GHCB IOIO_PROT
    #[cfg_attr(coverage, no_coverage)]
    pub fn do_io_out(&self, portnumber: u16, value: u16) {
        const IOIO_TYPE_OUT: u64 = 0;
        const IOIO_DATA_16: u64 = 1 << 5;
        const SVM_EXIT_IOIO_PROT: u64 = 0x7B;

        let mut this = self.write();

        this.invalidate();

        this.ghcb.save_area.rax = value as _;
        let offset: usize = ptr::addr_of!(this.ghcb.save_area.rax) as _;
        this.set_offset_valid(offset);

        unsafe {
            if this
                .vmgexit(
                    SVM_EXIT_IOIO_PROT,
                    IOIO_DATA_16 | IOIO_TYPE_OUT | ((portnumber as u64).checked_shl(16).unwrap()),
                    0,
                )
                .is_err()
            {
                crate::debug::_early_debug_panic(4, 0x10);
            }

            // FIXME: check error codes
        }
    }

    /// turn physical pages to decrypted / shared
    #[cfg_attr(coverage, no_coverage)]
    pub fn set_memory_shared(&self, virt_addr: VirtAddr, npages: usize) {
        const SVM_VMGEXIT_PSC: u64 = 0x80000010;

        (virt_addr.as_u64()
            ..(virt_addr + Page::<Size4KiB>::SIZE.checked_mul(npages as u64).unwrap()).as_u64())
            .step_by(Page::<Size4KiB>::SIZE as usize)
            .for_each(|a| {
                let virt = VirtAddr::new(a);
                smash(virt).unwrap();
                pvalidate(virt, PvalidateSize::Size4K, false).unwrap();
            });

        clear_c_bit_address_range(
            virt_addr,
            virt_addr + Page::<Size4KiB>::SIZE.checked_mul(npages as u64).unwrap(),
        )
        .unwrap();

        let mut this = self.write();

        // Fill in shared_buffer
        // SnpPscDesc has the exact same size.
        let psc_desc: &mut SnpPscDesc =
            unsafe { &mut *(this.ghcb.shared_buffer.as_mut_ptr() as *mut SnpPscDesc) };

        *psc_desc = <SnpPscDesc as ConstDefault>::DEFAULT;

        // FIXME
        assert!(psc_desc.entries.len() >= npages);

        psc_desc.cur_entry = 0;
        psc_desc.end_entry = (npages as u16).checked_sub(1).unwrap();

        let mut pa_addr = PhysAddr::new((virt_addr - SHIM_VIRT_OFFSET).as_u64());

        for i in 0..npages {
            psc_desc.entries[i].set_entry(pa_addr.as_u64(), RmpPgOp::Shared, RmpPgSize::Size4k);
            pa_addr += Page::<Size4KiB>::SIZE;
        }

        loop {
            // Use `read_volatile` to be safe
            let cur_entry = unsafe { ptr::addr_of!(psc_desc.cur_entry).read_volatile() };
            let end_entry = unsafe { ptr::addr_of!(psc_desc.end_entry).read_volatile() };

            if cur_entry > end_entry {
                break;
            }

            this.invalidate();

            let addr = ptr::addr_of!(this.ghcb.shared_buffer);
            this.ghcb.save_area.sw_scratch = (VirtAddr::from_ptr(addr) - SHIM_VIRT_OFFSET).as_u64();
            let offset: usize = ptr::addr_of!(this.ghcb.save_area.sw_scratch) as _;
            this.set_offset_valid(offset);

            unsafe {
                if this.vmgexit(SVM_VMGEXIT_PSC, 0, 0).is_err() {
                    crate::debug::_early_debug_panic(4, 0x33);
                }
            }

            if this.ghcb.save_area.sw_exit_info2 != 0 {
                unsafe {
                    crate::debug::_early_debug_panic(4, 0x34);
                }
            }
            if psc_desc.reserved != 0 {
                unsafe {
                    crate::debug::_early_debug_panic(4, 0x35);
                }
            }
            if (psc_desc.end_entry > end_entry) || (cur_entry > psc_desc.cur_entry) {
                unsafe {
                    crate::debug::_early_debug_panic(4, 0x36);
                }
            }
        }
    }

    /// GHCB GUEST_REQUEST
    ///
    /// # Safety
    /// undefined behaviour, if the parameters don't follow the GHCB protocol
    #[cfg_attr(coverage, no_coverage)]
    pub unsafe fn guest_req(&self, req_gpa: PhysAddr, resp_gpa: PhysAddr) -> Result<(), u64> {
        const SVM_VMGEXIT_GUEST_REQUEST: u64 = 0x80000011;

        let mut this = self.write();

        this.invalidate();

        this.vmgexit(
            SVM_VMGEXIT_GUEST_REQUEST,
            req_gpa.as_u64(),
            resp_gpa.as_u64(),
        )
        .map_err(|_| u64::MAX)?;

        if this.ghcb.save_area.sw_exit_info2 != 0 {
            Err(this.ghcb.save_area.sw_exit_info2)
        } else {
            Ok(())
        }
    }

    /// GHCB EXT_GUEST_REQUEST
    ///
    /// # Safety
    /// undefined behaviour, if the parameters don't follow the GHCB protocol
    #[cfg_attr(coverage, no_coverage)]
    pub unsafe fn guest_req_ext(
        &self,
        data_gpa: PhysAddr,
        num_pages: u64,
        req_gpa: PhysAddr,
        resp_gpa: PhysAddr,
    ) -> Result<(), u64> {
        const SVM_VMGEXIT_EXT_GUEST_REQUEST: u64 = 0x80000012;

        let mut this = self.write();

        this.invalidate();

        this.ghcb.save_area.rax = data_gpa.as_u64();
        let offset: usize = ptr::addr_of!(this.ghcb.save_area.rax) as _;
        this.set_offset_valid(offset);

        this.ghcb.save_area.rbx = num_pages;
        let offset: usize = ptr::addr_of!(this.ghcb.save_area.rbx) as _;
        this.set_offset_valid(offset);

        this.vmgexit(
            SVM_VMGEXIT_EXT_GUEST_REQUEST,
            req_gpa.as_u64(),
            resp_gpa.as_u64(),
        )
        .map_err(|_| u64::MAX)?;

        if this.ghcb.save_area.sw_exit_info2 != 0 {
            // FIXME: check for SNP_GUEST_REQ_INVALID_LEN == 0x100000000ULL
            // then extract expected number of pages in
            // this.ghcb.save_area.rbx if set
            Err(this.ghcb.save_area.sw_exit_info2)
        } else {
            Ok(())
        }
    }
}

/// A handle to the GHCB extended request
#[derive(Debug, ConstDefault)]
pub struct GhcbExtHandle {
    request: SnpGuestMsg,
    response: SnpGuestMsg,
}

impl Default for GhcbExtHandle {
    fn default() -> Self {
        <Self as ConstDefault>::DEFAULT
    }
}

#[cfg_attr(coverage, no_coverage)]
fn lazy_ghcb_ext() -> Locked<&'static mut GhcbExtHandle> {
    static GHCBEXTHANDLE: RacyCell<GhcbExtHandle> =
        RacyCell::new(<GhcbExtHandle as ConstDefault>::DEFAULT);

    let ghcb_ext_handle_mut = unsafe { &mut (*GHCBEXTHANDLE.get()) };
    ghcb_ext_handle_mut.init();
    Locked::<&mut GhcbExtHandle>::new(ghcb_ext_handle_mut)
}

/// The global Enarx GHCB Ext
///
/// # Safety
/// `GHCB_EXT` is the only way to get an instance of the static `GHCBEXTHANDLE`.
/// It is guarded by `RwLocked`.
pub static GHCB_EXT: Lazy<Locked<&mut GhcbExtHandle>> = Lazy::new(lazy_ghcb_ext);

impl GhcbExtHandle {
    #[cfg_attr(coverage, no_coverage)]
    fn init(&mut self) {
        let request_virt = VirtAddr::from_ptr(&self.request);

        GHCB.set_memory_shared(request_virt, 1);

        let response_virt = VirtAddr::from_ptr(&self.response);

        GHCB.set_memory_shared(response_virt, 1);
    }

    #[cfg_attr(coverage, no_coverage)]
    fn guest_req(&mut self) -> Result<(), u64> {
        let req_gpa =
            PhysAddr::new((VirtAddr::from_ptr(&self.request) - SHIM_VIRT_OFFSET).as_u64());

        self.response = <SnpGuestMsg as ConstDefault>::DEFAULT;

        let resp_gpa =
            PhysAddr::new((VirtAddr::from_ptr(&self.response) - SHIM_VIRT_OFFSET).as_u64());

        // prevent earlier writes from being moved beyond this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

        // SAFETY: request and response are valid and mapped to shared memory
        let ret = unsafe { GHCB.guest_req(req_gpa, resp_gpa) };

        // prevent later reads from being moved before this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

        if ret.is_ok() {
            SECRETS.inc_msg_seqno_0();
        }

        ret
    }

    fn enc_payload(
        &mut self,
        version: u8,
        msg_type: SnpMsgType,
        plaintext: &mut [u8],
    ) -> Result<(), ()> {
        let plaintext_size = plaintext.len();

        self.request.hdr.algo = AeadAlgo::SnpAeadAes256Gcm as _;
        self.request.hdr.hdr_version = MSG_HDR_VER;
        self.request.hdr.hdr_sz = size_of::<SnpGuestMsgHdr>() as _;
        self.request.hdr.msg_type = msg_type as _;
        self.request.hdr.msg_version = version;
        self.request.hdr.msg_seqno = SECRETS.get_msg_seqno_0() as _;
        self.request.hdr.msg_vmpck = 0;
        self.request.hdr.msg_sz = plaintext_size as _;

        let vmpck0 = SECRETS.get_vmpck0();

        let cipher = Aes256Gcm::new_from_slice(&vmpck0).unwrap();

        let mut seqno_nonce = [0u8; 12];
        seqno_nonce[0..8].copy_from_slice(unsafe {
            core::slice::from_raw_parts(&self.request.hdr.msg_seqno as *const _ as *const u8, 8)
        });

        let nonce = Nonce::from_slice(&seqno_nonce); // 96-bits; unique per message

        let asssoc_data = unsafe {
            core::slice::from_raw_parts(&self.request.hdr.algo as *const _ as *const u8, 48)
        };

        let tag = cipher
            .encrypt_in_place_detached(nonce, asssoc_data, plaintext)
            .map_err(|_| ())?;

        self.request.payload[0..plaintext_size].copy_from_slice(plaintext);

        self.request.hdr.authtag[0..16].copy_from_slice(&tag.as_slice()[0..16]);

        Ok(())
    }

    fn dec_payload(
        &mut self,
        plaintext: &mut [u8],
        expected_msg_type: SnpMsgType,
    ) -> Result<(), ()> {
        let payload_size = plaintext.len();

        let next_seqno = self.request.hdr.msg_seqno.checked_add(1).ok_or(())?;
        if next_seqno != self.response.hdr.msg_seqno {
            return Err(());
        }

        if expected_msg_type as u8 != self.response.hdr.msg_type {
            return Err(());
        }

        if self.request.hdr.msg_version != self.response.hdr.msg_version {
            return Err(());
        }

        if self.response.hdr.algo != AeadAlgo::SnpAeadAes256Gcm as _ {
            return Err(());
        }

        if self.response.hdr.hdr_sz != size_of::<SnpGuestMsgHdr>() as _ {
            return Err(());
        }

        if self.response.hdr.msg_vmpck != 0 {
            return Err(());
        }

        if self.response.hdr.msg_sz as usize > payload_size {
            return Err(());
        }

        let vmpck0 = SECRETS.get_vmpck0();
        let cipher = Aes256Gcm::new_from_slice(&vmpck0).unwrap();

        let mut seqno_nonce = [0u8; 12];
        seqno_nonce[0..8].copy_from_slice(unsafe {
            core::slice::from_raw_parts(&self.response.hdr.msg_seqno as *const _ as *const u8, 8)
        });

        let nonce = Nonce::from_slice(&seqno_nonce); // 96-bits; unique per message

        let asssoc_data = unsafe {
            core::slice::from_raw_parts(&self.response.hdr.algo as *const _ as *const u8, 48)
        };

        let tag = Tag::from_slice(&self.response.hdr.authtag[0..16]);

        plaintext[0..self.response.hdr.msg_sz as usize]
            .copy_from_slice(&self.response.payload[0..self.response.hdr.msg_sz as usize]);

        cipher
            .decrypt_in_place_detached(
                nonce,
                asssoc_data,
                &mut plaintext[0..self.response.hdr.msg_sz as usize],
                tag,
            )
            .expect("decrypt failed!");

        Ok(())
    }
}

/// SNP derived key length in bytes
pub const SNP_KEY_LEN: usize = 32;

#[repr(C)]
struct KeyRsp {
    /// 0 if valid
    status: u32,
    _rsvd: [u8; 28],
    derived_key: [u8; SNP_KEY_LEN],
}

#[repr(C)]
struct KeyReq {
    root_key_select: u32,
    _rsvd: u32,
    guest_field_select: u64,
    vmpl: u32,
    guest_svn: u32,
    tcb_version: u64,
}

// SAFETY: KeyRsp is a C struct with no UD states and pointers.
unsafe impl ByteSized for KeyRsp {}
// SAFETY: KeyReq is a C struct with no UD states and pointers.
unsafe impl ByteSized for KeyReq {}

bitflags! {
    /// Indicates which guest-selectable fields will be mixed into the derived key
    #[derive(Default)]
    pub struct GuestFieldSelect: u64 {
        /// Guest policy will be mixed into the key
        const GUEST_POLICY = 1;

        /// Image ID of the guest will be mixed into the key
        const IMAGE_ID = 1 << 1;

        /// Family ID of the guest will be mixed into the key
        const FAMILY_ID = 1 << 2;

        /// Measurement of the guest during launch will be mixed into the key
        const MEASUREMENT = 1 << 3;

        /// Guest-provided SVN will be mixed into the key
        const GUEST_SVN = 1 << 4;

        /// Guest-provided TCB_VERSION will be mixed into the key
        const TCB_VERSION = 1 << 5;
    }
}

impl Locked<&mut GhcbExtHandle> {
    /// Request a derived key
    pub fn get_key(&self, version: u8, guest_svn: u32) -> Result<[u8; 32], i32> {
        let mut this = self.lock();

        let key_req = KeyReq {
            root_key_select: 0,
            _rsvd: 0,
            guest_field_select: GuestFieldSelect::GUEST_SVN.bits
                | GuestFieldSelect::GUEST_POLICY.bits,
            vmpl: 0,
            guest_svn,
            tcb_version: 0,
        };

        this.request = <SnpGuestMsg as ConstDefault>::DEFAULT;

        let mut request = [0u8; KeyReq::SIZE];
        let mut response = [0u8; KeyRsp::SIZE];

        request.copy_from_slice(key_req.as_bytes());

        this.enc_payload(version, SnpMsgType::KeyReq, &mut request)
            .expect("encryption failed");

        this.guest_req().expect("request failed");

        this.dec_payload(&mut response, SnpMsgType::KeyRsp)
            .expect("decryption failed");

        let key_rsp = KeyRsp::from_bytes(&response).ok_or(EIO)?;

        match key_rsp.status {
            0 => Ok(key_rsp.derived_key),
            0x16 => Err(EIO),
            _ => panic!("invalid MSG_KEY_RSP error value {}", key_rsp.status),
        }
    }

    /// Get an attestation report via the GHCB shared page protocol
    pub fn get_report(
        &self,
        version: u8,
        nonce: &[u8],
        response: &mut [u8],
    ) -> Result<(usize, usize), i32> {
        if nonce.len() != 64 {
            return Err(EINVAL as _);
        }

        if response.len() < SNP_ATTESTATION_LEN_MAX {
            return Err(EINVAL as _);
        }

        let mut this = self.lock();
        let mut report_request = SnpReportRequest::default();
        report_request.report_data.copy_from_slice(nonce);

        let mut request = [0u8; SnpReportRequest::SIZE];
        request.copy_from_slice(report_request.as_bytes());

        this.request = <SnpGuestMsg as ConstDefault>::DEFAULT;

        this.enc_payload(version, SnpMsgType::ReportReq, &mut request)
            .expect("encryption failed");

        this.guest_req().expect("request failed");

        this.dec_payload(response, SnpMsgType::ReportRsp)
            .expect("decryption failed");

        if (this.response.hdr.msg_sz as usize) < size_of::<SnpReportResponseHeader>() {
            eprintln!("invalid report response size  {}", this.response.hdr.msg_sz);
            return Err(EIO);
        }

        let report =
            SnpReportResponseHeader::from_bytes(&response[..size_of::<SnpReportResponseHeader>()])
                .ok_or_else(|| {
                    eprintln!("invalid report response size from bytes");
                    EIO
                })?;

        match report.status {
            0 => Ok((size_of::<SnpReportResponseHeader>(), report.size as _)),
            0x16 => {
                eprintln!("report request status 0x16");
                Err(EIO)
            }
            _ => panic!("invalid MSG_REPORT_RSP error value {}", report.status),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use testaso::testaso;

    testaso! {
        struct SnpGuestMsgHdr: 8, 96 => {
            authtag:        0,
            msg_seqno:     32,
            algo:          48,
            hdr_version:   49,
            hdr_sz:        50,
            msg_type:      52,
            msg_version:   53,
            msg_sz:        54,
            msg_vmpck:     60
        }

        struct SnpGuestMsg: 4096, 4096 => {
            hdr:            0,
            payload:       96
        }

        struct Ghcb: 4096, 4096 => {
            save_area:          0x000,
            shared_buffer:      0x800,
            protocol_version:   0xFFA,
            ghcb_usage:         0xFFC
        }

        struct GhcbSaveArea: 1, 2048 => {
            cpl:            0x0CB,
            rax:            0x1F8,
            rcx:            0x308,
            rdx:            0x310,
            rbx:            0x318,
            sw_exit_code:   0x390,
            sw_exit_info1:  0x398,
            sw_exit_info2:  0x3A0,
            sw_scratch:     0x3A8,
            xcr0:           0x3E8,
            valid_bitmap:   0x3F0,
            x87state_gpa:   0x400
        }

        struct SnpPscDesc: 8, 2032 => {
            cur_entry:  0,
            end_entry:  2,
            entries:    8
        }

        struct SnpReportRequest: 4, 96 => {
            report_data: 0,
            vmpl: 64,
            rsvd: 68
        }
    }

    #[test]
    fn test_gcm() {
        use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};

        use std::mem::size_of;

        let mut request = <SnpGuestMsg as ConstDefault>::DEFAULT;
        let payload_size = 64;

        request.hdr.algo = AeadAlgo::SnpAeadAes256Gcm as _;
        request.hdr.hdr_version = MSG_HDR_VER;
        request.hdr.hdr_sz = size_of::<SnpGuestMsgHdr>() as _;
        request.hdr.msg_type = SnpMsgType::ReportReq as _;
        request.hdr.msg_version = 1;
        request.hdr.msg_seqno = 1;
        request.hdr.msg_vmpck = 0;
        request.hdr.msg_sz = payload_size;

        let vmpck0 = [
            194, 192, 39, 162, 189, 244, 162, 115, 12, 1, 241, 103, 225, 194, 186, 12, 79, 156, 98,
            186, 126, 75, 217, 65, 119, 135, 183, 107, 152, 18, 248, 41,
        ];

        let cipher = Aes256Gcm::new_from_slice(&vmpck0).unwrap();

        let mut seqno_nonce = [0u8; 12];
        let msg_seqno_ptr = &request.hdr.msg_seqno as *const _ as *const u8;
        seqno_nonce[0..8].copy_from_slice(unsafe { core::slice::from_raw_parts(msg_seqno_ptr, 8) });

        let nonce = Nonce::from_slice(&seqno_nonce); // 96-bits; unique per message

        let algo_ptr = &request.hdr.algo as *const _ as *const u8;
        let asssoc_data = unsafe { core::slice::from_raw_parts(algo_ptr, 48) };

        let payload_slice = &mut request.payload[0..payload_size as usize];
        let enc_res = cipher.encrypt_in_place_detached(nonce, asssoc_data, payload_slice);
        let tag = enc_res.expect("encrypt failed");

        request.hdr.authtag[0..16].copy_from_slice(&tag.as_slice()[0..16]);

        let mut plaintext = [0u8; 64];

        let tag = Tag::from_slice(&request.hdr.authtag[0..16]);

        let payload_slice = &request.payload[0..request.hdr.msg_sz as usize];
        plaintext[0..request.hdr.msg_sz as usize].copy_from_slice(payload_slice);

        let plain_slice = &mut plaintext[0..request.hdr.msg_sz as usize];
        let dec_ret = cipher.decrypt_in_place_detached(nonce, asssoc_data, plain_slice, tag);
        dec_ret.expect("decrypt failed!");
    }
}
