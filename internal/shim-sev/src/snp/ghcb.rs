// SPDX-License-Identifier: Apache-2.0

//! GHCB

// FIXME: https://github.com/enarx/enarx/issues/991
#![allow(missing_docs)]
#![allow(clippy::result_unit_err)]

use crate::addr::SHIM_VIRT_OFFSET;
use crate::pagetables::{clear_c_bit_address_range, smash};
use crate::snp::secrets_page::SECRETS;
use crate::snp::{pvalidate, PvalidateSize};
use crate::spin::RwLocked;
use crate::_ENARX_GHCB;

use core::mem::size_of;
use core::ptr;

use aes_gcm::AeadInPlace;
use aes_gcm::NewAead;
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use const_default::ConstDefault;
use spinning::Lazy;
use x86_64::registers::model_specific::Msr;
use x86_64::structures::paging::{Page, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

pub const SEV_GHCB_MSR: u32 = 0xc001_0130u32;

pub const GHCB_MSR_GPA_REQ: u64 = 0x12;
pub const GHCB_MSR_GPA_RESP: u64 = 0x13;
pub const GHCB_MSR_PSC_REQ: u64 = 0x14;
pub const GHCB_MSR_PSC_RESP: u64 = 0x15;

pub const GHCB_MSR_EXIT_REQ: u64 = 0x100;

pub const GHCB_MSR_PSC_OP_POS: u64 = 52;
pub const GHCB_MSR_PSC_GFN_POS: u64 = 12;
pub const GHCB_MSR_PSC_ERROR_POS: u64 = 32;

pub const SNP_PAGE_STATE_PRIVATE: u64 = 1;
pub const SNP_PAGE_STATE_SHARED: u64 = 2;

pub const GHCB_PROTOCOL_MIN: u16 = 1;
pub const GHCB_PROTOCOL_MAX: u16 = 2;
pub const GHCB_DEFAULT_USAGE: u32 = 0;

pub const IOIO_TYPE_OUT: u64 = 0;
pub const IOIO_DATA_16: u64 = 1 << 5;
pub const SVM_EXIT_IOIO_PROT: u64 = 0x7B;

pub const SVM_VMGEXIT_PSC: u64 = 0x80000010;
pub const SVM_VMGEXIT_GUEST_REQUEST: u64 = 0x80000011;
pub const SVM_VMGEXIT_EXT_GUEST_REQUEST: u64 = 0x80000012;

#[derive(Copy, Clone)]
#[repr(u8)]
#[non_exhaustive]
pub enum SnpMsgType {
    TypeInvalid = 0,
    CpuidReq,
    CpuidRsp,
    KeyReq,
    KeyRsp,
    ReportReq,
    ReportRsp,
    ExportReq,
    ExportRsp,
    ImportReq,
    ImportRsp,
    AbsorbReq,
    AbsorbRsp,
    VmrkReq,
    VmrkRsp,
}

#[derive(Copy, Clone)]
#[repr(u8)]
#[non_exhaustive]
pub enum AeadAlgo {
    SnpAeadInvalid = 0,
    SnpAeadAes256Gcm,
}

pub const AAD_LEN: usize = 48;
pub const MSG_HDR_VER: u8 = 1;

pub const MAX_AUTHTAG_LEN: usize = 32;

/// Header of a SnpGuestMsg
#[derive(Copy, Clone, Debug, ConstDefault)]
#[repr(C)]
pub struct SnpGuestMsgHdr {
    pub authtag: [u8; MAX_AUTHTAG_LEN],
    pub msg_seqno: u64,
    rsvd1: [u8; 8],
    pub algo: u8,
    pub hdr_version: u8,
    pub hdr_sz: u16,
    pub msg_type: u8,
    pub msg_version: u8,
    pub msg_sz: u16,
    rsvd2: u32,
    pub msg_vmpck: u8,
    rsvd3: [u8; 35],
}

impl Default for SnpGuestMsgHdr {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// GHCB GUEST_REQUEST Message
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C, align(4096))]
pub struct SnpGuestMsg {
    pub hdr: SnpGuestMsgHdr,
    pub payload: [u8; 4000],
}

impl Default for SnpGuestMsg {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// GHCB page sizes
#[derive(Copy, Clone)]
#[repr(C)]
#[non_exhaustive]
pub enum RmpPgSize {
    Size4k = 0,
    Size2m,
}

/// GHCB page operation
#[derive(Copy, Clone)]
#[repr(C)]
#[non_exhaustive]
pub enum RmpPgOp {
    Private = 1,
    Shared,
    PSmash,
    UnSmash,
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
    pub fn set_entry(&mut self, cur_page: u64, operation: RmpPgOp, pagesize: RmpPgSize) {
        self.entry = cur_page | ((operation as u64) << 52) | ((pagesize as u64) << 56)
    }
}

pub const VMGEXIT_PSC_MAX_ENTRY: usize = 253;

/// GHCB page state description
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C)]
pub struct SnpPscDesc {
    pub cur_entry: u16,
    pub end_entry: u16,
    pub reserved: u32,
    pub entries: [PscEntry; VMGEXIT_PSC_MAX_ENTRY],
}

/// GHCB Save Area
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C, packed)]
pub struct GhcbSaveArea {
    reserved1: [u8; 203],
    pub cpl: u8,
    reserved8: [u8; 300],
    pub rax: u64,
    reserved4: [u8; 264],
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    reserved5: [u8; 112],
    pub sw_exit_code: u64,
    pub sw_exit_info1: u64,
    pub sw_exit_info2: u64,
    pub sw_scratch: u64,
    reserved6: [u8; 56],
    pub xcr0: u64,
    pub valid_bitmap: [u8; 16],
    pub x87state_gpa: u64,
    reserved7: [u8; 1016],
}

/// GHCB
#[derive(Debug, Copy, Clone, ConstDefault)]
#[repr(C, align(4096))]
pub struct Ghcb {
    pub save_area: GhcbSaveArea,
    pub shared_buffer: [u8; 2032],
    reserved1: [u8; 10],
    pub protocol_version: u16,
    pub ghcb_usage: u32,
}

/// make a page shared with the GHCB MSR Protocol
fn ghcb_msr_make_page_shared(page_virt: VirtAddr) {
    smash(page_virt).unwrap();

    unsafe { pvalidate(page_virt, PvalidateSize::Size4K, false).unwrap() };

    if clear_c_bit_address_range(page_virt, page_virt + Page::<Size4KiB>::SIZE).is_err() {
        unsafe {
            crate::debug::_early_debug_panic(4, 0x30);
        }
    }

    let gpa = page_virt - SHIM_VIRT_OFFSET;

    const SHARED_BIT: u64 = SNP_PAGE_STATE_SHARED << GHCB_MSR_PSC_OP_POS;

    let val = gpa.as_u64() | SHARED_BIT;

    unsafe {
        let ret = vmgexit_msr(GHCB_MSR_PSC_REQ, val, GHCB_MSR_PSC_RESP);

        const GHCB_MSR_PSC_ERROR_MASK: u64 = u64::MAX >> GHCB_MSR_PSC_ERROR_POS;

        if (ret & GHCB_MSR_PSC_ERROR_MASK) != 0 {
            crate::debug::_early_debug_panic(4, 0x33);
        }
    }
}

/// SNP vmgexit with the GHCB MSR Protocol
///
/// # Safety
/// Unknown request codes can trigger exceptions
#[inline(always)]
pub unsafe fn vmgexit_msr(request_code: u64, value: u64, expected_response: u64) -> u64 {
    let val = request_code | value;

    let mut msr: Msr = Msr::new(SEV_GHCB_MSR);

    msr.write(val);

    asm!("rep vmmcall", options(nostack));

    let retcode = msr.read();

    if expected_response != retcode & 0xFFF {
        crate::debug::_early_debug_panic(1, 2);
    }

    retcode & (!0xFFF)
}

/// A handle to the GHCB block
pub struct GhcbHandle {
    ghcb: &'static mut Ghcb,
}

/// The global Enarx GHCB
pub static GHCB: Lazy<RwLocked<GhcbHandle>> =
    Lazy::new(|| RwLocked::<GhcbHandle>::new(GhcbHandle::new(unsafe { &mut _ENARX_GHCB })));

impl GhcbHandle {
    fn new(ghcb: &'static mut Ghcb) -> Self {
        let ghcb_virt = VirtAddr::from_ptr(ghcb);

        ghcb_msr_make_page_shared(ghcb_virt);

        unsafe {
            let gpa = (ghcb_virt - SHIM_VIRT_OFFSET).as_u64();

            let ret = vmgexit_msr(GHCB_MSR_GPA_REQ, gpa, GHCB_MSR_GPA_RESP);

            if ret != gpa {
                crate::debug::_early_debug_panic(4, 0x34);
            }
        }

        *ghcb = Ghcb::DEFAULT;

        Self { ghcb }
    }

    /// do a vmgexit with the ghcb block
    ///
    /// # Safety
    /// undefined behaviour if not everything is setup according to the GHCB protocol
    pub unsafe fn vmgexit(
        &mut self,
        exit_code: u64,
        exit_info_1: u64,
        exit_info_2: u64,
    ) -> Result<(), ()> {
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

        let mut msr: Msr = Msr::new(SEV_GHCB_MSR);
        let gpa = (VirtAddr::from_ptr(self.ghcb) - SHIM_VIRT_OFFSET).as_u64();
        msr.write(gpa);

        asm!("rep vmmcall", options(nostack));

        // prevent later reads from being moved before this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

        if (self.ghcb.save_area.sw_exit_info1 & 0xffffffff) == 1 {
            // FIXME: add VmgExitErrorCheck
            // https://github.com/AMDESE/ovmf/blob/sev-snp-v6/OvmfPkg/Library/VmgExitLib/VmgExitLib.c
            // or linux kernel arch/x86/kernel/sev-shared.c
            Err(())
        } else {
            Ok(())
        }
    }

    /// clear all bits in the valid offset bitfield
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

impl RwLocked<GhcbHandle> {
    /// GHCB IOIO_PROT
    pub fn do_io_out(&self, portnumber: u16, value: u16) {
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
    pub fn set_memory_shared(&self, virt_addr: VirtAddr, npages: usize) {
        (virt_addr.as_u64()
            ..(virt_addr + Page::<Size4KiB>::SIZE.checked_mul(npages as u64).unwrap()).as_u64())
            .step_by(Page::<Size4KiB>::SIZE as usize)
            .for_each(|a| {
                let virt = VirtAddr::new(a);
                smash(virt).unwrap();
                unsafe { pvalidate(virt, PvalidateSize::Size4K, false).unwrap() };
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

        *psc_desc = SnpPscDesc::DEFAULT;

        // FIXME
        assert!(VMGEXIT_PSC_MAX_ENTRY >= npages);

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
    pub unsafe fn guest_req(&self, req_gpa: PhysAddr, resp_gpa: PhysAddr) -> Result<(), u64> {
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
    pub unsafe fn guest_req_ext(
        &self,
        data_gpa: PhysAddr,
        num_pages: u64,
        req_gpa: PhysAddr,
        resp_gpa: PhysAddr,
    ) {
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
        .unwrap();
    }
}

/// A handle to the GHCB extended
#[derive(Debug, ConstDefault)]
pub struct GhcbExtHandle {
    request: SnpGuestMsg,
    response: SnpGuestMsg,
}

impl Default for GhcbExtHandle {
    fn default() -> Self {
        Self::DEFAULT
    }
}

static mut GHCBEXTHANDLE: GhcbExtHandle = GhcbExtHandle::DEFAULT;

/// The global Enarx GHCB Ext
pub static GHCB_EXT: Lazy<RwLocked<&mut GhcbExtHandle>> = Lazy::new(|| unsafe {
    GHCBEXTHANDLE.init();
    RwLocked::<&mut GhcbExtHandle>::new(&mut GHCBEXTHANDLE)
});

impl GhcbExtHandle {
    fn init(&mut self) {
        let request_virt = VirtAddr::from_ptr(&self.request);

        GHCB.set_memory_shared(request_virt, 1);
        //ghcb_msr_make_page_shared(request_virt);

        let response_virt = VirtAddr::from_ptr(&self.response);

        GHCB.set_memory_shared(response_virt, 1);
        //ghcb_msr_make_page_shared(response_virt);
    }

    unsafe fn guest_req(&mut self) -> Result<(), u64> {
        let req_gpa =
            PhysAddr::new((VirtAddr::from_ptr(&self.request) - SHIM_VIRT_OFFSET).as_u64());

        self.response = SnpGuestMsg::DEFAULT;

        let resp_gpa =
            PhysAddr::new((VirtAddr::from_ptr(&self.response) - SHIM_VIRT_OFFSET).as_u64());

        // prevent earlier writes from being moved beyond this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

        let ret = GHCB.guest_req(req_gpa, resp_gpa);

        // prevent later reads from being moved before this point
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

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

        let key = Key::from_slice(&vmpck0);
        let cipher = Aes256Gcm::new(key);

        let mut seqno_nonce = [0u8; 12];
        seqno_nonce[0..8].copy_from_slice(unsafe {
            core::slice::from_raw_parts(&self.request.hdr.msg_seqno as *const _ as *const u8, 8)
        });

        let nonce = Nonce::from_slice(&seqno_nonce); // 96-bits; unique per message

        let asssoc_data = unsafe {
            core::slice::from_raw_parts(&self.request.hdr.algo as *const _ as *const u8, 48)
        };

        //FIXME: don't use the shared memory for plaintext

        let tag = cipher
            .encrypt_in_place_detached(nonce, asssoc_data, plaintext)
            .map_err(|_| ())?;

        self.request.payload[0..plaintext_size].copy_from_slice(plaintext);

        self.request.hdr.authtag[0..16].copy_from_slice(&tag.as_slice()[0..16]);

        Ok(())
    }

    fn dec_payload(&mut self, plaintext: &mut [u8]) -> Result<(), ()> {
        let payload_size = plaintext.len();

        // FIXME
        #[allow(clippy::integer_arithmetic)]
        if self.request.hdr.msg_seqno + 1 != self.response.hdr.msg_seqno {
            return Err(());
        }

        // FIXME
        #[allow(clippy::integer_arithmetic)]
        if self.request.hdr.msg_type + 1 != self.response.hdr.msg_type {
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
        let key = Key::from_slice(&vmpck0);
        let cipher = Aes256Gcm::new(key);

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

impl RwLocked<&mut GhcbExtHandle> {
    /// FIXME: doc
    pub fn get_report(
        &self,
        version: u8,
        user_data: &[u8; 64],
        response: &mut [u8; 4000],
    ) -> Result<(), u64> {
        let mut this = self.write();

        let mut user_data = *user_data;

        this.request = SnpGuestMsg::DEFAULT;

        this.enc_payload(version, SnpMsgType::ReportReq, &mut user_data)
            .expect("encryption failed");

        unsafe {
            this.guest_req().expect("request failed");
        }

        this.dec_payload(response).expect("decryption failed");

        let resp_slice =
            unsafe { core::slice::from_raw_parts(&this.response as *const _ as *const u8, 4000) };

        response.copy_from_slice(resp_slice);
        Ok(())
    }

    /// FIXME: doc
    pub fn get_key(&self, version: u8, response: &mut [u8; 4000]) -> Result<(), u64> {
        let mut this = self.write();

        this.request = SnpGuestMsg::DEFAULT;

        let mut user_data = [0u8; 24];

        this.enc_payload(version, SnpMsgType::KeyReq, &mut user_data)
            .expect("encryption failed");

        unsafe {
            this.guest_req().expect("request failed");
        }

        this.dec_payload(response).expect("decryption failed");

        let resp_slice =
            unsafe { core::slice::from_raw_parts(&this.response as *const _ as *const u8, 4000) };

        response.copy_from_slice(resp_slice);
        Ok(())
    }
}

#[cfg(test)]
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
}

#[cfg(test)]
#[test]
fn test_gcm() {
    use aes_gcm::AeadInPlace;
    use aes_gcm::NewAead;
    use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
    use std::mem::size_of;

    let mut request = SnpGuestMsg::DEFAULT;
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

    let key = Key::from_slice(&vmpck0);
    let cipher = Aes256Gcm::new(key);

    let mut seqno_nonce = [0u8; 12];
    seqno_nonce[0..8].copy_from_slice(unsafe {
        core::slice::from_raw_parts(&request.hdr.msg_seqno as *const _ as *const u8, 8)
    });

    let nonce = Nonce::from_slice(&seqno_nonce); // 96-bits; unique per message

    let asssoc_data =
        unsafe { core::slice::from_raw_parts(&request.hdr.algo as *const _ as *const u8, 48) };

    let tag = cipher
        .encrypt_in_place_detached(
            nonce,
            asssoc_data,
            &mut request.payload[0..payload_size as usize],
        )
        .expect("encrypt failed");

    request.hdr.authtag[0..16].copy_from_slice(&tag.as_slice()[0..16]);

    let mut plaintext = [0u8; 64];

    let tag = Tag::from_slice(&request.hdr.authtag[0..16]);

    plaintext[0..request.hdr.msg_sz as usize]
        .copy_from_slice(&request.payload[0..request.hdr.msg_sz as usize]);

    cipher
        .decrypt_in_place_detached(
            nonce,
            asssoc_data,
            &mut plaintext[0..request.hdr.msg_sz as usize],
            &tag,
        )
        .expect("decrypt failed!");
}
