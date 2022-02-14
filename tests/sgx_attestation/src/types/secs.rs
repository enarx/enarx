// SPDX-License-Identifier: Apache-2.0

//! SECS (Section 38.7)
//! The SGX Enclave Control Structure (SECS) is a special enclave page that is not
//! visible in the address space. In fact, this structure defines the address
//! range and other global attributes for the enclave and it is the first EPC
//! page created for any enclave. It is moved from a temporary buffer to an EPC
//! by the means of ENCLS(ECREATE) leaf.

use super::{attr, isv, misc::MiscSelect};
use core::num::NonZeroU32;

/// Section 38.7
#[derive(Copy, Clone, Debug)]
#[repr(C, align(4096))]
pub struct Secs {
    size: u64,
    baseaddr: u64,
    ssaframesize: NonZeroU32,
    miscselect: MiscSelect,
    reserved0: [u8; 24],
    attributes: attr::Attributes,
    mrenclave: [u8; 32],
    reserved1: [u8; 32],
    mrsigner: [u8; 32],
    reserved2: [u64; 12],
    isv_prod_id: isv::ProdId,
    isv_svn: isv::Svn,
    reserved3: [u32; 7],
    reserved4: [[u64; 28]; 17],
}

#[cfg(test)]
testaso! {
    struct Secs: 4096, 4096 => {
        size: 0,
        baseaddr: 8,
        ssaframesize: 16,
        miscselect: 20,
        reserved0: 24,
        attributes: 48,
        mrenclave: 64,
        reserved1: 96,
        mrsigner: 128,
        reserved2: 160,
        isv_prod_id: 256,
        isv_svn: 258,
        reserved3: 260,
        reserved4: 288
    }
}
