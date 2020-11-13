// SPDX-License-Identifier: Apache-2.0

/// `get_attestation` syscall number
///
/// See https://github.com/enarx/enarx-keepldr/issues/31
#[allow(dead_code)]
pub const SYS_ENARX_GETATT: i64 = 0xEA01;

/// Enarx syscall extension: get `MemInfo` from the host
#[allow(dead_code)]
pub const SYS_ENARX_MEM_INFO: i64 = 0xEA02;

/// Enarx syscall extension: request an additional memory region
#[allow(dead_code)]
pub const SYS_ENARX_BALLOON_MEMORY: i64 = 0xEA03;

/// Enarx syscall extension: CPUID
#[allow(dead_code)]
pub const SYS_ENARX_CPUID: i64 = 0xEA04;

/// Enarx syscall extension: Resume an enclave after an asynchronous exit
// Keep in sync with shim-sgx/src/start.S
#[allow(dead_code)]
pub const SYS_ENARX_ERESUME: i64 = -1;

/// `get_attestation` technology return value
///
/// See https://github.com/enarx/enarx-keepldr/issues/31
#[allow(dead_code)]
pub const SEV_TECH: usize = 1;

/// `get_attestation` technology return value
///
/// See https://github.com/enarx/enarx-keepldr/issues/31
#[allow(dead_code)]
pub const SGX_TECH: usize = 2;

/// Size in bytes of expected SGX Quote
// TODO: Determine length of Quote of PCK cert type
#[allow(dead_code)]
pub const SGX_QUOTE_SIZE: usize = 512;

/// Size in bytes of expected SGX QE TargetInfo
#[allow(dead_code)]
pub const SGX_TI_SIZE: usize = 512;

/// Dummy value returned when daemon to return SGX TargetInfo is
/// not available on the system.
#[allow(dead_code)]
pub const SGX_DUMMY_TI: [u8; SGX_TI_SIZE] = [32u8; SGX_TI_SIZE];

/// Dummy value returned when daemon to return SGX Quote is not
/// available on the system.
#[allow(dead_code)]
pub const SGX_DUMMY_QUOTE: [u8; SGX_QUOTE_SIZE] = [44u8; SGX_QUOTE_SIZE];
