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
