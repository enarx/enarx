// SPDX-License-Identifier: Apache-2.0

use crate::backend::parking::THREAD_PARK;
use crate::backend::sgx::attestation::{
    get_attestation_key_id, get_key_size, get_quote, get_quote_size, get_target_info,
};
use crate::backend::sgx::ioctls::{
    ModifyTypes, RemovePages, RestrictPermissions, ENCLAVE_MODIFY_TYPES, ENCLAVE_REMOVE_PAGES,
    ENCLAVE_RESTRICT_PERMISSIONS,
};
use crate::backend::{Command, Keep};

use std::arch::x86_64::CpuidResult;
use std::io;
use std::mem::{forget, size_of, MaybeUninit};
use std::sync::Arc;

use anyhow::Context;
use libc::{timespec, EAGAIN, EINVAL, PROT_READ};
use mmarinus::{perms, Map, Shared};
use sallyport::host::{deref_aligned, deref_slice};
use sallyport::item;
use sallyport::item::enarxcall::sgx::{Report, TargetInfo};
use sallyport::item::{enarxcall, Item};
use tracing::{error, trace_span};

pub(crate) fn sgx_enarxcall<'a>(
    enarxcall: &'a mut enarxcall::Payload,
    data: &'a mut [u8],
    keep: Arc<super::Keep>,
) -> anyhow::Result<Option<Item<'a>>> {
    match enarxcall {
        enarxcall::Payload {
            num: item::enarxcall::Number::Spawn,
            ret,
            ..
        } => {
            *ret = if let Some(mut thread) = keep.spawn()? {
                std::thread::spawn(move || {
                    trace_span!(
                        "Thread",
                        id = ?std::thread::current().id()
                    )
                    .in_scope(|| loop {
                        match thread.enter(&None)? {
                            Command::Continue => (),
                            Command::Exit(exit_code) => {
                                drop(thread);
                                return Ok::<i32, anyhow::Error>(exit_code);
                            }
                        }
                    })
                });
                0
            } else {
                error!("no more SGX threads available");
                -EAGAIN as usize
            };

            Ok(None)
        }
        item::Enarxcall {
            num: item::enarxcall::Number::Park,
            argv: [val, timeout, ..],
            ret,
            ..
        } => {
            let timeout = if *timeout != sallyport::NULL {
                Some(unsafe {
                    // Safety: `deref_aligned` gives us a pointer to an aligned `timespec` struct.
                    // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                    // is a subslice of.
                    (*deref_aligned::<MaybeUninit<timespec>>(data, *timeout, 1)
                        .map_err(io::Error::from_raw_os_error)
                        .context("sgx_enarxcall deref")?)
                    .assume_init()
                })
            } else {
                None
            };

            *ret = THREAD_PARK
                .park(*val as _, timeout.as_ref())
                .map(|v| v as usize)
                .unwrap_or_else(|e| -e as usize);

            Ok(None)
        }
        item::Enarxcall {
            num: item::enarxcall::Number::UnPark,
            ret,
            ..
        } => {
            THREAD_PARK.unpark();
            *ret = 0;
            Ok(None)
        }
        item::Enarxcall {
            num: item::enarxcall::Number::Cpuid,
            argv: [leaf, subleaf, cpuid_offset, ..],
            ret,
        } => {
            let cpuid_buf = unsafe {
                // Safety: `deref_aligned` gives us a pointer to an aligned `CpuidResult` struct.
                // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                // is a subslice of.
                &mut *deref_aligned::<MaybeUninit<CpuidResult>>(data, *cpuid_offset, 1)
                    .map_err(io::Error::from_raw_os_error)
                    .context("sgx_enarxcall deref")?
            };

            // Safety: we know we are on an SGX machine, which can do cpuid
            let cpuid_ret = unsafe { core::arch::x86_64::__cpuid_count(*leaf as _, *subleaf as _) };

            cpuid_buf.write(cpuid_ret);
            *ret = 0;
            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::GetSgxTargetInfo,
            argv: [target_info_offset, ..],
            ret,
        } => {
            let out_buf = unsafe {
                // Safety: `deref_slice` gives us a pointer to a byte slice, which does not have to be aligned.
                // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                // is a subslice of.
                &mut *deref_slice::<u8>(data, *target_info_offset, size_of::<TargetInfo>())
                    .map_err(io::Error::from_raw_os_error)
                    .context("sgx_enarxcall deref")?
            };
            let akid = get_attestation_key_id().context(
                "Error obtaining attestation key id. Check your aesmd / pccs service installation.",
            )?;
            let pkeysize = get_key_size(akid.clone()).context(
                "Error obtaining key size. Check your aesmd / pccs service installation.",
            )?;
            *ret = get_target_info(akid, pkeysize, out_buf).context(
                "Error getting target info. Check your aesmd / pccs service installation.",
            )?;

            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::GetSgxQuote,
            argv: [report_offset, quote_offset, quote_len, ..],
            ret,
        } => {
            let report_buf = unsafe {
                // Safety: `deref_slice` gives us a pointer to a byte slice, which does not have to be aligned.
                // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                // is a subslice of.
                &mut *deref_slice::<u8>(data, *report_offset, size_of::<Report>())
                    .map_err(io::Error::from_raw_os_error)
                    .context("sgx_enarxcall deref")?
            };

            let quote_buf = unsafe {
                // Safety: `deref_slice` gives us a pointer to a byte slice, which does not have to be aligned.
                // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                // is a subslice of.
                &mut *deref_slice::<u8>(data, *quote_offset, *quote_len)
                    .map_err(io::Error::from_raw_os_error)
                    .context("sgx_enarxcall deref")?
            };

            let akid = get_attestation_key_id().context(
                "Error obtaining attestation key id. Check your aesmd / pccs service installation.",
            )?;
            *ret = get_quote(report_buf, akid, quote_buf)
                .context("Error getting quote. Check your aesmd / pccs service installation.")?;

            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::GetSgxQuoteSize,
            ret,
            ..
        } => {
            let akid = get_attestation_key_id().context(
                "Error obtaining attestation key id. Check your aesmd / pccs service installation.",
            )?;
            *ret = get_quote_size(akid).context(
                "Error getting quote size. Check your aesmd / pccs service installation.",
            )?;

            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::MmapHost,
            argv: [addr, len, prot, ..],
            ret,
            ..
        } => {
            // Safety: an `mmap()` call is pointed to a file descriptor of the
            // created enclave, and can therefore only affect the memory
            // mappings within the address range given to ENCLAVE_CREATE.
            match unsafe {
                Map::bytes(*len)
                    .onto(*addr)
                    .from(&mut keep.enclave.try_clone().unwrap(), 0)
                    .with_kind(Shared)
                    .with(perms::Unknown(*prot as i32))
            } {
                Ok(map) => {
                    // Skip `drop()`. The VMA's ownership has been moved to the shim.
                    forget(map);
                    *ret = 0;
                }
                Err(err) => {
                    *ret = (-err.err.raw_os_error().unwrap()) as usize;
                }
            };
            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::MprotectHost,
            argv: [addr, len, prot, ..],
            ret,
            ..
        } => {
            let mem_end = keep.mem.addr() + keep.mem.size();
            let end = *addr + *len;

            // Check that the span is within the enclave address range:
            if *addr < keep.mem.addr() || end > mem_end {
                *ret = EINVAL as _;
                return Ok(None);
            }

            // Safety: the parameters have been verified to be within the shim's
            // address range.
            if unsafe { libc::mprotect(*addr as _, *len, *prot as i32) } != 0 {
                *ret = (-io::Error::last_os_error().raw_os_error().unwrap()) as _;
                return Ok(None);
            }

            // TODO: https://github.com/enarx/enarx/issues/1892
            let mut parameters =
                RestrictPermissions::new(*addr - keep.mem.addr(), *len, PROT_READ as _);
            ENCLAVE_RESTRICT_PERMISSIONS
                .ioctl(&mut keep.enclave.try_clone().unwrap(), &mut parameters)
                .context("ENCLAVE_RESTRICT_PERMISSIONS failed")?;

            *ret = 0;
            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::MunmapHost,
            argv: [addr, len, ..],
            ret,
            ..
        } => {
            let mem_end = keep.mem.addr() + keep.mem.size();
            let end = *addr + *len;

            // Check that the span is within the enclave address range:
            if *addr < keep.mem.addr() || end > mem_end {
                panic!("munmap() is out of range");
            }

            // Safety: the parameters have been sanity checked before, that only
            // enclave memory is unmapped.
            unsafe {
                libc::munmap(*addr as *mut _, *len);
            }

            let mut parameters = RemovePages::new(*addr - keep.mem.addr(), *len);
            ENCLAVE_REMOVE_PAGES
                .ioctl(&mut keep.enclave.try_clone().unwrap(), &mut parameters)
                .context("ENCLAVE_REMOVE_PAGES failed")?;

            *ret = 0;
            Ok(None)
        }

        item::Enarxcall {
            num: item::enarxcall::Number::TrimSgxPages,
            argv: [addr, length, ..],
            ret,
            ..
        } => {
            let mut parameters = ModifyTypes::new(*addr - keep.mem.addr(), *length, 4);
            ENCLAVE_MODIFY_TYPES
                .ioctl(&mut keep.enclave.try_clone().unwrap(), &mut parameters)
                .context("ENCLAVE_MODIFY_TYPES failed")?;
            *ret = 0;
            Ok(None)
        }

        _ => return Ok(Some(Item::Enarxcall(enarxcall, data))),
    }
}
