// SPDX-License-Identifier: Apache-2.0

//! This module implements Intel SGX-related IOCTLs using the iocuddle crate.
//! All references to Section or Tables are from
//! [Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 3D: System Programming Guide, Part 4](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf)

#![allow(dead_code)]

use std::marker::PhantomData;
use std::sync::Mutex;
use std::time;
use std::{fs, io};

use iocuddle::*;
use sgx::page::{SecInfo, Secs};
use sgx::signature::Signature;
use tracing::debug;

const SGX: Group = Group::new(0xA4);

/// IOCTL identifier for ECREATE (see Section 41-21)
pub const ENCLAVE_CREATE: Ioctl<Write, &Create<'_>> = unsafe { SGX.write(0x00) };

/// IOCTL identifier for EADD (see Section 41-11)
pub const ENCLAVE_ADD_PAGES: Ioctl<WriteRead, &AddPages<'_>> = unsafe { SGX.write_read(0x01) };

/// IOCTL identifier for EINIT (see Section 41-35)
pub const ENCLAVE_INIT: Ioctl<Write, &Init<'_>> = unsafe { SGX.write(0x02) };

pub const ENCLAVE_SET_ATTRIBUTE: Ioctl<Write, &SetAttribute<'_>> = unsafe { SGX.write(0x03) };

/// SGX_IOC_VEPC_REMOVE_ALL (0x04) is not used by Enarx.

/// SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS
pub const ENCLAVE_RESTRICT_PERMISSIONS: Ioctl<WriteRead, &RestrictPermissions> =
    unsafe { SGX.write_read(0x05) };

/// SGX_IOC_ENCLAVE_MODIFY_TYPES
pub const ENCLAVE_MODIFY_TYPES: Ioctl<WriteRead, &ModifyTypes> = unsafe { SGX.write_read(0x06) };

/// SGX_IOC_ENCLAVE_REMOVE_PAGES
pub const ENCLAVE_REMOVE_PAGES: Ioctl<WriteRead, &RemovePages> = unsafe { SGX.write_read(0x07) };

#[repr(C)]
#[derive(Debug)]
/// Struct for creating a new enclave from SECS
pub struct Create<'a>(u64, PhantomData<&'a ()>);

impl<'a> Create<'a> {
    /// A new Create struct wraps an SECS struct from the sgx-types crate.
    pub fn new(secs: &'a Secs) -> Self {
        Create(secs as *const _ as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
/// Struct for adding pages to an enclave
pub struct AddPages<'a> {
    src: u64,
    offset: u64,
    length: u64,
    secinfo: u64,
    flags: u64,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> AddPages<'a> {
    /// Creates a new AddPages struct for a page at a certain offset
    pub fn new(bytes: &'a [u8], offset: usize, secinfo: &'a SecInfo, measure: bool) -> Self {
        const MEASURE: u64 = 1 << 0;

        let flags = match measure {
            true => MEASURE,
            false => 0,
        };

        Self {
            src: bytes.as_ptr() as _,
            offset: offset as _,
            length: bytes.len() as _,
            secinfo: secinfo as *const _ as _,
            flags,
            count: 0,
            phantom: PhantomData,
        }
    }

    #[allow(dead_code)]
    /// WIP
    pub fn count(&self) -> u64 {
        self.count
    }
}

#[repr(C)]
#[derive(Debug)]
/// Struct for initializing an enclave
pub struct Init<'a>(u64, PhantomData<&'a ()>);

impl<'a> Init<'a> {
    /// A new Init struct must wrap a Signature from the sgx-types crate.
    pub fn new(sig: &'a Signature) -> Self {
        Init(sig as *const _ as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
/// Struct for setting enclave attributes - WIP - ERESUME? EREMOVE?
pub struct SetAttribute<'a>(u64, PhantomData<&'a ()>);

impl<'a> SetAttribute<'a> {
    #[allow(dead_code)]
    /// A new SetAttribute struct must wrap a file descriptor.
    pub fn new(fd: &'a impl std::os::unix::io::AsRawFd) -> Self {
        SetAttribute(fd.as_raw_fd() as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
/// SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS parameter structure
pub struct RestrictPermissions {
    /// In: starting page offset
    offset: u64,
    /// In: length of the address range (multiple of the page size)
    length: u64,
    /// In: restricted permissions
    permissions: u64,
    /// Out: ENCLU[EMODPR] return value
    result: u64,
    /// Out: length of the address range successfully changed
    count: u64,
}

impl RestrictPermissions {
    /// Create a new RestrictPermissions instance.
    pub fn new(offset: usize, length: usize, permissions: usize) -> Self {
        Self {
            offset: offset as _,
            length: length as _,
            permissions: permissions as _,
            result: 0,
            count: 0,
        }
    }

    /// Read result attribute.
    pub fn result(&self) -> u64 {
        self.result
    }

    /// Read count attribute.
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn execute(&self, mutex_fd: &Mutex<fs::File>) -> io::Result<()> {
        let mut count: u64 = 0;
        while self.length > count {
            let mut parameters = Self {
                offset: self.offset + count,
                length: self.length - count,
                permissions: self.permissions,
                result: 0,
                count: 0,
            };

            let fd_locked = mutex_fd.lock().unwrap();
            let mut fd_cloned = fd_locked.try_clone().unwrap();
            match ENCLAVE_RESTRICT_PERMISSIONS.ioctl(&mut fd_cloned, &mut parameters) {
                Ok(_) => {}
                // EINTR
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR)) => {
                    debug!("ENCLAVE_RESTRICT_PERMISSIONS failed with EINTR");
                }
                // EWOULDBLOCK, EAGAIN
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock) => {
                    debug!("ENCLAVE_RESTRICT_PERMISSIONS failed with EAGAIN");
                }
                // EBUSY
                Err(e) if matches!(e.raw_os_error(), Some(libc::EBUSY)) => {
                    debug!("ENCLAVE_RESTRICT_PERMISSIONS failed with EBUSY");
                    std::thread::sleep(time::Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(e);
                }
            }

            count += parameters.count();
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Debug)]
/// SGX_IOC_ENCLAVE_MODIFY_TYPES parameter structure
pub struct ModifyTypes {
    /// In: starting page offset
    offset: u64,
    /// In: length of the address range (multiple of the page size)
    length: u64,
    /// In: page type
    page_type: u64,
    /// Out: ENCLU[EMODT] return value
    result: u64,
    /// Out: length of the address range successfully changed
    count: u64,
}

impl ModifyTypes {
    /// Create a new ModifyTypes instance.
    pub fn new(offset: usize, length: usize, page_type: usize) -> Self {
        Self {
            offset: offset as _,
            length: length as _,
            page_type: page_type as _,
            result: 0,
            count: 0,
        }
    }

    pub fn execute(&self, mutex_fd: &Mutex<fs::File>) -> io::Result<()> {
        let mut count: u64 = 0;
        while self.length > count {
            let mut parameters = Self {
                offset: self.offset + count,
                length: self.length - count,
                page_type: self.page_type,
                result: 0,
                count: 0,
            };

            let fd_locked = mutex_fd.lock().unwrap();
            let mut fd_cloned = fd_locked.try_clone().unwrap();
            match ENCLAVE_MODIFY_TYPES.ioctl(&mut fd_cloned, &mut parameters) {
                Ok(_) => {}
                // EINTR
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR)) => {
                    debug!("ENCLAVE_MODIFY_TYPES failed with EINTR");
                }
                // EWOULDBLOCK, EAGAIN
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock) => {
                    debug!("ENCLAVE_MODIFY_TYPES failed with EAGAIN");
                }
                // EBUSY
                Err(e) if matches!(e.raw_os_error(), Some(libc::EBUSY)) => {
                    debug!("ENCLAVE_MODIFY_TYPES failed with EBUSY");
                    std::thread::sleep(time::Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(e);
                }
            }

            count += parameters.count();
        }
        Ok(())
    }

    /// Read result attribute.
    pub fn result(&self) -> u64 {
        self.result
    }

    /// Read count attribute.
    pub fn count(&self) -> u64 {
        self.count
    }
}

#[repr(C)]
#[derive(Debug)]
/// SGX_IOC_ENCLAVE_REMOVE_PAGES parameter structure
pub struct RemovePages {
    /// In: starting page offset
    offset: u64,
    /// In: length of the address range (multiple of the page size)
    length: u64,
    /// Out: length of the address range successfully changed
    count: u64,
}

impl RemovePages {
    /// Create a new RemovePages instance.
    pub fn new(offset: usize, length: usize) -> Self {
        Self {
            offset: offset as _,
            length: length as _,
            count: 0,
        }
    }

    /// Read count attribute.
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn execute(&self, mutex_fd: &Mutex<fs::File>) -> io::Result<()> {
        let mut count: u64 = 0;
        while self.length > count {
            let mut parameters = Self {
                offset: self.offset + count,
                length: self.length - count,
                count: 0,
            };

            let fd_locked = mutex_fd.lock().unwrap();
            let mut fd_cloned = fd_locked.try_clone().unwrap();
            match ENCLAVE_REMOVE_PAGES.ioctl(&mut fd_cloned, &mut parameters) {
                Ok(_) => {}
                // EINTR
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR)) => {
                    debug!("ENCLAVE_REMOVE_PAGES failed with EINTR");
                }
                // EWOULDBLOCK, EAGAIN
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock) => {
                    debug!("ENCLAVE_REMOVE_PAGES failed with EAGAIN");
                }
                // EBUSY
                Err(e) if matches!(e.raw_os_error(), Some(libc::EBUSY)) => {
                    debug!("ENCLAVE_REMOVE_PAGES failed with EBUSY");
                    std::thread::sleep(time::Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(e);
                }
            }

            count += parameters.count();
        }
        Ok(())
    }
}

#[cfg(all(test, host_can_test_sgx))]
mod tests {
    use super::*;

    #[test]
    fn restrict_permissions() {
        use std::fs::OpenOptions;

        let mut device_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx_enclave")
            .unwrap();

        let mut parameters = RestrictPermissions::new(0, 0, 0);

        let ret = match ENCLAVE_RESTRICT_PERMISSIONS.ioctl(&mut device_file, &mut parameters) {
            Ok(_) => 0,
            Err(err) => err.raw_os_error().unwrap(),
        };

        assert_eq!(ret, libc::EINVAL);
    }
}
