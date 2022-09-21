// SPDX-License-Identifier: Apache-2.0

//! Platform-specific functionality.

use std::io::{ErrorKind, Result};

use const_oid::ObjectIdentifier;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Technology {
    Kvm,
    Snp,
    Sgx,
}

impl Technology {
    const KVM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.1");
    const SGX: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.2");
    const SNP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.3");
}

impl From<Technology> for ObjectIdentifier {
    fn from(value: Technology) -> Self {
        match value {
            Technology::Kvm => Technology::KVM,
            Technology::Snp => Technology::SNP,
            Technology::Sgx => Technology::SGX,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Platform {
    technology: Technology,
    report_size: usize,
    #[allow(dead_code)]
    key_size: usize,
}

impl Platform {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    fn get_att(_nonce: Option<&[u8]>, _buf: Option<&mut [u8]>) -> Result<(Technology, usize)> {
        Ok((Technology::Kvm, 0))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn get_att(nonce: Option<&[u8]>, mut buf: Option<&mut [u8]>) -> Result<(Technology, usize)> {
        use sallyport::item::enarxcall::SYS_GETATT;
        use std::arch::asm;
        use std::ptr::{null, null_mut};

        const ENOSYS: isize = -(libc::ENOSYS as isize);
        const EPERM: isize = -(libc::EPERM as isize);

        let mut rax;
        let mut rdx;

        unsafe {
            asm!(
                "syscall",
                lateout("rax") rax,
                lateout("rdx") rdx,
                in("rax") SYS_GETATT,
                in("rdi") nonce.map(|x| x.as_ptr()).unwrap_or_else(null),
                in("rsi") nonce.map(|x| x.len()).unwrap_or_default(),
                in("rdx") buf.as_mut().map(|x| x.as_mut_ptr()).unwrap_or_else(null_mut),
                in("r10") buf.map(|x| x.len()).unwrap_or_default(),
                lateout("rcx") _, // clobbered
                lateout("r11") _, // clobbered
            )
        }

        match (rax, rdx) {
            (ENOSYS | EPERM, ..) => Ok((Technology::Kvm, 0)),
            (n, ..) if n < 0 => Err(std::io::Error::from_raw_os_error(-n as i32)),
            (n, t) => match t {
                0 => Ok((Technology::Kvm, n as _)),
                1 => Ok((Technology::Snp, n as _)),
                2 => Ok((Technology::Sgx, n as _)),
                _ => Err(ErrorKind::Other.into()),
            },
        }
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    fn get_key(_buf: Option<&mut [u8]>) -> Result<usize> {
        Ok(0)
    }

    /// `get_key` syscall to the shim.
    ///
    /// See <https://github.com/enarx/enarx/issues/2110>
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn get_key(mut buf: Option<&mut [u8]>) -> Result<usize> {
        use sallyport::item::enarxcall::SYS_GETKEY;
        use std::arch::asm;
        use std::ptr::null_mut;

        const ENOSYS: isize = -(libc::ENOSYS as isize);
        const EPERM: isize = -(libc::EPERM as isize);

        let mut rax: isize;

        unsafe {
            asm!(
            "syscall",
            lateout("rax") rax,
            in("rax") SYS_GETKEY,
            in("rdi") buf.as_mut().map(|x| x.as_mut_ptr()).unwrap_or_else(null_mut),
            in("rsi") buf.map(|x| x.len()).unwrap_or_default(),
            lateout("rcx") _, // clobbered
            lateout("r11") _, // clobbered
            )
        }

        match rax {
            ENOSYS | EPERM => Ok(0),
            n if n < 0 => Err(std::io::Error::from_raw_os_error(-n as i32)),
            n => Ok(n as _),
        }
    }

    pub fn get() -> Result<Self> {
        let (technology, report_size) = Self::get_att(None, None)?;
        let key_size = Self::get_key(None)?;

        Ok(Self {
            technology,
            report_size,
            key_size,
        })
    }

    pub fn technology(&self) -> Technology {
        self.technology
    }

    #[allow(dead_code)]
    pub fn key(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; self.key_size];

        let size = Self::get_key(Some(&mut buf))?;
        if size > buf.len() {
            return Err(ErrorKind::Other.into());
        }

        Ok(buf)
    }

    pub fn attest(&self, nonce: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0; self.report_size];

        let (_, size) = Self::get_att(Some(nonce), Some(&mut buf))?;
        if size > buf.len() {
            return Err(ErrorKind::Other.into());
        }

        buf.truncate(size);
        Ok(buf)
    }
}

#[test]
fn test() {
    let platform = Platform::get().unwrap();
    assert_eq!(platform.technology(), Technology::Kvm);
    assert_eq!(platform.report_size, 0);
    assert_eq!(platform.key_size, 0);
    let report = platform.attest(b"00000000").unwrap();
    assert!(report.is_empty());
}
