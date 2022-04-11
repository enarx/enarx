// SPDX-License-Identifier: Apache-2.0

use std::arch::asm;
use std::io::{ErrorKind, Result};
use std::ptr::{null, null_mut};

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
pub struct Platform(Technology, usize);

impl Platform {
    const SYS_GETATT: usize = 0xEA01;

    fn get_att(nonce: Option<&[u8]>, mut buf: Option<&mut [u8]>) -> Result<Self> {
        const ENOSYS: isize = -38;
        let mut rax;
        let mut rdx;

        unsafe {
            asm!(
                "syscall",
                lateout("rax") rax,
                lateout("rdx") rdx,
                in("rax") Self::SYS_GETATT,
                in("rdi") nonce.map(|x| x.as_ptr()).unwrap_or_else(null),
                in("rsi") nonce.map(|x| x.len()).unwrap_or_default(),
                in("rdx") buf.as_mut().map(|x| x.as_mut_ptr()).unwrap_or_else(null_mut),
                in("r10") buf.map(|x| x.len()).unwrap_or_default(),
            )
        }

        match (rax, rdx) {
            (ENOSYS, ..) => Ok(Self(Technology::Kvm, 0)),
            (n, ..) if n < 0 => Err(std::io::Error::from_raw_os_error(-n as i32)),
            (n, t) => match t {
                0 => Ok(Self(Technology::Kvm, n as _)),
                1 => Ok(Self(Technology::Snp, n as _)),
                2 => Ok(Self(Technology::Sgx, n as _)),
                _ => Err(ErrorKind::Other.into()),
            },
        }
    }

    pub fn get() -> Result<Self> {
        Self::get_att(None, None)
    }

    pub fn technology(self) -> Technology {
        self.0
    }

    pub fn attest(self, nonce: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0; self.1];

        let Self(.., size) = Self::get_att(Some(nonce), Some(&mut buf))?;
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
    assert_eq!(platform.1, 0);
    let report = platform.attest(b"00000000").unwrap();
    assert!(report.is_empty());
}
