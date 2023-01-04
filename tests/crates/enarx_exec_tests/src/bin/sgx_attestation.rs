// SPDX-License-Identifier: Apache-2.0

use enarx_exec_tests::{musl_fsbase_fix, CrlList};

use std::convert::TryFrom;
use std::io;

use der::{Decode, Sequence};
use x509_cert::Certificate;

musl_fsbase_fix!();

const MRSIGNER_START: usize = 48 + 128;
const QUOTE_SIG_START: usize = 436;
const QE_AUTH_LEN_START: usize = 576;
const QE_AUTH_LEN_END: usize = 578;

#[repr(u64)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
pub enum TeeTech {
    None = 0,
    Sev = 1,
    Sgx = 2,
}

pub struct TryFromIntError(pub(crate) ());

impl TryFrom<u64> for TeeTech {
    type Error = TryFromIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Sev),
            2 => Ok(Self::Sgx),
            _ => Err(TryFromIntError(())),
        }
    }
}

#[derive(Sequence)]
pub struct TcbPackage<'a> {
    pub crts: Vec<Certificate<'a>>,
    #[asn1(type = "OCTET STRING")]
    pub report: &'a [u8],
}

#[derive(Sequence)]
pub struct SgxEvidence<'a> {
    #[asn1(type = "OCTET STRING")]
    pub quote: &'a [u8],
    pub crl: CrlList<'a>,
    pub tcb: TcbPackage<'a>,
}

#[cfg(target_os = "linux")]
pub fn get_att_syscall(
    nonce: Option<&mut [u8]>,
    buf: Option<&mut [u8]>,
) -> io::Result<(usize, TeeTech)> {
    let rax: i64;
    let rdx: u64;

    let nonce_ptr = if let Some(ref nonce) = nonce {
        nonce.as_ptr() as usize
    } else {
        0usize
    };

    let nonce_len = if let Some(ref nonce) = nonce {
        nonce.len()
    } else {
        0usize
    };

    let buf_len = if let Some(ref buf) = buf {
        buf.len()
    } else {
        0usize
    };

    let buf_ptr = if let Some(buf) = buf {
        buf.as_mut_ptr() as usize
    } else {
        0usize
    };

    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") sallyport::item::enarxcall::SYS_GETATT => rax,
            in("rdi") nonce_ptr,
            in("rsi") nonce_len,
            inlateout("rdx") buf_ptr => rdx,
            in("r10") buf_len,
            in("r8") 0,
            in("r9") 0,
            lateout("rcx") _, // clobbered
            lateout("r11") _, // clobbered
        );
    }

    if rax < 0 {
        return Err(io::Error::from_raw_os_error(-rax as _));
    }

    let tech = TeeTech::try_from(rdx).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;

    Ok((rax as _, tech))
}

#[cfg(not(target_os = "linux"))]
pub fn get_att_syscall(_: Option<&mut [u8]>, _: Option<&mut [u8]>) -> io::Result<(usize, TeeTech)> {
    unimplemented!("`get_att_syscall` only supported on Linux")
}

fn main() -> io::Result<()> {
    let (len, tech) = get_att_syscall(None, None)?;

    assert!(matches!(tech, TeeTech::Sgx));

    let mut nonce: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
    ];

    let mut buffer = vec![0u8; len];

    let (len, tech) = get_att_syscall(Some(&mut nonce[..]), Some(&mut buffer))?;

    assert!(matches!(tech, TeeTech::Sgx));

    let evidence = SgxEvidence::from_der(&buffer[..len]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("SGX evidence to DER error {e}"),
        )
    })?;

    assert!(
        evidence.crl.crls.len() > 1,
        "ensure CRLs were present, got {}",
        evidence.crl.crls.len()
    );

    let buffer = evidence.quote;

    let bytes = &buffer[MRSIGNER_START..][..32];
    let out = hex::encode(bytes);
    println!("MRSIGNER = {out}");

    let bytes = &buffer[QUOTE_SIG_START..];

    let mut qe_auth_len_bytes = [0u8; 2];
    qe_auth_len_bytes.copy_from_slice(&bytes[QE_AUTH_LEN_START..QE_AUTH_LEN_END]);
    let qe_auth_len: usize = u16::from_le_bytes(qe_auth_len_bytes).into();
    let qe_auth_end = qe_auth_len + QE_AUTH_LEN_END;

    let mut qe_cert_data_type_bytes = [0u8; 2];
    qe_cert_data_type_bytes.copy_from_slice(&bytes[qe_auth_end..][..2]);
    let qe_cert_data_type = u16::from_le_bytes(qe_cert_data_type_bytes);

    // PCKCertChain
    assert!(qe_cert_data_type == 5);

    Ok(())
}
