// SPDX-License-Identifier: Apache-2.0

use crate::attestation_types::quote::Quote;
use std::arch::asm;
use std::convert::TryFrom;

#[cfg(test)]
macro_rules! testaso {
    (@off $name:path=>$field:ident) => {
        memoffset::offset_of!($name, $field)
    };

    ($(struct $name:path: $align:expr, $size:expr => { $($field:ident: $offset:expr),* })+) => {
        #[cfg(test)]
        #[test]
        fn align() {
            use core::mem::align_of;

            $(
                assert_eq!(
                    align_of::<$name>(),
                    $align,
                    "align: {}",
                    stringify!($name)
                );
            )+
        }

        #[cfg(test)]
        #[test]
        fn size() {
            use core::mem::size_of;

            $(
                assert_eq!(
                    size_of::<$name>(),
                    $size,
                    "size: {}",
                    stringify!($name)
                );
            )+
        }

        #[cfg(test)]
        #[test]
        fn offsets() {
            $(
                $(
                    assert_eq!(
                        testaso!(@off $name=>$field),
                        $offset,
                        "offset: {}::{}",
                        stringify!($name),
                        stringify!($field)
                    );
                )*
        )+
        }
    };
}

mod attestation_types;
mod types;

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

pub fn get_att_syscall(
    nonce: Option<&mut [u8]>,
    buf: Option<&mut [u8]>,
) -> std::io::Result<(usize, TeeTech)> {
    let rax: i64;
    let rdx: u64;

    let arg0 = if let Some(ref nonce) = nonce {
        nonce.as_ptr() as usize
    } else {
        0usize
    };

    let arg1 = if let Some(ref nonce) = nonce {
        nonce.len()
    } else {
        0usize
    };

    let arg3 = if let Some(ref buf) = buf {
        buf.len()
    } else {
        0usize
    };

    let arg2 = if let Some(buf) = buf {
        buf.as_mut_ptr() as usize
    } else {
        0usize
    };

    unsafe {
        asm!(
            "syscall",
            inlateout("rax") sallyport::syscall::SYS_ENARX_GETATT => rax,
            in("rdi") arg0,
            in("rsi") arg1,
            inlateout("rdx") arg2 => rdx,
            in("r10") arg3,
            in("r8") 0,
            in("r9") 0,
            lateout("rcx") _, // clobbered
            lateout("r11") _, // clobbered
        );
    }

    if rax < 0 {
        return Err(std::io::Error::from_raw_os_error(-rax as _));
    }

    let tech = TeeTech::try_from(rdx)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;

    Ok((rax as _, tech))
}

fn main() -> std::io::Result<()> {
    let (len, tech) = get_att_syscall(None, None)?;

    if matches!(tech, TeeTech::Sgx) {
        assert_eq!(len, 4598);

        get_att([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        ])?;

        get_att([0; 64])?;
    }

    Ok(())
}

fn get_att(mut nonce: [u8; 64]) -> std::io::Result<()> {
    let mut buffer = [0u8; 4598];
    let (len, tech) = get_att_syscall(Some(&mut nonce[..]), Some(&mut buffer))?;

    assert!(matches!(tech, TeeTech::Sgx));

    let quote = Quote::try_from(buffer.as_ref()).map_err(|e| {
        eprintln!("{:#?}", e);
        std::io::Error::from(std::io::ErrorKind::InvalidData)
    })?;

    assert_eq!(len, 4598);

    dbg!(&quote);

    Ok(())
}
