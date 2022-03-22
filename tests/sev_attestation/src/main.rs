// SPDX-License-Identifier: Apache-2.0

use std::arch::asm;
use std::convert::TryFrom;
use std::mem::size_of;

use sallyport::item::enarxcall::SYS_GETATT;

pub const MAX_AUTHTAG_LEN: usize = 32;

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

#[repr(C, align(4096))]
pub struct SnpGuestMsg {
    pub hdr: SnpGuestMsgHdr,
    pub payload: [u8; 4000],
}

#[repr(C)]
#[derive(Debug)]
struct SnpReportResponseData {
    status: u32,
    size: u32,
    rsvd: [u8; 18],
    report: SnpReportData,
}

#[repr(C)]
#[derive(Debug)]
struct SnpReportData {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub sig_algo: u32,
    pub current_tcb: u64,
    pub plat_info: u64,
    pub author_key_en: u32,
    rsvd1: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: u64,
    rsvd2: [u8; 24],
    pub chip_id: [u8; 64],
    pub committed_tcb: u64,
    pub current_build: u8,
    pub current_minor: u8,
    pub current_major: u8,
    rsvd3: u8,
    pub committed_build: u8,
    pub committed_minor: u8,
    pub committed_major: u8,
    rsvd4: u8,
    pub launch_tcb: u64,
    rsvd5: [u8; 168],
    pub signature: [u8; 512],
}

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

    let arg1 = if let Some(ref nonce) = nonce {
        nonce.len()
    } else {
        0usize
    };

    let arg0 = if let Some(nonce) = nonce {
        nonce.as_ptr() as usize
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
            inlateout("rax") SYS_GETATT => rax,
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

fn main() {
    get_att([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
    ])
    .unwrap()
}

const ASN_LEN_HEADER_SIZE: usize = 6;
const ASN_SECTION_CONSTRUCTED: u8 = 0x30;
const ASN_OCTET_STRING: u8 = 0x04;
const ASN_LEN_4_BYTES: u8 = 0x84;

fn get_att(mut nonce: [u8; 64]) -> std::io::Result<()> {
    let (len, tech) = get_att_syscall(None, None)?;
    assert!(matches!(tech, TeeTech::Sev));

    let mut buf = vec![0u8; len];
    let (len, tech) = get_att_syscall(Some(&mut nonce[..]), Some(&mut buf))?;
    assert!(matches!(tech, TeeTech::Sev));
    let chunks = &buf[..len];

    eprintln!("To be pasted in https://lapo.it/asn1js/ :");
    for b in chunks {
        eprint!("{:02x} ", b);
    }
    eprintln!("\n");

    // section
    let (asn_header, chunks) = chunks.split_at(ASN_LEN_HEADER_SIZE);
    assert_eq!(asn_header[0], ASN_SECTION_CONSTRUCTED);
    assert_eq!(asn_header[1], ASN_LEN_4_BYTES);
    let len_left = u32::from_be_bytes(asn_header[2..6].try_into().unwrap());
    assert_eq!(chunks.len(), len_left as usize);

    // vcek
    let (vcek_buf, chunks) =
        chunks.split_at(chunks.len() - size_of::<SnpReportData>() - ASN_LEN_HEADER_SIZE);

    // octet
    let (asn_header, report_buf) = chunks.split_at(ASN_LEN_HEADER_SIZE);
    assert_eq!(asn_header[0], ASN_OCTET_STRING);
    assert_eq!(asn_header[1], ASN_LEN_4_BYTES);
    let len_left = u32::from_be_bytes(asn_header[2..6].try_into().unwrap());
    assert_eq!(report_buf.len(), len_left as usize);

    // report
    assert_eq!(report_buf.len(), size_of::<SnpReportData>());
    let report_data = report_buf.as_ptr() as *const SnpReportData;
    let report = unsafe { report_data.read_unaligned() };

    assert_eq!(report.version, 2);
    assert_eq!(nonce, report.report_data);

    eprintln!("report: {:?}", report);
    eprintln!("vcek: {:?}", vcek_buf);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use testaso::testaso;

    testaso! {
        struct SnpReportResponseData: 8, 1216 => {
        }

        struct SnpReportData: 8, 1184 => {
            version: 0,
            guest_svn: 4,
            policy: 8,
            family_id: 0x10,
            image_id: 0x20,
            vmpl: 0x30,
            sig_algo: 0x34,
            current_tcb: 0x38,
            plat_info: 0x40,
            author_key_en: 0x48,
            rsvd1: 0x4C,
            report_data: 0x50,
            measurement: 0x90,
            host_data: 0xC0,
            id_key_digest: 0xE0,
            author_key_digest: 0x110,
            report_id: 0x140,
            report_id_ma: 0x160,
            reported_tcb: 0x180,
            rsvd2: 0x188,
            chip_id: 0x1A0,
            committed_tcb: 0x1E0,
            current_build: 0x1E8,
            current_minor: 0x1E9,
            current_major: 0x1EA,
            rsvd3: 0x1EB,
            committed_build: 0x1EC,
            committed_minor: 0x1ED,
            committed_major: 0x1EE,
            rsvd4: 0x1EF,
            launch_tcb: 0x1F0,
            rsvd5: 0x1F8,
            signature: 0x2A0
        }

        struct SnpGuestMsgHdr: 8, 0x60 => {
            authtag: 0,
            msg_seqno: 0x20,
            rsvd1: 0x28,
            algo: 0x30,
            hdr_version: 0x31,
            hdr_sz: 0x32,
            msg_type: 0x34,
            msg_version: 0x35,
            msg_sz: 0x36,
            rsvd2: 0x38,
            msg_vmpck: 0x3C,
            rsvd3: 0x3D
        }

        struct SnpGuestMsg: 4096, 4096 => {
            hdr: 0,
            payload: 0x60
        }
    }
}
