use std::os::raw::{c_int, c_ulong, c_void};
use std::collections::{HashSet, HashMap};
use std::os::unix::io::AsRawFd;
use std::fs::File;

use super::certs::{Firmware, Usage, Kind};
use super::certs::Certificate as Cert;
use super::certs::Error as CertError;

use codicon::Decoder;

const SEV_CERT_LEN: usize = 0x824;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum Code {
    PlatformReset = 0,
    PlatformStatus = 1,
    PekGenerate = 2,
    PekCertificateSigningRequest = 3,
    PdhGenerate = 4,
    PdhCertificateExport = 5,
    PekCertificateImport = 6,
    GetIdentifier = 7,
}

#[derive(Debug)]
pub enum CodeError {
    IoError(std::io::Error),

    InvalidPlatformState,
    InvalidGuestState,
    InavlidConfig,
    InvalidLen,
    AlreadyOwned,
    InvalidCertificate,
    PolicyFailure,
    Inactive,
    InvalidAddress,
    BadSignature,
    BadMeasurement,
    AsidOwned,
    InvalidAsid,
    WbinvdRequired,
    DfFlushRequired,
    InvalidGuest,
    InvalidCommand,
    Active,
    HardwarePlatform,
    HardwareUnsafe,
    Unsupported,
}

impl From<std::io::Error> for CodeError {
    fn from(error: std::io::Error) -> CodeError {
        CodeError::IoError(error)
    }
}

#[derive(Debug)]
pub enum Error {
    Code(Option<CodeError>),
    Cert(CertError),
}

impl From<CodeError> for Error {
    fn from(error: CodeError) -> Error {
        Error::Code(Some(error))
    }
}

impl From<CertError> for Error {
    fn from(error: CertError) -> Error {
        Error::Cert(error)
    }
}

impl From<Option<CodeError>> for Error {
    fn from(error: Option<CodeError>) -> Error {
        Error::Code(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        CodeError::IoError(error).into()
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Build(Firmware, u8);

impl std::fmt::Display for Build {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum State {
    Uninitialized,
    Initialized,
    Working,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Flags {
    Owned,
    EncryptedState,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    pub build: Build,
    pub state: State,
    pub flags: HashSet<Flags>,
    pub guests: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier(Vec<u8>);

impl From<Identifier> for Vec<u8> {
    fn from(id: Identifier) -> Vec<u8> {
        id.0
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02X}", b)?;
        }

        Ok(())
    }
}

pub struct Sev(File);

impl Sev {
    #[inline]
    fn cmd<T>(&self, code: Code, data: Option<&mut T>) -> Result<(), Option<CodeError>> {
        extern "C" {
            fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        }

        #[allow(clippy::unreadable_literal)]
        const SEV_ISSUE_CMD: c_ulong = 0xc0105300;

        #[repr(C, packed)]
        struct Command {
            pub code: Code,
            pub data: u64,
            pub error: u32,
        }

        let mut c = Command { code, data: match data {
            Some(t) => t as *mut T as u64,
            None => 0,
        }, error: 0 };

        match unsafe { ioctl(self.0.as_raw_fd(), SEV_ISSUE_CMD, &mut c) } {
            0 => Ok(()),
            _ => Err(Some(match c.error {
                0 => std::io::Error::from(errno::errno()).into(),
                1 => CodeError::InvalidPlatformState,
                2 => CodeError::InvalidGuestState,
                3 => CodeError::InavlidConfig,
                4 => CodeError::InvalidLen,
                5 => CodeError::AlreadyOwned,
                6 => CodeError::InvalidCertificate,
                7 => CodeError::PolicyFailure,
                8 => CodeError::Inactive,
                9 => CodeError::InvalidAddress,
                10 => CodeError::BadSignature,
                11 => CodeError::BadMeasurement,
                12 => CodeError::AsidOwned,
                13 => CodeError::InvalidAsid,
                14 => CodeError::WbinvdRequired,
                15 => CodeError::DfFlushRequired,
                16 => CodeError::InvalidGuest,
                17 => CodeError::InvalidCommand,
                18 => CodeError::Active,
                19 => CodeError::HardwarePlatform,
                20 => CodeError::HardwareUnsafe,
                21 => CodeError::Unsupported,
                _ => Err(None)?,
            }))
        }
    }

    pub fn new() -> std::io::Result<Sev> {
        Ok(Sev(File::open("/dev/sev")?))
    }

    pub fn platform_reset(&self) -> Result<(), Option<CodeError>> {
        self.cmd::<c_void>(Code::PlatformReset, None)
    }

    pub fn platform_status(&self) -> Result<Status, Option<CodeError>> {
        #[derive(Copy, Clone, Default)]
        #[repr(C, packed)]
        struct Stat {
            api_major: u8,
            api_minor: u8,
            state: u8,
            flags: u32,
            build: u8,
            guest_count: u32,
        }

        let mut stat = Stat::default();

        self.cmd(Code::PlatformStatus, Some(&mut stat))?;

        let mut flags = HashSet::new();

        if stat.flags & 1 != 0 {
            flags.insert(Flags::Owned);
        }

        if stat.flags & (1 << 8) != 0 {
            flags.insert(Flags::EncryptedState);
        }

        Ok(Status {
            build: Build(Firmware(stat.api_major, stat.api_minor), stat.build),
            guests: stat.guest_count,
            flags: flags,
            state: match stat.state {
                0 => State::Uninitialized,
                1 => State::Initialized,
                2 => State::Working,
                _ => Err(None)?,
            },
        })
    }

    pub fn pek_generate(&self) -> Result<(), Option<CodeError>> {
        self.cmd::<c_void>(Code::PekGenerate, None)
    }

    pub fn pdh_generate(&self) -> Result<(), Option<CodeError>> {
        self.cmd::<c_void>(Code::PdhGenerate, None)
    }

    pub fn get_identifer(&self) -> Result<Identifier, Option<CodeError>> {
        // Per AMD, this interface will change in a future revision.
        // Future iterations will only ever return one id and its
        // length will be variable. We handle the current verison of
        // the API here. We'll adjust to future versions later. We
        // don't anticipate any future change in *our* public API.

        #[repr(C, packed)]
        struct Ids([u8; 64], [u8; 64]);

        let mut ids = Ids([0; 64], [0; 64]);

        self.cmd(Code::GetIdentifier, Some(&mut ids))?;

        Ok(Identifier(ids.0.to_vec()))
    }

    pub fn pdh_cert_export(&self) -> Result<HashMap<Usage, Cert>, Error> {
        #[derive(Copy, Clone, Default)]
        #[repr(C, packed)]
        struct Data {
            pdh_cert_address: u64,
            pdh_cert_length: u32,
            cert_chain_address: u64,
            cert_chain_length: u32,
        }

        let mut buf = vec![0u8; SEV_CERT_LEN * 4];
        let mut data = Data {
            pdh_cert_address: (&mut buf[..SEV_CERT_LEN]).as_mut_ptr() as u64,
            pdh_cert_length: SEV_CERT_LEN as u32,
            cert_chain_address: (&mut buf[SEV_CERT_LEN..]).as_mut_ptr() as u64,
            cert_chain_length: SEV_CERT_LEN as u32 * 3,
        };

        self.cmd(Code::PdhCertificateExport, Some(&mut data))?;

        let mut map = HashMap::new();
        let mut rdr = &buf[..];
        for _ in 0..4 {
            let cert = Cert::decode(&mut rdr, Kind::Sev)?;
            map.insert(cert.usage(), cert);
        }

        Ok(map)
    }

    pub fn pek_csr(&self) -> Result<Vec<u8>, Option<CodeError>> {
        #[derive(Copy, Clone, Default)]
        #[repr(C, packed)]
        struct Data {
            address: u64,
            length: u32,
        }

        let mut buf = vec![0u8; SEV_CERT_LEN];
        let mut data = Data {
            address: buf.as_mut_ptr() as u64,
            length: SEV_CERT_LEN as u32,
        };

        self.cmd(Code::PekCertificateSigningRequest, Some(&mut data))?;
        if data.length != SEV_CERT_LEN as u32 { Err(None)? }
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn platform_reset() {
        let sev = Sev::new().unwrap();
        sev.platform_reset().unwrap();
    }

    #[cfg_attr(not(has_sev), ignore)]
    #[test]
    fn platform_status() {
        let sev = Sev::new().unwrap();
        let status = sev.platform_status().unwrap();
        assert!(status.build > Build(Firmware(0, 14), 0));
        assert!(!status.flags.contains(&Flags::Owned));
        assert!(!status.flags.contains(&Flags::EncryptedState));
        assert_eq!(status.guests, 0);
    }

    #[ignore]
    #[test]
    fn pek_generate() {
        let sev = Sev::new().unwrap();
        sev.pek_generate().unwrap();
    }

    #[ignore]
    #[test]
    fn pdh_generate() {
        let sev = Sev::new().unwrap();
        sev.pdh_generate().unwrap();
    }

    #[cfg_attr(not(has_sev), ignore)]
    #[test]
    fn get_identifer() {
        let sev = Sev::new().unwrap();
        let id = sev.get_identifer().unwrap();
        assert_ne!(id.0, vec![0u8; 64]);
    }

    #[cfg_attr(not(has_sev), ignore)]
    #[test]
    fn pdh_cert_export() {
        let sev = Sev::new().unwrap();
        let chain = sev.pdh_cert_export().unwrap();

        assert!(chain.get(&Usage::PlatformDiffieHellman).is_some());
        assert!(chain.get(&Usage::PlatformEndorsementKey).is_some());
        assert!(chain.get(&Usage::OwnerCertificateAuthority).is_some());
        assert!(chain.get(&Usage::ChipEndorsementKey).is_some());
    }

    #[cfg_attr(not(has_sev), ignore)]
    #[test]
    fn pek_csr() {
        use certs::{Certificate, Kind, Usage};
        use codicon::Decoder;

        let sev = Sev::new().unwrap();
        let pek = sev.pek_csr().unwrap();

        let cert = Certificate::decode(&mut &pek[..], Kind::Sev).unwrap();
        assert_eq!(cert.usage(), Usage::PlatformEndorsementKey);
    }
}
