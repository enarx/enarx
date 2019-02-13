use std::os::raw::{c_int, c_ulong, c_void};
use std::os::unix::io::AsRawFd;
use std::collections::HashSet;
use std::fs::File;

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
pub enum Error {
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

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::IoError(error)
    }
}

pub struct Sev(File);

impl Sev {
    unsafe fn cmd<T>(&self, code: Code, data: Option<&mut T>) -> Result<(), Option<Error>> {
        extern "C" {
            fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        }

        const SEV_ISSUE_CMD: c_ulong = 0xc0105300;

        #[repr(C, packed)]
        struct Command<'a, T> {
            pub code: Code,
            pub data: Option<&'a mut T>,
            pub error: u32,
        }
    
        let mut c = Command { code, data, error: 0 };
        match ioctl(self.0.as_raw_fd(), SEV_ISSUE_CMD, &mut c) {
            0 => Ok(()),
            _ => Err(Some(match c.error {
                0 => std::io::Error::from(errno::errno()).into(),
                1 => Error::InvalidPlatformState,
                2 => Error::InvalidGuestState,
                3 => Error::InavlidConfig,
                4 => Error::InvalidLen,
                5 => Error::AlreadyOwned,
                6 => Error::InvalidCertificate,
                7 => Error::PolicyFailure,
                8 => Error::Inactive,
                9 => Error::InvalidAddress,
                10 => Error::BadSignature,
                11 => Error::BadMeasurement,
                12 => Error::AsidOwned,
                13 => Error::InvalidAsid,
                14 => Error::WbinvdRequired,
                15 => Error::DfFlushRequired,
                16 => Error::InvalidGuest,
                17 => Error::InvalidCommand,
                18 => Error::Active,
                19 => Error::HardwarePlatform,
                20 => Error::HardwareUnsafe,
                21 => Error::Unsupported,
                _ => Err(None)?,
            }))
        }
    }

    pub fn new() -> std::io::Result<Sev> {
        Ok(Sev(File::open("/dev/sev")?))
    }

    pub fn platform_reset(&self) -> Result<(), Option<Error>> {
        unsafe { self.cmd::<c_void>(Code::PlatformReset, None) }
    }

    pub fn platform_status(&self) -> Result<Status, Option<Error>> {
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

        unsafe {
            self.cmd(Code::PlatformStatus, Some(&mut stat))?
        };

        let mut flags = HashSet::new();

        if stat.flags & (1 << 0) != 0 {
            flags.insert(Flags::Owned);
        }

        if stat.flags & (1 << 8) != 0 {
            flags.insert(Flags::EncryptedState);
        }

        Ok(Status {
            version: Version(stat.api_major, stat.api_minor, stat.build),
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

    pub fn pek_generate(&self) -> Result<(), Option<Error>> {
        unsafe { self.cmd::<c_void>(Code::PekGenerate, None) }
    }

    pub fn pdh_generate(&self) -> Result<(), Option<Error>> {
        unsafe { self.cmd::<c_void>(Code::PdhGenerate, None) }
    }

    pub fn get_identifer(&self) -> Result<Identifier, Option<Error>> {
        // Per AMD, this interface will change in a future revision.
        // Future iterations will only ever return one id and its
        // length will be variable. We handle the current verison of
        // the API here. We'll adjust to future versions later. We
        // don't anticipate any future change in *our* public API.

        #[repr(C, packed)]
        struct Ids([u8; 64], [u8; 64]);

        let mut ids = Ids([0; 64], [0; 64]);

        unsafe {
            self.cmd(Code::GetIdentifier, Some(&mut ids))?
        };

        Ok(Identifier(ids.0.to_vec()))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub struct Version(u8, u8, u8);

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
    pub version: Version,
    pub state: State,
    pub flags: HashSet<Flags>,
    pub guests: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Identifier(Vec<u8>);

impl From<Identifier> for Vec<u8> {
    fn from(id: Identifier) -> Vec<u8> {
        id.0
    }
}

impl std::fmt::LowerHex for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for b in self.0.iter() {
            write!(f, "{:x}", b)?;
        }

        Ok(())
    }
}

impl std::fmt::UpperHex for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for b in self.0.iter() {
            write!(f, "{:X}", b)?;
        }

        Ok(())
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

    #[test]
    fn platform_status() {
        let sev = Sev::new().unwrap();
        let status = sev.platform_status().unwrap();
        assert!(status.version > Version(0, 14, 0));
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

    #[test]
    fn get_identifer() {
        let sev = Sev::new().unwrap();
        let id = sev.get_identifer().unwrap();
        assert_ne!(id.0, vec![0u8; 64]);
    }
}
