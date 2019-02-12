use std::os::raw::{c_int, c_ulong};
use std::os::unix::io::AsRawFd;
use std::fs::File;

extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

const SEV_ISSUE_CMD: c_ulong = 0xc0105300;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum Code {
    FactoryReset = 0,
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
    pub fn new() -> std::io::Result<Sev> {
        Ok(Sev(File::open("/dev/sev")?))
    }

    unsafe fn cmd<T>(&self, code: Code, data: &mut T) -> Result<(), Option<Error>> {
        #[repr(C, packed)]
        struct Command<'a, T> {
            pub code: Code,
            pub data: &'a T,
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

    pub fn platform_status(&self) -> Result<Status, Option<Error>> {
        let mut status = Status {
            api_major: 0,
            api_minor: 0,
            state: 0,
            flags: 0,
            build: 0,
            guest_count: 0,
        };

        unsafe {
            self.cmd(Code::PlatformStatus, &mut status)?
        };

        Ok(status)
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

#[repr(C, packed)]
pub struct Status {
    api_major: u8,
    api_minor: u8,
    state: u8,
    flags: u32,
    build: u8,
    guest_count: u32,
}

impl Status {
    pub fn version(&self) -> Version {
        Version(self.api_major, self.api_minor, self.build)
    }
    
    pub fn state(&self) -> Option<State> {
        Some(match self.state {
            0 => State::Uninitialized,
            1 => State::Initialized,
            2 => State::Working,
            _ => return None,
        })
    }
    
    pub fn owned(&self) -> bool {
        self.flags & (1 << 0) != 0
    }
    
    pub fn encrypted_state(&self) -> bool {
        self.flags & (1 << 8) != 0
    }
    
    pub fn guest_count(&self) -> u32 {
        self.guest_count
    }
}
