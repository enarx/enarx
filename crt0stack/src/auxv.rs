// SPDX-License-Identifier: Apache-2.0

//! Types and Constants to create an ELF AUXV

/// AuxvEntry to be used with `Crt0Stack::add_auxv_entry()`
#[derive(Debug, PartialEq)]
pub enum Entry<'a> {
    /// file descriptor of program
    ExecFd(usize), // core does not have RawFd

    /// program headers for program
    PHdr(usize),

    /// size of program header entry
    PHent(usize),

    /// number of program headers
    PHnum(usize),

    /// system page size
    PageSize(usize),

    /// base address of interpreter
    Base(usize),

    /// flags
    Flags(usize),

    /// entry point of program
    Entry(usize),

    /// program is not ELF
    NotElf(bool),

    /// real uid
    Uid(usize),

    /// effective uid
    EUid(usize),

    /// real gid
    Gid(usize),

    /// effective gid
    EGid(usize),

    /// string identifying CPU for optimizations
    Platform(&'a str),

    /// arch dependent hints at CPU capabilities
    HWCap(usize),

    /// frequency at which times() increments
    ClockTick(usize),

    /// secure mode boolean
    Secure(bool),

    /// string identifying real platform, may differ from Platform.
    BasePlatform(&'a str),

    /// address of 16 random bytes
    Random([u8; 16]),

    /// extension of HWCAP
    HWCap2(usize),

    /// filename of program
    ExecFilename(&'a str),

    /// pointer to the vDSO page (deprecated)
    #[cfg(target_arch = "x86")]
    SysInfo(usize),

    /// pointer to the ELF headers of the vDSO page
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    SysInfoEHdr(usize),
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Key(usize);

impl From<Key> for usize {
    fn from(value: Key) -> Self {
        value.0
    }
}

impl Key {
    /// end of vector
    pub const NULL: Key = Key(0);

    /// entry should be ignored
    #[allow(dead_code)]
    pub const IGNORE: Key = Key(1);

    /// file descriptor of program
    pub const EXECFD: Key = Key(2);

    /// program headers for program
    pub const PHDR: Key = Key(3);

    /// size of program header entry
    pub const PHENT: Key = Key(4);

    /// number of program headers
    pub const PHNUM: Key = Key(5);

    /// system page size
    pub const PAGESZ: Key = Key(6);

    /// base address of interpreter
    pub const BASE: Key = Key(7);

    /// flags
    pub const FLAGS: Key = Key(8);

    /// entry point of program
    pub const ENTRY: Key = Key(9);

    /// program is not ELF
    pub const NOTELF: Key = Key(10);

    /// real uid
    pub const UID: Key = Key(11);

    /// effective uid
    pub const EUID: Key = Key(12);

    /// real gid
    pub const GID: Key = Key(13);

    /// effective gid
    pub const EGID: Key = Key(14);

    /// string identifying CPU for optimizations
    pub const PLATFORM: Key = Key(15);

    /// arch dependent hints at CPU capabilities
    pub const HWCAP: Key = Key(16);

    /// frequency at which times() increments
    pub const CLKTCK: Key = Key(17);

    /// secure mode boolean
    pub const SECURE: Key = Key(23);

    /// string identifying real platform, may differ from PLATFORM
    pub const BASE_PLATFORM: Key = Key(24);

    /// address of 16 random bytes
    pub const RANDOM: Key = Key(25);

    /// extension of AT_HWCAP
    pub const HWCAP2: Key = Key(26);

    /// filename of program
    pub const EXECFN: Key = Key(31);

    /// pointer to the vDSO page (deprecated)
    #[cfg(target_arch = "x86")]
    pub const SYSINFO: Key = Key(32);

    /// pointer to the ELF headers of the vDSO page
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub const SYSINFO_EHDR: Key = Key(33);
}
