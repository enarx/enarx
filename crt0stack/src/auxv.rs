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
    HwCap(usize),

    /// frequency at which times() increments
    ClockTick(usize),

    /// secure mode boolean
    Secure(bool),

    /// string identifying real platform, may differ from Platform.
    BasePlatform(&'a str),

    /// address of 16 random bytes
    Random([u8; 16]),

    /// extension of HWCAP
    HwCap2(usize),

    /// filename of program
    ExecFilename(&'a str),

    /// pointer to the vDSO page (deprecated)
    SysInfo(usize),

    /// pointer to the ELF headers of the vDSO page
    SysInfoEHdr(usize),
}

enumerate::enumerate! {
    #[derive(Copy, Clone, Default)]
    pub(crate) enum Key: usize {
        /// end of vector
        Null = 0,

        /// entry should be ignored
        #[allow(dead_code)]
        Ignore = 1,

        /// file descriptor of program
        ExecFd = 2,

        /// program headers for program
        PHdr = 3,

        /// size of program header entry
        PHent = 4,

        /// number of program headers
        PHnum = 5,

        /// system page size
        PageSize = 6,

        /// base address of interpreter
        Base = 7,

        /// flags
        Flags = 8,

        /// entry point of program
        Entry = 9,

        /// program is not ELF
        NotElf = 10,

        /// real uid
        Uid = 11,

        /// effective uid
        EUid = 12,

        /// real gid
        Gid = 13,

        /// effective gid
        EGid = 14,

        /// string identifying CPU for optimizations
        Platform = 15,

        /// arch dependent hints at CPU capabilities
        HwCap = 16,

        /// frequency at which times() increments
        ClockTick = 17,

        /// secure mode boolean
        Secure = 23,

        /// string identifying real platform, may differ from PLATFORM
        BasePlatform = 24,

        /// address of 16 random bytes
        Random = 25,

        /// extension of AT_HWCAP
        HwCap2 = 26,

        /// filename of program
        ExecFilename = 31,

        /// pointer to the vDSO page (deprecated)
        SysInfo = 32,

        /// pointer to the ELF headers of the vDSO page
        SysInfoEHdr = 33,
    }
}
