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
