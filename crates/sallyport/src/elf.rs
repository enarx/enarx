//! Defines constants for use in ELF parsing

/// Program Header Types
pub mod pt {
    use goblin::elf64::program_header::PT_LOOS;

    /// The exec program header type
    ///
    /// This program header indicates the region within which the loader should
    /// load the executable. The executable must be loaded at the start of the
    /// region and must (obviously) fit in the region.
    pub const EXEC: u32 = PT_LOOS + 0x3400000;

    /// KVM Program Headers Types
    pub mod kvm {
        use super::PT_LOOS;

        /// The sallyport program header type
        pub const SALLYPORT: u32 = PT_LOOS + 0x34a0001;

        /// The enarx cpuid page program header type
        pub const CPUID: u32 = PT_LOOS + 0x34a0002;

        /// The enarx secrets page program header type
        pub const SECRET: u32 = PT_LOOS + 0x34a0003;
    }
}

/// Program Header Flags
pub mod pf {
    /// SGX Program Header Flags
    pub mod sgx {
        /// This segment contains TCS pages
        pub const TCS: u32 = 1 << 20;

        /// This segment contains unmeasured pages.
        pub const UNMEASURED: u32 = 1 << 21;
    }
}

/// ELF Notes
pub mod note {
    /// The name used for all note sections
    pub const NAME: &str = "sallyport";

    /// The name of the backend to use (utf-8 string)
    pub const BACKEND: u32 = 0;

    /// The minimum sallyport semver requires
    pub const REQUIRES: u32 = 1;

    /// SGX ELF Notes
    pub mod sgx {
        /// The SGX enclave bits (u8; in powers of 2)
        pub const BITS: u32 = 0x73677800;

        /// The number of pages in an SSA frame (u8)
        pub const SSAP: u32 = 0x73677801;

        /// The product identifier (u16)
        pub const PID: u32 = 0x73677810;

        /// The security version number (u16)
        pub const SVN: u32 = 0x73677811;

        /// MiscSelect (u32)
        pub const MISC: u32 = 0x73677812;

        /// MiscSelect Mask (u32)
        pub const MISCMASK: u32 = 0x73677813;

        /// Attributes (u128)
        pub const ATTR: u32 = 0x73677814;

        /// Attributes Mask (u128)
        pub const ATTRMASK: u32 = 0x73677815;
    }
}
