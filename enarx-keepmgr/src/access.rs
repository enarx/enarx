use bitflags::bitflags;

bitflags! {
    /// Memory access permissions
    ///
    /// Raw numeric values are from the ELF specification. This implies
    /// that an Access instance can be created from an ELF ProgramHeader
    /// directly.
    pub struct Access: u8 {
        /// Execute access
        const X = 1 << 0;

        /// Write access
        const W = 1 << 1;

        /// Read access
        const R = 1 << 2;
    }
}
