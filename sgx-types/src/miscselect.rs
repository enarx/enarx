bitflags::bitflags! {
    /// Section 38.7.2
    pub struct MiscSelect: u32 {
        const EXINFO = 1 << 0;
    }
}

impl Default for MiscSelect {
    fn default() -> Self {
        MiscSelect::EXINFO
    }
}
