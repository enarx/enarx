bitflags::bitflags! {
    /// Section 38.7.2
    pub struct MiscSelect: u32 {
        const EXINFO = 1 << 0;
    }
}

defflags!(MiscSelect EXINFO);
