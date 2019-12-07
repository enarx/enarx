bitflags::bitflags! {
    /// Section 38.7.1
    pub struct Attributes: u64 {
        const INIT = 1 << 0;
        const DEBUG = 1 << 1;
        const MODE_64_BIT = 1 << 2;
        const PROVISION_KEY = 1 << 4;
        const EINIT_TOKEN_KEY = 1 << 5;
    }
}

defflags!(Attributes MODE_64_BIT);
