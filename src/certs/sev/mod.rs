mod cert;
mod chain;

pub use cert::Certificate;
pub use chain::Chain;

use super::*;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Usage(u32);

impl Usage {
    pub const OCA: Usage = Usage(0x1001u32.to_le());
    pub const CEK: Usage = Usage(0x1004u32.to_le());
    pub const PEK: Usage = Usage(0x1002u32.to_le());
    pub const PDH: Usage = Usage(0x1003u32.to_le());
}

impl TryFrom<super::Usage> for Usage {
    type Error = ();

    fn try_from(value: super::Usage) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            super::Usage::OCA => Usage::OCA,
            super::Usage::CEK => Usage::CEK,
            super::Usage::PEK => Usage::PEK,
            super::Usage::PDH => Usage::PDH,
            _ => Err(())?
        })
    }
}

impl From<Usage> for super::Usage {
    fn from(value: Usage) -> Self {
        Self(value.0)
    }
}

impl PartialEq<super::Usage> for Usage {
    fn eq(&self, other: &super::Usage) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<Usage> for super::Usage {
    fn eq(&self, other: &Usage) -> bool {
        self.0 == other.0
    }
}
