// SPDX-License-Identifier: Apache-2.0

//! MiscSelect (Section 38.7.2)
//! The bit vector of MISCSELECT selects which extended information is to be saved in the MISC
//! region of the SSA frame when an AEX is generated.

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    /// Section 38.7.2
    #[derive(Default)]
    #[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
    pub struct MiscSelect: u32 {
        /// Report info about page faults and general protection exception that occurred inside an enclave.
        const EXINFO = 1 << 0;
    }
}
