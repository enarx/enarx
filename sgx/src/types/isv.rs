// SPDX-License-Identifier: Apache-2.0

//! ISV_PRODID and ISVSVN in SIGSTRUCT (Table 38-19)
//! Definitions for Independent Software Vendor Product ID and Security Version Number.

/// ISV assigned Product ID.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProdId(u16);

/// ISV assigned SVN (security version number).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Svn(u16);

impl ProdId {
    /// Creates a new ProdId based on value provided.
    pub const fn new(prod_id: u16) -> Self {
        Self(prod_id)
    }
}

impl Svn {
    /// Creates a new Svn based on value provided.
    pub const fn new(svn: u16) -> Self {
        Self(svn)
    }
}
