// Copyright 2019 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! ISV_PRODID and ISVSVN in SIGSTRUCT (Table 38-19)
//! Definitions for Independent Software Vendor Product ID and Security Version Number.

/// ISV assigned Product ID.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProdId(u16);

/// ISV assigned SVN (security version number).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
