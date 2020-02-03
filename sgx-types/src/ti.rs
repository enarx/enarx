// Copyright 2020 Red Hat, Inc.
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

//! Report Target Info (Section 38.16)
//! The Target Info is used to identify the target enclave that will be able to cryptographically
//! verify the REPORT structure returned by the EREPORT leaf. Must be 512-byte aligned.

use super::{attr::Attributes, misc::MiscSelect};

/// Table 38-22
#[derive(Debug)]
#[repr(C, align(512))]
pub struct TargetInfo {
    /// MRENCLAVE of the target enclave.
    pub mrenclave: [u8; 32],
    /// Attributes of the target enclave.
    pub attributes: Attributes,
    reserved0: u32,
    /// MiscSelect of the target enclave.
    pub misc: MiscSelect,
    reserved1: [u64; 32],
    reserved2: [u64; 25],
}

testaso! {
    struct TargetInfo: 512, 512 => {
        mrenclave: 0,
        attributes: 32,
        reserved0: 48,
        misc: 52,
        reserved1: 56,
        reserved2: 312
    }
}
