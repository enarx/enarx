// Copyright 2019 Red Hat
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

use bitflags::bitflags;
use super::*;

bitflags! {
    #[derive(Default)]
    pub struct PolicyFlags: u16 {
        const NO_DEBUG        = 0b00000001u16.to_le();
        const NO_KEY_SHARING  = 0b00000010u16.to_le();
        const ENCRYPTED_STATE = 0b00000100u16.to_le();
        const NO_SEND         = 0b00001000u16.to_le();
        const DOMAIN          = 0b00010000u16.to_le();
        const SEV             = 0b00100000u16.to_le();
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub flags: PolicyFlags,
    pub minfw: Version,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub nonce: [u8; 16],
    pub wrap_tk: [u8; 32],
    pub wrap_iv: [u8; 16],
    pub wrap_mac: [u8; 32],
    pub policy_mac: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Start {
    pub policy: Policy,
    pub cert: certs::sev::Certificate,
    pub session: Session,
}

bitflags! {
    #[derive(Default)]
    pub struct HeaderFlags: u32 {
        const COMPRESSED = 0b00000001u32.to_le();
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub flags: HeaderFlags,
    pub iv: [u8; 16],
    pub mac: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    pub measure: [u8; 32],
    pub mnonce: [u8; 16],
}
