// SPDX-License-Identifier: Apache-2.0

use crate::certs::sev;
use crate::launch::{Header, Measurement, Policy, Session};

use std::marker::PhantomData;

/// Initialize the SEV platform context.
#[repr(C)]
pub struct Init;

/// Initiate SEV launch flow.
#[repr(C)]
pub struct LaunchStart<'a> {
    pub handle: u32,
    policy: Policy,
    dh_addr: u64,
    dh_len: u32,
    session_addr: u64,
    session_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchStart<'a> {
    pub fn new(policy: &'a Policy, dh: &'a sev::Certificate, session: &'a Session) -> Self {
        Self {
            handle: 0, /* platform will generate one for us */
            policy: *policy,
            dh_addr: dh as *const _ as _,
            dh_len: std::mem::size_of_val(dh) as _,
            session_addr: session as *const _ as _,
            session_len: std::mem::size_of_val(session) as _,
            _phantom: PhantomData,
        }
    }
}

/// Encrypt guest data with its VEK.
#[repr(C)]
pub struct LaunchUpdateData<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchUpdateData<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            len: data.len() as _,
            _phantom: PhantomData,
        }
    }
}

/// Inject a secret into the guest.
#[repr(C)]
pub struct LaunchSecret<'a> {
    hdr_addr: u64,
    hdr_len: u32,
    guest_addr: u64,
    guest_len: u32,
    trans_addr: u64,
    trans_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchSecret<'a> {
    pub fn new(header: &'a Header, guest: &u8, trans: &'a [u8]) -> Self {
        Self {
            hdr_addr: header as *const _ as _,
            hdr_len: std::mem::size_of_val(header) as _,
            guest_addr: guest as *const _ as _,
            guest_len: trans.len() as _,
            trans_addr: trans.as_ptr() as _,
            trans_len: trans.len() as _,
            _phantom: PhantomData,
        }
    }
}

/// Get the guest's measurement.
#[repr(C)]
pub struct LaunchMeasure<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a Measurement>,
}

impl<'a> LaunchMeasure<'a> {
    pub fn new(measurement: &'a mut Measurement) -> Self {
        Self {
            addr: measurement as *mut _ as _,
            len: std::mem::size_of_val(measurement) as _,
            _phantom: PhantomData,
        }
    }
}

/// Complete the SEV launch flow and transition guest into
/// ready state.
#[repr(C)]
pub struct LaunchFinish;
