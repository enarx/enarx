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

use super::Ioctl;
use bitflags::bitflags;
use std::marker::PhantomData;
use std::os::raw::c_ulong;
use std::os::unix::io::AsRawFd;

#[repr(C)]
#[derive(Debug)]
pub struct Create<'a>(u64, PhantomData<&'a ()>);

impl<'a> Ioctl for Create<'a> {
    const REQUEST: c_ulong = 1_074_308_096; // SGX_IOC_ENCLAVE_CREATE
}

impl<'a> Create<'a> {
    pub fn new(secs: &'a crate::secs::Secs) -> Self {
        Create(secs as *const _ as _, PhantomData)
    }
}

bitflags! {
    pub struct PageFlags: u64 {
        const MEASURE = 1 << 0;
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct AddPages<'a> {
    src: u64,
    offset: u64,
    length: u64,
    secinfo: u64,
    flags: PageFlags,
    phantom: PhantomData<&'a ()>,
}

impl<'a> Ioctl for AddPages<'a> {
    const REQUEST: c_ulong = 3_223_888_897; // SGX_IOC_ENCLAVE_ADD_PAGES
}

// TODO: Implement AddPages::new()

#[repr(C)]
#[derive(Debug)]
pub struct Init<'a>(u64, PhantomData<&'a ()>);

impl<'a> Ioctl for Init<'a> {
    const REQUEST: c_ulong = 1_074_308_098; // SGX_IOC_ENCLAVE_INIT
}

// TODO: Implement Init::new()
//impl<'a> Init<'a> {
//    pub fn new(sig: &'a crate::sig::Sig) -> Self {
//        Init(sig as *const _ as _, PhantomData)
//    }
//}

#[repr(C)]
#[derive(Debug)]
pub struct SetAttribute<'a>(u64, PhantomData<&'a ()>);

impl<'a> Ioctl for SetAttribute<'a> {
    const REQUEST: c_ulong = 1_074_308_099; // SGX_IOC_ENCLAVE__SET_ATTRIBUTE
}

impl<'a> SetAttribute<'a> {
    pub fn new(fd: &'a impl AsRawFd) -> Self {
        SetAttribute(fd.as_raw_fd() as _, PhantomData)
    }
}
