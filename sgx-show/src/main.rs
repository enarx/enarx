// SPDX-License-Identifier: Apache-2.0

//! This program exists to gather and display data relating to SGX hardware,
//! SGX BIOS enablement, SGX kernel drivers and potentially SGX-related
//! software for use in debugging.
//!
//! It works by running a hierarchical tree of tests and displaying the
//! information gathered therefrom. If a parent test fails to validate,
//! the child tests are still called to produce their output, but do not
//! perform data collection since the data collection method may be invalid.
//! For example, we don't attempt to look up CPUIDs for SGX attributes if
//! the CPU doesn't support SGX.
//!
//! Each test has a name, as well as a `data` source, a data `sink` and
//! a (possibly empty) array of child tests. First, it attempts to collect
//! the data. Second, it converts the input data to the data type for the
//! sink. Third, it passes the data to the sink to determine if this data
//! is successful or not. Fourth, it prints the success status, the test
//! name, the data source and the sink to the command line. Finally, it
//! calls all child tests, passing the status of the parent test to the
//! child.
//!
//! Note that there are differet kinds of sinks. Some perform data validation.
//! Others, like `sink::debug::Debug` just dump some of the input data.
//!
//! There is currently only one data source (CPUID).

#![deny(missing_docs)]
#![deny(clippy::all)]
#![allow(clippy::unreadable_literal)]

mod data;
mod exec;
mod sink;

use std::convert::TryFrom;

use exec::*;
use sgx_types::{attr, misc};

use data::cpuid::{CpuId, CpuInfo, ExtFeat, SgxAttr, SgxCaps};
use sink::{bit::Bit, debug::Debug, mask::Mask};

impl TryFrom<CpuId<SgxCaps>> for misc::MiscSelect {
    type Error = ();

    fn try_from(value: CpuId<SgxCaps>) -> Result<Self, ()> {
        misc::MiscSelect::from_bits(value.ebx()).ok_or(())
    }
}

impl TryFrom<CpuId<SgxAttr>> for attr::Flags {
    type Error = ();

    fn try_from(value: CpuId<SgxAttr>) -> Result<Self, ()> {
        let flags = ((value.ebx() as u64) << 32) | value.eax() as u64;
        attr::Flags::from_bits(flags).ok_or(())
    }
}

impl TryFrom<CpuId<SgxAttr>> for attr::Xfrm {
    type Error = ();

    fn try_from(value: CpuId<SgxAttr>) -> Result<Self, ()> {
        let xfrm = ((value.edx() as u64) << 32) | value.ecx() as u64;
        attr::Xfrm::from_bits(xfrm).ok_or(())
    }
}

struct Size32(bytesize::ByteSize);

impl std::fmt::Debug for Size32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<CpuId<SgxCaps>> for Size32 {
    fn from(value: CpuId<SgxCaps>) -> Self {
        let bits = value.edx() as u8;
        Self(bytesize::ByteSize(1 << bits))
    }
}

struct Size64(bytesize::ByteSize);

impl std::fmt::Debug for Size64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<data::cpuid::CpuId<SgxCaps>> for Size64 {
    fn from(value: CpuId<SgxCaps>) -> Self {
        let bits = value.edx() >> 8 as u8;
        Self(bytesize::ByteSize(1 << bits))
    }
}

fn main() {
    let test = Test {
        name: "Intel CPU",
        data: Box::new(CpuInfo),
        sink: Box::new(Mask {
            mask: 0x00000000ffffffffffffffffffffffffu128,
            data: 0x00000000756e65476c65746e49656e69u128,
        }),
        next: vec![
            Box::new(Test {
                name: "SGX Launch Config",
                data: Box::new(ExtFeat),
                sink: Box::new(Bit {
                    reg: CpuId::ecx,
                    bit: 30,
                }),
                next: vec![],
            }),
            Box::new(Test {
                name: "SGX Support",
                data: Box::new(ExtFeat),
                sink: Box::new(Bit {
                    reg: CpuId::ebx,
                    bit: 2,
                }),
                next: vec![
                    Box::new(Test {
                        name: "Version 1",
                        data: Box::new(SgxCaps),
                        sink: Box::new(Bit {
                            reg: CpuId::eax,
                            bit: 0,
                        }),
                        next: vec![],
                    }),
                    Box::new(Test {
                        name: "Version 2",
                        data: Box::new(SgxCaps),
                        sink: Box::new(Bit {
                            reg: CpuId::eax,
                            bit: 1,
                        }),
                        next: vec![],
                    }),
                    Box::new(Test {
                        name: "Max Size (32bit)",
                        data: Box::new(SgxCaps),
                        sink: Box::new(Debug::<Size32>::new()),
                        next: vec![],
                    }),
                    Box::new(Test {
                        name: "Max Size (64bit)",
                        data: Box::new(SgxCaps),
                        sink: Box::new(Debug::<Size64>::new()),
                        next: vec![],
                    }),
                    Box::new(Test {
                        name: "MiscSelect",
                        data: Box::new(SgxCaps),
                        sink: Box::new(Debug::<misc::MiscSelect>::new()),
                        next: vec![],
                    }),
                    Box::new(Test {
                        name: "attr::Flags",
                        data: Box::new(SgxAttr),
                        sink: Box::new(Debug::<attr::Flags>::new()),
                        next: vec![],
                    }),
                    Box::new(Test {
                        name: "attr::Xfrm",
                        data: Box::new(SgxAttr),
                        sink: Box::new(Debug::<attr::Xfrm>::new()),
                        next: vec![],
                    }),
                ],
            }),
        ],
    };

    test.exec(0, true);
}
