// SPDX-License-Identifier: Apache-2.0

//! The `sev-types` crate contains types that are useful with interacting with
//! a SEV-enabled environment.
//!
//! These types are described in the ["Secure Encrypted Virtualization API"](
//! https://developer.amd.com/wp-content/resources/55766.PDF) published by AMD.
//!
//! This crate is based on the SEV API document version 0.22 published in July,
//! 2019. If any discrepancies are found, please file an issue and/or open a
//! pull request. It is important that this crate remains in lockstep with the
//! API specification above.
//!
//! If this crate is updated to reflect a newer version of the AMD SEV API,
//! please update this documentation so that the following items are correct:
//! the SEV API specification document version; the specification publication
//! date; the link to the SEV API specification.

#![no_std]
#![deny(missing_docs)]
#![deny(clippy::all)]
