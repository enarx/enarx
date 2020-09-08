// SPDX-License-Identifier: Apache-2.0

use super::vm;

pub struct Kvm;
impl vm::builder::Hook for Kvm {}
