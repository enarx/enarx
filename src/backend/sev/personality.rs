// SPDX-License-Identifier: Apache-2.0

use crate::backend::kvm::Personality;

pub struct Sev;

impl Personality for Sev {}
