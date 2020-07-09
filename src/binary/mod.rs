// SPDX-License-Identifier: Apache-2.0

mod component;
mod segment;

pub use component::Component;
pub use segment::Segment;

/// Permissions ascribed to a particular program header
pub struct Permissions {
    /// Segment is readable
    pub read: bool,

    /// Segment is writable
    pub write: bool,

    /// Segment is executable
    pub execute: bool,
}
