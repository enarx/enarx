// SPDX-License-Identifier: Apache-2.0

//! The `proxy` module contains structures used to facilitate communication between
//! the microkernel and the hypervisor. This is referred to as "proxying" in the
//! project literature. This is a very thin and low-level layer that is meant to
//! be as transparent as possible.

use memory::Register;

/// The `Message` struct is the most minimal representation of the register context
/// needed for service requests between the microkernel and the hypervisor. An example
/// of such a service would be proxying a system call.
///
/// This struct contains a number of convenient setter/getter functions to avoid accidentally
/// mixing up registers when implementing requests.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Message {
    /// The `rax` register is where the microkernel will indicate what kind of request
    /// (or syscall number) the hypervisor should carry out on its behalf. The hypervisor
    /// will write the return code to this register once it has completed its work.
    ///
    /// Note: this register context corresponds to the x86_64 `syscall` instruction style
    /// calling convention.
    pub rax: Register<u64>,
    /// 1st parameter register.
    pub rdi: Register<u64>,
    /// 2nd parameter register.
    pub rsi: Register<u64>,
    /// 3rd parameter register.
    pub rdx: Register<u64>,
    /// 4th parameter register.
    pub r10: Register<u64>,
    /// 5th parameter register.
    pub r8: Register<u64>,
    /// 6th parameter register.
    pub r9: Register<u64>,
}

impl Message {
    /// Construct a new `Message`.
    pub fn new(rax: Register<u64>) -> Self {
        Self {
            rax,
            rdi: Register::from_raw(0),
            rsi: Register::from_raw(0),
            rdx: Register::from_raw(0),
            r10: Register::from_raw(0),
            r8: Register::from_raw(0),
            r9: Register::from_raw(0),
        }
    }

    /// Assign a value to the first parameter register (rdi).
    pub fn first(mut self, val: Register<u64>) -> Self {
        self.rdi = val;
        self
    }

    /// Access the first parameter register (rdi).
    pub fn get_first(&self) -> Register<u64> {
        self.rdi
    }

    /// Assign a value to the second parameter register (rsi).
    pub fn second(mut self, val: Register<u64>) -> Self {
        self.rsi = val;
        self
    }

    /// Access the second parameter register (rsi).
    pub fn get_second(&self) -> Register<u64> {
        self.rsi
    }

    /// Assign a value to the third parameter register (rdx).
    pub fn third(mut self, val: Register<u64>) -> Self {
        self.rdx = val;
        self
    }

    /// Access the third parameter register (rdx).
    pub fn get_third(&self) -> Register<u64> {
        self.rdx
    }

    /// Assign a value to the fourth parameter register (r10).
    pub fn fourth(mut self, val: Register<u64>) -> Self {
        self.r10 = val;
        self
    }

    /// Access the fourth parameter register (r10)
    pub fn get_fourth(&self) -> Register<u64> {
        self.r10
    }

    /// Assign a value to the fifth parameter register (r8).
    pub fn fifth(mut self, val: Register<u64>) -> Self {
        self.r8 = val;
        self
    }

    /// Access the fifth parameter register (r8).
    pub fn get_fifth(&self) -> Register<u64> {
        self.r8
    }

    /// Assign a value to the sixth parameter register (r9).
    pub fn sixth(mut self, val: Register<u64>) -> Self {
        self.r9 = val;
        self
    }

    /// Access the sixth parameter register (r9)
    pub fn get_sixth(&self) -> Register<u64> {
        self.r9
    }
}

/// The `Block` struct encloses the Message's register context but also provides
/// a data buffer used to store data that might be required to service the request.
/// For example, bytes that must be written out by the host could be stored in the
/// `Block`'s `buf` field. It is expected that the trusted microkernel has copied
/// the necessary data components into the `Block`'s `buf` field and has updated
/// the `msg` register context fields accordingly in the event those registers
/// must point to those data components within the `buf`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Block {
    /// The register context corresponding to the request.
    pub msg: Message,
    /// A buffer where any additional request components may be stored. For example,
    /// a series of bytes to be written out in a proxied `write` syscall.
    ///
    /// Note that this buffer size is *less than* a page, since the buffer shares
    /// space with the `Message` that describes it.
    pub buf: [u8; Block::buf_capacity()],
}

impl Block {
    /// Get the maximum capacity of the data buffer.
    pub const fn buf_capacity() -> usize {
        memory::Page::size() - core::mem::size_of::<Message>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_block_size() {
        assert_eq!(memory::Page::size(), core::mem::size_of::<Block>());
    }
}
