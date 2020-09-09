// SPDX-License-Identifier: Apache-2.0

//! Some basic address operations

/// The offset of shim virtual address space to the physical address
///
/// physical address + `SHIM_VIRT_OFFSET` = shim virtual address
///
/// FIXME: change to dynamic offset with ASLR https://github.com/enarx/enarx/issues/624
pub const SHIM_VIRT_OFFSET: u64 = 0xFFFF_FF80_0000_0000;

#[allow(clippy::integer_arithmetic)]
const BYTES_2_MIB: u64 = bytes![2; MiB];

use crate::frame_allocator::FRAME_ALLOCATOR;
use crate::get_cbit_mask;
use core::convert::TryFrom;
use nbytes::bytes;
use primordial::{Address, Register};

/// Address in the host virtual address space
pub struct HostVirtAddr<U>(Address<u64, U>);

impl<U> HostVirtAddr<U> {
    /// Create a new HostVirtAddr
    ///
    /// # Safety
    /// The caller has to ensure, that the address is in the hosts virtual address space
    pub unsafe fn new(val: Address<u64, U>) -> Self {
        Self(val)
    }
}

impl<U> From<ShimPhysUnencryptedAddr<U>> for HostVirtAddr<U> {
    #[inline(always)]
    fn from(val: ShimPhysUnencryptedAddr<U>) -> Self {
        FRAME_ALLOCATOR.read().phys_to_host(val)
    }
}

impl<T, U> From<HostVirtAddr<U>> for Register<T>
where
    Register<T>: From<Register<u64>>,
{
    #[inline(always)]
    fn from(val: HostVirtAddr<U>) -> Self {
        Register::<u64>::from(val.0).into()
    }
}

/// Address in the shim physical address space
pub struct ShimPhysAddr<U>(Address<u64, U>);

impl<T, U> From<Address<T, U>> for ShimPhysAddr<U>
where
    Address<T, U>: Into<Address<u64, U>>,
{
    #[inline(always)]
    fn from(val: Address<T, U>) -> Self {
        let mut val: Address<u64, U> = val.into();
        val = unsafe { Address::unchecked(val.raw() | get_cbit_mask()) };
        Self(val)
    }
}

impl<U> ShimPhysAddr<U> {
    /// Get the raw address
    pub fn raw(self) -> Address<u64, U> {
        self.0
    }
}

/// Address in the shim virtual address space
#[derive(Clone)]
pub struct ShimVirtAddr<U>(Address<u64, U>);

impl<U> TryFrom<Address<u64, U>> for ShimVirtAddr<U> {
    type Error = ();

    #[inline(always)]
    fn try_from(value: Address<u64, U>) -> Result<Self, Self::Error> {
        let value = value.raw();

        if value < SHIM_VIRT_OFFSET {
            return Err(());
        }

        Ok(Self(unsafe { Address::unchecked(value) }))
    }
}

impl<U> From<ShimVirtAddr<U>> for *const U {
    #[inline(always)]
    fn from(shim_virt_addr: ShimVirtAddr<U>) -> Self {
        shim_virt_addr.0.raw() as _
    }
}

impl<U> From<ShimVirtAddr<U>> for *mut U {
    #[inline(always)]
    fn from(shim_virt_addr: ShimVirtAddr<U>) -> Self {
        shim_virt_addr.0.raw() as _
    }
}

impl<U> From<ShimPhysAddr<U>> for ShimVirtAddr<U> {
    #[inline(always)]
    fn from(shim_phys_addr: ShimPhysAddr<U>) -> Self {
        // Safety: checked, that it is in the shim virtual address space earlier
        #[allow(clippy::integer_arithmetic)]
        ShimVirtAddr(unsafe {
            Address::unchecked((shim_phys_addr.0.raw() & (!get_cbit_mask())) + SHIM_VIRT_OFFSET)
        })
    }
}

/// Address in the shim virtual address space
pub struct ShimPhysUnencryptedAddr<U>(Address<u64, U>);

impl<U> ShimPhysUnencryptedAddr<U> {
    /// Get the raw address
    pub fn raw(self) -> Address<u64, U> {
        self.0
    }

    /// convert to mutable reference
    pub fn into_mut<'a>(self) -> &'a mut U {
        unsafe { &mut *(self.0.raw() as *mut U) }
    }
}

impl<U> TryFrom<ShimVirtAddr<U>> for ShimPhysUnencryptedAddr<U> {
    type Error = ();

    #[inline(always)]
    fn try_from(value: ShimVirtAddr<U>) -> Result<Self, Self::Error> {
        #[allow(clippy::integer_arithmetic)]
        let value = value.0.raw();
        let value = value.checked_sub(SHIM_VIRT_OFFSET).ok_or(())? & (!get_cbit_mask());

        if value >= BYTES_2_MIB {
            return Err(());
        }

        Ok(Self(unsafe { Address::unchecked(value) }))
    }
}

impl<U> TryFrom<Address<u64, U>> for ShimPhysUnencryptedAddr<U> {
    type Error = ();

    #[inline(always)]
    fn try_from(value: Address<u64, U>) -> Result<Self, Self::Error> {
        let value = value.raw();

        if (value & get_cbit_mask()) != 0 {
            return Err(());
        }

        Ok(Self(unsafe { Address::unchecked(value) }))
    }
}
