// SPDX-License-Identifier: Apache-2.0

//! Some basic address operations

/// The offset of shim virtual address space to the physical address
///
/// physical address + `SHIM_VIRT_OFFSET` = shim virtual address
///
/// FIXME: change to dynamic offset with ASLR https://github.com/enarx/enarx/issues/624
pub const SHIM_VIRT_OFFSET: u64 = 0xFFFF_FF80_0000_0000;

use core::convert::TryFrom;
use memory::Address;

/// Address in the shim physical address space
pub struct ShimPhysAddr<U>(Address<u64, U>);

impl<T, U> From<ShimPhysAddr<U>> for memory::Register<T>
where
    memory::Register<T>: From<memory::Register<u64>>,
{
    #[inline(always)]
    fn from(val: ShimPhysAddr<U>) -> Self {
        memory::Register::<u64>::from(val.0).into()
    }
}

/// Address in the shim virtual address space
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

impl<U> From<ShimVirtAddr<U>> for ShimPhysAddr<U> {
    #[inline(always)]
    fn from(shim_virt_addr: ShimVirtAddr<U>) -> Self {
        // Safety: checked, that it is in the shim virtual address space earlier
        #[allow(clippy::integer_arithmetic)]
        ShimPhysAddr(unsafe { Address::unchecked(shim_virt_addr.0.raw() - SHIM_VIRT_OFFSET) })
    }
}

impl<U> From<ShimVirtAddr<U>> for Address<u64, U> {
    #[inline(always)]
    fn from(shim_virt_addr: ShimVirtAddr<U>) -> Self {
        shim_virt_addr.0
    }
}
