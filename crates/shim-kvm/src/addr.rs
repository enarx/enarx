// SPDX-License-Identifier: Apache-2.0

//! Some basic address operations

use crate::paging::ShimPageTable;
use crate::snp::get_cbit_mask;

use core::convert::TryFrom;

use nbytes::bytes;
use primordial::Address;
use x86_64::structures::paging::Translate;
use x86_64::{PhysAddr, VirtAddr};

/// The offset of shim virtual address space to the physical address
///
/// physical address + `SHIM_VIRT_OFFSET` = shim virtual address
///
/// FIXME: change to dynamic offset with ASLR https://github.com/enarx/enarx/issues/624
pub const SHIM_VIRT_OFFSET: u64 = 0xFFFF_FF80_0000_0000;

/// 2 MiB
#[allow(clippy::integer_arithmetic)]
pub const BYTES_2_MIB: u64 = bytes![2; MiB];

/// 1 GiB
#[allow(clippy::integer_arithmetic)]
pub const BYTES_1_GIB: u64 = bytes![1; GiB];

/// Translate addresses with the page table
pub trait TranslateFrom<T>: Sized {
    /// The type returned in the event of a conversion error.
    type Error;

    /// Performs the conversion.
    fn translate_from(shim_page_table: &ShimPageTable, value: T) -> Result<Self, Self::Error>;
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

impl<U> TryFrom<PhysAddr> for ShimPhysAddr<U> {
    type Error = ();

    fn try_from(value: PhysAddr) -> Result<Self, Self::Error> {
        Address::<u64, ()>::from(value.as_u64())
            .try_cast::<U>()
            .map(|val| {
                ShimPhysAddr::from(unsafe { Address::unchecked(val.raw() | get_cbit_mask()) })
            })
            .map_err(|_| ())
    }
}

impl<U> ShimPhysAddr<U> {
    /// Get the raw address
    pub fn raw(self) -> Address<u64, U> {
        self.0
    }
}

impl<U> TranslateFrom<*const U> for ShimPhysAddr<U> {
    type Error = ();

    /// translate the address to shim physical address
    fn translate_from(
        shim_page_table: &ShimPageTable,
        value: *const U,
    ) -> Result<Self, Self::Error> {
        let pa = shim_page_table
            .translate_addr(VirtAddr::from_ptr(value))
            .ok_or(())?;
        Ok(unsafe { Self(Address::unchecked(pa.as_u64())) })
    }
}

/// Address in the shim virtual address space
#[derive(Clone)]
pub struct ShimVirtAddr<U>(Address<u64, U>);

impl<U> From<&U> for ShimVirtAddr<U> {
    fn from(val: &U) -> Self {
        ShimVirtAddr(Address::from(val))
    }
}

impl<U> From<*const U> for ShimVirtAddr<U> {
    fn from(val: *const U) -> Self {
        ShimVirtAddr(Address::from(val))
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

impl<U> TryFrom<ShimVirtAddr<U>> for ShimPhysAddr<U> {
    type Error = ();

    #[inline(always)]
    fn try_from(value: ShimVirtAddr<U>) -> Result<Self, Self::Error> {
        #[allow(clippy::integer_arithmetic)]
        let value = value.0.raw();
        let value = value.checked_sub(SHIM_VIRT_OFFSET).ok_or(())?;

        Ok(Self(unsafe { Address::unchecked(value) }))
    }
}

/// Address in the shim virtual address space
#[derive(Copy, Clone)]
pub struct ShimPhysUnencryptedAddr<U>(Address<u64, U>);

impl<U> ShimPhysUnencryptedAddr<U> {
    /// Get the raw address
    #[inline(always)]
    pub fn raw(self) -> Address<u64, U> {
        self.0
    }

    /// convert to mutable reference
    #[inline(always)]
    pub fn into_mut<'a>(self) -> &'a mut U {
        unsafe { &mut *(self.0.raw().checked_add(SHIM_VIRT_OFFSET).unwrap() as *mut U) }
    }
}

impl<U> TranslateFrom<*const U> for ShimPhysUnencryptedAddr<U> {
    type Error = ();

    fn translate_from(
        shim_page_table: &ShimPageTable,
        value: *const U,
    ) -> Result<Self, Self::Error> {
        let pa = shim_page_table
            .translate_addr(VirtAddr::from_ptr(value))
            .ok_or(())?;

        if pa.as_u64() & get_cbit_mask() != 0 {
            return Err(());
        }

        Ok(unsafe { Self(Address::unchecked(pa.as_u64())) })
    }
}

impl<U> TranslateFrom<ShimVirtAddr<U>> for ShimPhysUnencryptedAddr<U> {
    type Error = ();

    #[inline(always)]
    fn translate_from(
        shim_page_table: &ShimPageTable,
        value: ShimVirtAddr<U>,
    ) -> Result<Self, Self::Error> {
        #[allow(clippy::integer_arithmetic)]
        let value = value.0;

        ShimPhysUnencryptedAddr::translate_from(shim_page_table, value)
    }
}

impl<U> TranslateFrom<Address<u64, U>> for ShimPhysUnencryptedAddr<U> {
    type Error = ();

    #[inline(always)]
    fn translate_from(
        shim_page_table: &ShimPageTable,
        value: Address<u64, U>,
    ) -> Result<Self, Self::Error> {
        let value = value.raw();

        let pa = shim_page_table
            .translate_addr(VirtAddr::new(value))
            .ok_or(())?;

        if pa.as_u64() & get_cbit_mask() != 0 {
            return Err(());
        }

        Ok(Self(unsafe { Address::unchecked(pa.as_u64()) }))
    }
}
