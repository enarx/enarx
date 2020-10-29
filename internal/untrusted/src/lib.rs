// SPDX-License-Identifier: Apache-2.0

//! New Types to handle verified addresses

#![deny(missing_docs)]
#![deny(clippy::all)]
#![cfg_attr(not(test), no_std)]

use core::convert::TryInto;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use primordial::Register;

/// Trait to validate `self` with an `AddressValidator`
pub trait Validate {
    /// The output type
    type Output;

    /// validate `self` with an `AddressValidator`
    ///
    /// returns `None`, if `self` is not valid
    fn validate<V: AddressValidator>(self, validator: &V) -> Option<Self::Output>;
}

/// Trait to validate `self` with an `AddressValidator`
pub trait ValidateSlice {
    /// The output type
    type Output;

    /// validate a slice for `self` and `length` with an `AddressValidator`
    ///
    /// returns `None`, if `self` is not valid
    fn validate_slice<I: TryInto<usize>, V: AddressValidator>(
        self,
        length: I,
        validator: &V,
    ) -> Option<Self::Output>;
}

/// Factory for validated address references
pub trait AddressValidator {
    /// validator test function
    ///
    /// Returns `true`, if the memory is readable
    fn validate_const_mem_fn(&self, ptr: *const (), size: usize) -> bool;

    /// validator function
    ///
    /// Returns `true`, if the memory is readable and writable
    fn validate_mut_mem_fn(&self, ptr: *mut (), size: usize) -> bool;
}

/// A reference to a user space object
///
/// Uses `*const` so, that it does not implement `Send` and `Sync`
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct UntrustedRef<'a, T>(*const T, PhantomData<&'a T>);

impl<'a, T> UntrustedRef<'a, T> {
    /// Get a pointer
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.0 as _
    }
}

impl<'a, T> From<*const T> for UntrustedRef<'a, T> {
    fn from(data: *const T) -> Self {
        Self(data, PhantomData::default())
    }
}

impl<'a, T, U> From<Register<U>> for UntrustedRef<'a, T>
where
    usize: From<Register<U>>,
{
    fn from(data: Register<U>) -> Self {
        Self(usize::from(data) as _, PhantomData::default())
    }
}

impl<'a, T> Validate for UntrustedRef<'a, T> {
    type Output = &'a T;

    fn validate<V: AddressValidator>(self, validator: &V) -> Option<Self::Output> {
        if self.0.is_null() {
            return None;
        }

        // check for alignment
        if self.0 as usize % align_of::<T>() != 0 {
            return None;
        }

        // check for accessibility
        if !validator.validate_const_mem_fn(self.0 as _, size_of::<T>()) {
            return None;
        }

        Some(unsafe { &*self.0 })
    }
}

impl<'a, T> ValidateSlice for UntrustedRef<'a, T> {
    type Output = &'a [T];

    fn validate_slice<I: TryInto<usize>, V: AddressValidator>(
        self,
        length: I,
        validator: &V,
    ) -> Option<Self::Output> {
        let length = match length.try_into() {
            Ok(val) => val,
            Err(_) => return None,
        };

        if self.0.is_null() {
            return None;
        }

        // check for alignment
        if self.0 as usize % align_of::<T>() != 0 {
            return None;
        }

        // check for accessibility
        if !validator.validate_const_mem_fn(self.0 as _, size_of::<T>() * length) {
            return None;
        }

        Some(unsafe { core::slice::from_raw_parts(self.0, length) })
    }
}

/// A mutable reference to a user space object
///
/// Uses `*mut` so, that it does not implement `Send` and `Sync`
#[repr(transparent)]
pub struct UntrustedRefMut<'a, T>(*mut T, PhantomData<&'a mut T>);

impl<'a, T> UntrustedRefMut<'a, T> {
    /// Get a pointer
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.0 as _
    }

    /// Get a mutable pointer
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.0 as _
    }
}

impl<'a, T> From<*mut T> for UntrustedRefMut<'a, T> {
    fn from(data: *mut T) -> Self {
        Self(data, PhantomData::default())
    }
}

impl<'a, T, U> From<Register<U>> for UntrustedRefMut<'a, T>
where
    usize: From<Register<U>>,
{
    fn from(data: Register<U>) -> Self {
        Self(usize::from(data) as _, PhantomData::default())
    }
}

impl<'a, T> Validate for UntrustedRefMut<'a, T> {
    type Output = &'a mut T;

    fn validate<V: AddressValidator>(self, validator: &V) -> Option<Self::Output> {
        if self.0.is_null() {
            return None;
        }

        // check for alignment
        if self.0 as usize % align_of::<T>() != 0 {
            return None;
        }

        // check for accessibility
        if !validator.validate_mut_mem_fn(self.0 as _, size_of::<T>()) {
            return None;
        }

        Some(unsafe { &mut *self.0 })
    }
}

impl<'a, T> ValidateSlice for UntrustedRefMut<'a, T> {
    type Output = &'a mut [T];

    fn validate_slice<I: TryInto<usize>, V: AddressValidator>(
        self,
        length: I,
        validator: &V,
    ) -> Option<Self::Output> {
        let length = match length.try_into() {
            Ok(val) => val,
            Err(_) => return None,
        };

        if self.0.is_null() {
            return None;
        }

        // check for alignment
        if self.0 as usize % align_of::<T>() != 0 {
            return None;
        }

        // check for accessibility
        if !validator.validate_mut_mem_fn(self.0 as _, size_of::<T>() * length) {
            return None;
        }

        Some(unsafe { core::slice::from_raw_parts_mut(self.0, length) })
    }
}
