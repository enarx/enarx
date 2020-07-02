// SPDX-License-Identifier: Apache-2.0

//! Helper macros to define a static mut singleton with locking

/// A helper macro to define a static mut singleton with mutex locking
#[macro_export]
macro_rules! mutex_singleton {
    (static mut $GLOBAL:ident : $Mutex:ident < $Inner:ty > ;) => {
        /// A wrapper struct to access a global singleton
        pub struct $Mutex(spinning::Mutex<Option<$Inner>>);
        static mut $GLOBAL: $Mutex = $Mutex::const_new();

        impl $Mutex {
            #[inline(always)]
            const fn const_new() -> Self {
                Self(spinning::Mutex::<Option<$Inner>>::const_new(
                    spinning::RawMutex::const_new(),
                    None,
                ))
            }

            /// Initialize the global static mut of the singleton
            #[inline(always)]
            pub fn init_global(val: $Inner) {
                unsafe {
                    $GLOBAL.0.lock().replace(val);
                }
            }

            /// Get a an instance
            ///
            /// # Panics
            ///
            /// Panics, if the singleton is not yet initialized.
            ///
            /// # Safety
            ///
            /// Guarded by a Mutex lock
            #[inline(always)]
            pub fn lock() -> spinning::MappedMutexGuard<'static, $Inner> {
                spinning::MutexGuard::map(unsafe { $GLOBAL.0.lock() }, |e| e.as_mut().unwrap())
            }

            /// Try to get a an instance
            ///
            /// # Panics
            ///
            /// Panics, if the singleton is not yet initialized.
            ///
            /// # Safety
            ///
            /// Guarded by a Mutex lock
            #[inline(always)]
            pub fn try_lock() -> Option<spinning::MappedMutexGuard<'static, $Inner>> {
                unsafe {
                    $GLOBAL
                        .0
                        .try_lock()
                        .map(|l| spinning::MutexGuard::map(l, |e| e.as_mut().unwrap()))
                }
            }
        }
    };
}

/// A helper macro to define a static mut singleton with rw locking
#[macro_export]
macro_rules! rwlock_singleton {
    (static mut $GLOBAL:ident : $RWLock:ident < $Inner:ty > ;) => {
        /// A wrapper struct to access a global singleton
        pub struct $RWLock(spinning::RwLock<Option<$Inner>>);
        static mut $GLOBAL: $RWLock = $RWLock::const_new();

        impl $RWLock {
            #[inline(always)]
            const fn const_new() -> Self {
                Self(spinning::RwLock::<Option<$Inner>>::const_new(
                    spinning::RawRwLock::const_new(),
                    None,
                ))
            }

            /// Initialize the global static mut of the singleton
            #[inline(always)]
            pub fn init_global(val: $Inner) {
                unsafe {
                    $GLOBAL.0.write().replace(val);
                }
            }

            /// Get a writable instance
            ///
            /// # Panics
            ///
            /// Panics, if the singleton is not yet initialized.
            ///
            /// # Safety
            ///
            /// Guarded by a RWLock
            #[inline(always)]
            pub fn write() -> spinning::MappedRwLockWriteGuard<'static, $Inner> {
                spinning::RwLockWriteGuard::map(unsafe { $GLOBAL.0.write() }, |e| {
                    e.as_mut().unwrap()
                })
            }

            /// Try to get a writable instance
            ///
            /// # Panics
            ///
            /// Panics, if the singleton is not yet initialized.
            ///
            /// # Safety
            ///
            /// Guarded by a RWLock
            #[inline(always)]
            pub fn try_write() -> Option<spinning::MappedRwLockWriteGuard<'static, $Inner>> {
                unsafe {
                    $GLOBAL
                        .0
                        .try_write()
                        .map(|l| spinning::RwLockWriteGuard::map(l, |e| e.as_mut().unwrap()))
                }
            }

            /// Get a readable instance
            ///
            /// # Panics
            ///
            /// Panics, if the singleton is not yet initialized.
            ///
            /// # Safety
            ///
            /// Guarded by a RWLock
            #[inline(always)]
            pub fn read() -> spinning::MappedRwLockReadGuard<'static, $Inner> {
                spinning::RwLockReadGuard::map(unsafe { $GLOBAL.0.read() }, |e| e.as_ref().unwrap())
            }

            /// Try to get a readable instance
            ///
            /// # Panics
            ///
            /// Panics, if the singleton is not yet initialized.
            ///
            /// # Safety
            ///
            /// Guarded by a RWLock
            #[inline(always)]
            pub fn try_read() -> Option<spinning::MappedRwLockReadGuard<'static, $Inner>> {
                unsafe {
                    $GLOBAL
                        .0
                        .try_read()
                        .map(|l| spinning::RwLockReadGuard::map(l, |e| e.as_ref().unwrap()))
                }
            }
        }
    };
}
