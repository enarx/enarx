// SPDX-License-Identifier: Apache-2.0

//! Helpful primitives for developing the crate.

/// A simple const generics substitute.
#[macro_export]
macro_rules! impl_const_id {
    (
        $visibility:vis $trait:ident => $id_ty:ty;
        $(
            $iocty:ty = $val:expr
        ),* $(,)*
    ) => {
        $visibility trait $trait {
            const ID: $id_ty;
        }

        $(
            impl $trait for $iocty {
                const ID: $id_ty = $val;
            }
        )*
    };
}

#[cfg(test)]
mod tests {
    struct A;
    struct B;
    struct C;

    impl_const_id! {
        Id => usize;
        A = 1,
        B = 2,
        C = 3,
    }

    #[test]
    fn test_const_id_macro() {
        assert_eq!(A::ID, 1);
        assert_eq!(B::ID, 2);
        assert_eq!(C::ID, 3);
    }
}
