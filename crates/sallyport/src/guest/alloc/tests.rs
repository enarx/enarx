// SPDX-License-Identifier: Apache-2.0

use super::*;

use core::fmt::LowerHex;
use core::mem::{size_of, transmute};

fn assert_block_eq<const N: usize>(got: [usize; N], expected: [usize; N]) {
    #[inline]
    fn format(iter: impl IntoIterator<Item = impl LowerHex>) -> String {
        iter.into_iter()
            .fold("\n[\n".into(), |s, el| format!("{s} {el:#018x},\n"))
            + "]\n"
    }
    assert_eq!(
        got,
        expected,
        "\ngot: {}\nexpected: {}",
        format(got),
        format(expected),
    );
}

#[test]
fn alloc() {
    const USIZE_COUNT: usize = 16;

    let mut buf = [usize::MAX; USIZE_COUNT];
    let mut free = USIZE_COUNT * size_of::<usize>();
    let mut offset = 0;

    let mut alloc = Alloc::new(&mut buf).stage();

    // Alloc stores a `NonNull<[u8]>` view of the underlying `[usize; N]` buffer.
    // Before it starts advancing the pointer to the buffer by handing out allocations,
    // we grab a copy of the original address, extract the raw pointer to the `*mut u8` buffer,
    // and transmute that to a `*mut [usize; N]` so we can test the buffer contents.
    // The reason that we do this dance after the Alloc has been constructed rather than
    // stash a pointer to the original buffer is to keep Miri happy.
    // Specifically, this avoids ever aliasing any `&mut T`, and preserves pointer provenance.
    let buf_ptr: *mut [usize; USIZE_COUNT] = unsafe { transmute(alloc.ptr.as_mut_ptr()) };

    assert_eq!(alloc.free::<usize>(), USIZE_COUNT);
    assert_eq!(alloc.free::<u8>(), free);

    let in_u32 = Input::stage(&mut alloc, 0xdeadbeef_u32).unwrap();
    free -= size_of::<u32>();
    assert_eq!(alloc.free::<usize>(), USIZE_COUNT - 1);
    assert_eq!(alloc.free::<u8>(), free);
    assert_eq!(in_u32.offset(), offset);
    offset += size_of::<u32>();

    let out_u16 = Output::stage(&mut alloc, 0x8888_u16).unwrap();
    free -= size_of::<u16>();
    assert_eq!(alloc.free::<usize>(), USIZE_COUNT - 1);
    assert_eq!(alloc.free::<u8>(), free);
    assert_eq!(out_u16.offset(), offset);
    offset += size_of::<u16>();

    let in_slice_u32 = Input::stage_slice(
        &mut alloc,
        [
            0xaaaaaaaa_u32,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
        ],
    )
    .unwrap();
    assert_eq!(in_slice_u32.len(), 5);
    free -= size_of::<u16>() + 5 * size_of::<u32>();
    offset += size_of::<u16>();
    assert_eq!(alloc.free::<usize>(), USIZE_COUNT - 4);
    assert_eq!(alloc.free::<u8>(), free);
    assert_eq!(in_slice_u32.offset(), offset);
    offset += 5 * size_of::<u32>();

    let out_slice_u8 =
        Output::stage_slice(&mut alloc, [0x88_u8, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88]).unwrap();
    assert_eq!(out_slice_u8.len(), 7);
    free -= 7;
    assert_eq!(alloc.free::<usize>(), USIZE_COUNT - 5);
    assert_eq!(alloc.free::<u8>(), free);
    assert_eq!(out_slice_u8.offset(), offset);
    offset += 7;

    let (mut in_out_slice_max_usize, mut in_tuple_usize_ref) = alloc
        .reserve_input(|alloc| {
            assert_eq!(alloc.free::<u8>(), free - 2 * size_of::<usize>());
            assert_eq!(alloc.free::<usize>(), USIZE_COUNT - 7);
            alloc.allocate_inout_slice_max(USIZE_COUNT + 1)
        })
        .unwrap();
    offset += 5;
    assert_eq!(in_out_slice_max_usize.len(), free / size_of::<usize>() - 2);
    assert_eq!(alloc.free::<usize>(), 0);
    assert_eq!(alloc.free::<u8>(), 0);
    assert_eq!(in_out_slice_max_usize.offset(), offset);
    assert_eq!(
        in_tuple_usize_ref.offset(),
        (USIZE_COUNT - 2) * size_of::<usize>()
    );

    let alloc = alloc.commit();

    assert_block_eq(unsafe { buf_ptr.read() }, [usize::MAX; USIZE_COUNT]);

    in_u32.commit(&alloc);
    in_slice_u32.commit(&alloc);
    unsafe { in_out_slice_max_usize.copy_from_unchecked(&alloc, [0x11, 0x22, 0x33]) };
    in_tuple_usize_ref.copy_from(&alloc, (0xfeedfacecafebeef_usize, 0x1122334455667788_usize));

    let out_slice_max_usize = in_out_slice_max_usize.commit(&alloc);

    assert_block_eq(
        unsafe { buf_ptr.read() },
        [
            0xffffffffdeadbeef,
            0x00000000aaaaaaaa,
            0x0000000000000000,
            0xffffffff00000000,
            0xffffffffffffffff,
            0x0000000000000011,
            0x0000000000000022,
            0x0000000000000033,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xfeedfacecafebeef,
            0x1122334455667788,
        ],
    );
    unsafe {
        buf_ptr.write([
            0x0000feed00000000,
            0x0000000000000000,
            0x0000000000000000,
            0x4433221100000000,
            0x0000000000776655,
            0x00000000000000ff,
            0x00000000000000ee,
            0x00000000000000dd,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ])
    };

    let alloc = alloc.collect();

    assert_eq!(out_u16.collect(&alloc), 0xfeed);
    assert_eq!(
        out_slice_u8.collect(&alloc),
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
    );
    let mut out_slice_max_usize_got = [0_usize; USIZE_COUNT];
    unsafe {
        out_slice_max_usize.copy_to_unchecked(
            &alloc,
            &mut out_slice_max_usize_got[..out_slice_max_usize.len()],
        )
    };
    assert_eq!(
        out_slice_max_usize_got,
        [0xff, 0xee, 0xdd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
    );
}
