// SPDX-License-Identifier: Apache-2.0

use super::*;

use core::fmt::LowerHex;
use core::mem::size_of;

fn assert_block_eq<const N: usize>(got: [usize; N], expected: [usize; N]) {
    #[inline]
    fn format(iter: impl IntoIterator<Item = impl LowerHex>) -> String {
        iter.into_iter().fold(String::from("\n[\n"), |s, el| {
            format!("{} {:#018x},\n", s, el)
        }) + "]\n"
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
    let buf_ptr = &mut buf as *mut [usize; USIZE_COUNT];
    let mut free = USIZE_COUNT * size_of::<usize>();
    let mut offset = 0;

    let mut alloc = Alloc::new(&mut buf).stage();
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

    let out_slice_u8 = Output::stage_slice(&mut alloc, [0x88_u8, 0x88, 0x88, 0x88]).unwrap();
    assert_eq!(out_slice_u8.len(), 4);
    free -= 4;
    assert_eq!(alloc.free::<usize>(), USIZE_COUNT - 4);
    assert_eq!(alloc.free::<u8>(), free);
    assert_eq!(out_slice_u8.offset(), offset);
    offset += 4;

    assert_eq!(alloc.free::<usize>(), free / size_of::<usize>());
    let mut in_out_slice_max_usize = alloc.allocate_inout_slice_max(USIZE_COUNT).unwrap();
    assert_eq!(in_out_slice_max_usize.len(), free / size_of::<usize>());
    assert_eq!(alloc.free::<usize>(), 0);
    assert_eq!(alloc.free::<u8>(), 0);
    assert_eq!(in_out_slice_max_usize.offset(), offset);

    let alloc = alloc.commit();

    in_u32.commit(&alloc);
    in_slice_u32.commit(&alloc);
    unsafe { in_out_slice_max_usize.copy_from_unchecked(&alloc, [0x11, 0x22, 0x33]) };
    let out_slice_max_usize = in_out_slice_max_usize.commit(&alloc);

    assert_block_eq(
        unsafe { buf_ptr.read() },
        [
            0xffffffffdeadbeef,
            0x00000000aaaaaaaa,
            0x0000000000000000,
            0xffffffff00000000,
            0x0000000000000011,
            0x0000000000000022,
            0x0000000000000033,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
        ]
    );
    unsafe {
        buf_ptr.write([
            0x0000feed00000000,
            0x0000000000000000,
            0x0000000000000000,
            0x4433221100000000,
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
            0x0000000000000000,
        ])
    };

    let alloc = alloc.collect();

    assert_eq!(out_u16.collect(&alloc), 0xfeed);
    assert_eq!(out_slice_u8.collect(&alloc), [0x11, 0x22, 0x33, 0x44]);
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
