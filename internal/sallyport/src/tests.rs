#![cfg(test)]

use super::*;

#[test]
fn req_size() {
    assert_eq!(size_of::<Request>(), size_of::<usize>() * 8);
}

#[test]
fn rep_size() {
    assert_eq!(size_of::<Reply>(), size_of::<usize>() * 3);
}

#[test]
fn msg_size() {
    assert_eq!(size_of::<Message>(), size_of::<usize>() * 8);
}

#[test]
fn block_size() {
    assert_eq!(size_of::<Block>() % Page::size(), 0);
}

#[test]
fn buf_capacity() {
    assert!(Block::buf_capacity() > MAX_UDP_PACKET_SIZE);
    assert!(Block::buf_capacity() - Page::size() < MAX_UDP_PACKET_SIZE);
}

#[test]
#[cfg_attr(miri, ignore)]
fn syscall() {
    // Test syscall failure, including bidirectional conversion.
    let req = request!(libc::SYS_close => -1isize);
    let rep = unsafe { req.syscall() };
    assert_eq!(rep, Err(libc::EBADF).into());
    assert_eq!(libc::EBADF, Result::from(rep).unwrap_err());

    // Test dup() success.
    let req = request!(libc::SYS_dup => 0usize);
    let rep = unsafe { req.syscall() };
    let dup_fd: usize = Result::from(rep).unwrap()[0].into();
    assert!(dup_fd > 0);

    // Test close() success.
    let req = request!(libc::SYS_close => dup_fd);
    let rep = unsafe { req.syscall() };
    let res = Result::from(rep).unwrap()[0].into();
    assert_eq!(0usize, res);
}

#[test]
fn request() {
    let req = request!(0 => 1, 2, 3, 4, 5, 6, 7, 8, 9);
    assert_eq!(req.num, Register::<usize>::from(0));
    assert_eq!(req.arg[0], Register::<usize>::from(1));
    assert_eq!(req.arg[1], Register::<usize>::from(2));
    assert_eq!(req.arg[2], Register::<usize>::from(3));
    assert_eq!(req.arg[3], Register::<usize>::from(4));
    assert_eq!(req.arg[4], Register::<usize>::from(5));
    assert_eq!(req.arg[5], Register::<usize>::from(6));
    assert_eq!(req.arg[6], Register::<usize>::from(7));

    let req = request!(0 => 1);
    assert_eq!(req.num, Register::<usize>::from(0));
    assert_eq!(req.arg[0], Register::<usize>::from(1));
    assert_eq!(req.arg[1], Register::<usize>::from(0));
    assert_eq!(req.arg[2], Register::<usize>::from(0));
    assert_eq!(req.arg[3], Register::<usize>::from(0));
    assert_eq!(req.arg[4], Register::<usize>::from(0));
    assert_eq!(req.arg[5], Register::<usize>::from(0));
    assert_eq!(req.arg[6], Register::<usize>::from(0));

    let req = request!(17);
    assert_eq!(req.num, Register::<usize>::from(17));
    assert_eq!(req.arg[0], Register::<usize>::from(0));
    assert_eq!(req.arg[1], Register::<usize>::from(0));
    assert_eq!(req.arg[2], Register::<usize>::from(0));
    assert_eq!(req.arg[3], Register::<usize>::from(0));
    assert_eq!(req.arg[4], Register::<usize>::from(0));
    assert_eq!(req.arg[5], Register::<usize>::from(0));
    assert_eq!(req.arg[6], Register::<usize>::from(0));
}

#[test]
fn cursor() {
    let mut block = Block::default();

    let c = block.cursor();
    assert!(c
        .alloc::<usize>(MAX_UDP_PACKET_SIZE + Page::size())
        .is_err());

    let c = block.cursor();
    assert_eq!(c.alloc::<usize>(42usize).unwrap().1.len(), 42);

    let c = block.cursor();
    let (_c, slice) = c.copy_from_slice(&[87, 2, 3]).unwrap();
    assert_eq!(&slice, &[87, 2, 3]);
}

#[test]
fn cursor_multiple_allocs() {
    let mut block = Block::default();

    let c = block.cursor();
    let (c, slab1) = c
        .copy_from_slice::<usize>(&[1, 2])
        .expect("allocate slab of 2 usize values for the first time");

    let (c, slab2) = c
        .copy_from_slice::<usize>(&[3, 4])
        .expect("allocate slab of 2 usize values for the second time");

    let (_c, slab3) = c
        .copy_from_slice::<usize>(&[5, 6])
        .expect("allocate slab of 2 usize values for the third time");

    assert_eq!(slab1, &[1, 2]);
    assert_eq!(slab2, &[3, 4]);
    assert_eq!(slab3, &[5, 6]);

    let c = block.cursor();
    let (_c, slab_all) = c
        .alloc::<usize>(6)
        .expect("re-allocate slab of 6 usize values already initialized");

    // Assume init
    let slab_all: &mut [usize] = unsafe { &mut *(slab_all as *mut _ as *mut [_]) };

    assert_eq!(slab_all, &[1, 2, 3, 4, 5, 6]);

    // An attempt at re-using a mutable subslice from the first
    // cursor when aliasing with the second cursor will correctly
    // generate a compiler error.
    // slab3.copy_from_slice(&[1, 2]);

    // However, we can copy new values over using the second cursor
    // just fine.
    slab_all.copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    assert_eq!(slab_all, &[0, 0, 0, 0, 0, 0]);
}

#[test]
fn test_read_write() -> std::result::Result<(), OutOfSpace> {
    #[derive(Debug, Clone, Copy, PartialEq)]
    #[repr(C, align(64))]
    struct Test {
        a: u64,
        b: u64,
    }

    let mut block = Block::default();

    let c = block.cursor();

    let (c, _dst) = c.write(&Test { a: 1, b: 2 })?;
    let (_c, _dst) = c.write(&Test { a: 2, b: 3 })?;

    let c = block.cursor();

    let (c, test1) = unsafe { c.read::<Test>() }?;
    let (_, test2) = unsafe { c.read::<Test>() }?;

    assert_eq!(test1, Test { a: 1, b: 2 });
    assert_eq!(test2, Test { a: 2, b: 3 });

    Ok(())
}

#[test]
fn copy_into_raw_parts() -> std::result::Result<(), OutOfSpace> {
    let mut block = Block::default();

    let c = block.cursor();
    let (c, slab1) = c
        .copy_from_slice::<usize>(&[1, 2])
        .expect("allocate slab of 2 usize values for the first time");

    let (c, slab2) = c
        .copy_from_slice::<usize>(&[3, 4])
        .expect("allocate slab of 2 usize values for the second time");

    let (_c, slab3) = c
        .copy_from_slice::<usize>(&[5, 6])
        .expect("allocate slab of 2 usize values for the third time");

    assert_eq!(slab1, &[1, 2]);
    assert_eq!(slab2, &[3, 4]);
    assert_eq!(slab3, &[5, 6]);

    let c = block.cursor();

    let mut slab_all = MaybeUninit::<[usize; 3]>::uninit();

    let c = unsafe { c.copy_into_raw_parts::<usize>(4, slab_all.as_mut_ptr() as _, 3)? };

    // Assume init
    let slab_all = unsafe { slab_all.assume_init() };

    assert_eq!(&slab_all, &[1, 2, 3]);

    let mut slab_all = MaybeUninit::<[usize; 2]>::uninit();

    unsafe {
        c.copy_into_raw_parts::<usize>(2, slab_all.as_mut_ptr() as _, 2)?;
    }

    // Assume init
    let slab_all = unsafe { slab_all.assume_init() };

    assert_eq!(&slab_all, &[5, 6]);

    Ok(())
}

#[test]
fn copy_into_slice() -> std::result::Result<(), OutOfSpace> {
    let mut block = Block::default();

    let c = block.cursor();
    let (c, slab1) = c
        .copy_from_slice::<usize>(&[1, 2])
        .expect("allocate slab of 2 usize values for the first time");

    let (c, slab2) = c
        .copy_from_slice::<usize>(&[3, 4])
        .expect("allocate slab of 2 usize values for the second time");

    let (_c, slab3) = c
        .copy_from_slice::<usize>(&[5, 6])
        .expect("allocate slab of 2 usize values for the third time");

    assert_eq!(slab1, &[1, 2]);
    assert_eq!(slab2, &[3, 4]);
    assert_eq!(slab3, &[5, 6]);

    let c = block.cursor();

    let mut slab_all = [0usize; 3];

    let c = unsafe { c.copy_into_slice::<usize>(4, &mut slab_all) }?;

    assert_eq!(&slab_all, &[1, 2, 3]);

    let mut slab_all = [0usize; 2];

    let _ = unsafe { c.copy_into_slice::<usize>(2, &mut slab_all) }?;

    assert_eq!(&slab_all, &[5, 6]);

    Ok(())
}
