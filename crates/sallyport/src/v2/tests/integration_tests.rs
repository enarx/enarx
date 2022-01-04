// SPDX-License-Identifier: Apache-2.0

use std::env::temp_dir;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::prelude::AsRawFd;
use std::ptr::NonNull;
use std::slice;

use sallyport::guest::{Execute, Handler, Platform};
use sallyport::item::Block;
use sallyport::{host, Result};
use serial_test::serial;

struct TestPlatform<const N: usize>(NonNull<[usize; N]>);

impl<const N: usize> Platform for TestPlatform<N> {
    fn sally(&mut self) -> Result<()> {
        host::execute(Block::from(unsafe { &mut self.0.as_mut()[..] }));
        Ok(())
    }

    fn validate_mut<'b, T>(&self, ptr: usize) -> Result<&'b mut T> {
        Ok(unsafe { &mut *(ptr as *mut _) })
    }

    fn validate_slice_mut<'b, T>(&self, ptr: usize, len: usize) -> Result<&'b mut [T]> {
        Ok(unsafe { slice::from_raw_parts_mut(ptr as _, len) })
    }
}

fn run_test<const N: usize>(
    n: usize,
    mut block: [usize; N],
    f: impl Fn(&mut Handler<TestPlatform<N>>),
) {
    let platform = TestPlatform(NonNull::from(&mut block));
    let mut handler = Handler::new(&mut block, platform);
    for _ in 0..n {
        f(&mut handler);
    }
    let _ = block;
}

#[test]
#[serial]
fn read() {
    const EXPECTED: &str = "read";
    let path = temp_dir().join("sallyport-test-read");
    write!(&mut File::create(&path).unwrap(), "{}", EXPECTED).unwrap();

    run_test(3, [0xff; 16], move |handler| {
        let mut buf = [0u8; EXPECTED.len()];

        #[cfg(feature = "asm")]
        let expected_ret = Ok(EXPECTED.len());
        #[cfg(not(feature = "asm"))]
        let expected_ret = Err(libc::ENOSYS);

        assert_eq!(
            handler.read(File::open(&path).unwrap().as_raw_fd(), &mut buf),
            expected_ret,
        );
        #[cfg(feature = "asm")]
        assert_eq!(buf, EXPECTED.as_bytes());
    });
}

#[test]
#[serial]
fn write() {
    const EXPECTED: &str = "write";
    let path = temp_dir().join("sallyport-test-write");

    run_test(3, [0xff; 16], move |handler| {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .create(true)
            .open(&path)
            .unwrap();

        #[cfg(feature = "asm")]
        let expected_ret = Ok(EXPECTED.len());
        #[cfg(not(feature = "asm"))]
        let expected_ret = Err(libc::ENOSYS);

        assert_eq!(
            handler.write(file.as_raw_fd(), EXPECTED.as_bytes()),
            expected_ret,
        );
        let mut got = String::new();
        file.rewind().unwrap();
        file.read_to_string(&mut got).unwrap();
        #[cfg(feature = "asm")]
        assert_eq!(got, EXPECTED);
    })
}
