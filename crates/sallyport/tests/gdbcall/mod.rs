// SPDX-License-Identifier: Apache-2.0

use super::run_test;

use libc::ENOSYS;

use sallyport::guest::Handler;

#[test]
fn gdb_flush() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.gdb_flush(), Err(ENOSYS));
    })
}

#[test]
fn gdb_on_session_start() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.gdb_on_session_start(), Err(ENOSYS));
    })
}

#[test]
fn gdb_peek() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.gdb_peek(), Err(ENOSYS));
    })
}

#[test]
fn gdb_read() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.gdb_read(), Err(ENOSYS));
    })
}

#[test]
fn gdb_write() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.gdb_write(0xff), Err(ENOSYS));
    })
}

#[test]
fn gdb_write_all() {
    run_test(1, [0xff; 16], move |_, _, handler| {
        assert_eq!(handler.gdb_write_all(&[0xfe, 0xed]), Err(ENOSYS));
    })
}
