// SPDX-License-Identifier: Apache-2.0

//! print via vmsyscall

use vmsyscall::WRITE_BUF_LEN;

pub struct DummySerialPort(u32);

impl core::fmt::Write for DummySerialPort {
    #[inline(always)]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for c in s.as_bytes().chunks(WRITE_BUF_LEN) {
            crate::libc::write(self.0, c)
                .map(|_| ())
                .map_err(|_| core::fmt::Error)?;
        }
        Ok(())
    }
}

#[doc(hidden)]
pub fn _print(args: ::core::fmt::Arguments) {
    use core::fmt::Write;

    DummySerialPort(1)
        .write_fmt(args)
        .expect("Printing via vmsyscall fd 1 failed");
}

#[doc(hidden)]
pub fn _eprint(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    DummySerialPort(2)
        .write_fmt(args)
        .expect("Printing via vmsyscall fd 2 failed");
}

/// Prints to the host through the serial interface.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::arch::serial::_print(format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! serial_eprint {
    ($($arg:tt)*) => {
        $crate::arch::serial::_eprint(format_args!($($arg)*));
    };
}

/// Prints to the host through the serial interface, appending a newline.
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(concat!($fmt, "\n"), $($arg)*));
}

#[macro_export]
macro_rules! println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(concat!($fmt, "\n"), $($arg)*));
}

#[macro_export]
macro_rules! print {
    () => ();
    ($fmt:expr) => ($crate::serial_print!($fmt));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!($fmt, $($arg)*));
}

#[macro_export]
macro_rules! eprintln {
    () => ($crate::serial_eprint!("\n"));
    ($fmt:expr) => ($crate::serial_eprint!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_eprint!(concat!($fmt, "\n"), $($arg)*));
}
