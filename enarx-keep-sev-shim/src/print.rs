// SPDX-License-Identifier: Apache-2.0

//! Functions and macros to output text on the host

use crate::hostcall::{self, HostFd};

struct HostWrite(HostFd);

use core::fmt;

impl fmt::Write for HostWrite {
    #[inline(always)]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        hostcall::shim_write_all(self.0, s.as_bytes()).map_err(|_| fmt::Error)?;
        Ok(())
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;

    HostWrite(unsafe { HostFd::from_raw_fd(libc::STDOUT_FILENO) })
        .write_fmt(args)
        .expect("Printing via Host fd 1 failed");
}

#[doc(hidden)]
#[inline(always)]
pub fn _eprint(args: fmt::Arguments) {
    use fmt::Write;

    HostWrite(unsafe { HostFd::from_raw_fd(libc::STDERR_FILENO) })
        .write_fmt(args)
        .expect("Printing via Host fd 2 failed");
}

/// Prints to the standard output of the host.
///
/// Equivalent to the [`println!`] macro except that a newline is not printed at
/// the end of the message.
///
/// [`println!`]: macro.println.html
///
/// # Panics
///
/// Panics if writing to the host fails.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::print::_print(format_args!($($arg)*));
    };
}

/// Prints to the standard output of the host, with a newline.
///
/// Use the `format!` syntax to write data to the standard output.
/// See `core::fmt` for more information.
///
/// Use `println!` only for the primary output of your program. Use
/// [`eprintln!`] instead to print error and progress messages.
///
/// [`eprintln!`]: macro.eprintln.html
///
/// # Panics
///
/// Panics if writing to the host fails.
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($fmt:expr) => ($crate::print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::print!(concat!($fmt, "\n"), $($arg)*));
}

/// Prints to the standard error.
///
/// Equivalent to the [`print!`] macro, except that output goes to
/// `stderr` of the host instead of `stdout`.
///
/// Use `eprint!` only for error and progress messages. Use [`print!`]
/// instead for the primary output of your program.
///
/// [`print!`]: macro.print.html
///
/// # Panics
///
/// Panics if writing to the host fails.
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {
        $crate::print::_eprint(format_args!($($arg)*));
    };
}

/// Prints to the standard error of the host, with a newline.
///
/// Equivalent to the [`println!`] macro, except that output goes to
/// `stderr` of the host instead of `stdout`. See [`println!`] for
/// example usage.
///
/// Use `eprintln!` only for error and progress messages. Use [`println!`]
/// instead for the primary output of your program.
///
/// [`println!`]: macro.println.html
///
/// # Panics
///
/// Panics if writing to the host fails.
#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($fmt:expr) => ($crate::eprint!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::eprint!(concat!($fmt, "\n"), $($arg)*));
}

/// Prints and returns the value of a given expression for quick and dirty
/// debugging.
#[macro_export]
macro_rules! dbg {
    () => {
        $crate::eprintln!("[{}:{}]", file!(), line!());
    };
    ($val:expr $(,)?) => {
        // Use of `match` here is intentional because it affects the lifetimes
        // of temporaries - https://stackoverflow.com/a/48732525/1063961
        match $val {
            tmp => {
                $crate::eprintln!("[{}:{}] {} = {:#?}",
                    file!(), line!(), stringify!($val), &tmp);
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}
