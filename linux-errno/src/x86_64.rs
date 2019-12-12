// Copyright 2020 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! errno type and constants for x84_64

/// Errno as a transparent type
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Errno(i64);

impl From<i64> for Errno {
    #[inline(always)]
    fn from(val: i64) -> Self {
        Self(val)
    }
}

impl From<Errno> for i64 {
    #[inline(always)]
    fn from(val: Errno) -> Self {
        val.0
    }
}

// generated with
// ```bash
// $ cat include/uapi/asm-generic/errno-base.h include/uapi/asm-generic/errno.h \
//   | egrep '^#define\s+E[A-Z_0-9]+\s+[0-9]+' \
//   | while read a b c d; do \
//       echo "$d" | sed -e 's#/\*#///#;s#\*/##'; \
//       echo "pub const ${b} : Errno = Errno($c);"; \
//       echo
//     done
// ```

/// Operation not permitted
pub const EPERM: Errno = Errno(1);

/// No such file or directory
pub const ENOENT: Errno = Errno(2);

/// No such process
pub const ESRCH: Errno = Errno(3);

/// Interrupted system call
pub const EINTR: Errno = Errno(4);

/// I/O error
pub const EIO: Errno = Errno(5);

/// No such device or address
pub const ENXIO: Errno = Errno(6);

/// Argument list too long
pub const E2BIG: Errno = Errno(7);

/// Exec format error
pub const ENOEXEC: Errno = Errno(8);

/// Bad file number
pub const EBADF: Errno = Errno(9);

/// No child processes
pub const ECHILD: Errno = Errno(10);

/// Try again
pub const EAGAIN: Errno = Errno(11);

/// Out of memory
pub const ENOMEM: Errno = Errno(12);

/// Permission denied
pub const EACCES: Errno = Errno(13);

/// Bad address
pub const EFAULT: Errno = Errno(14);

/// Block device required
pub const ENOTBLK: Errno = Errno(15);

/// Device or resource busy
pub const EBUSY: Errno = Errno(16);

/// File exists
pub const EEXIST: Errno = Errno(17);

/// Cross-device link
pub const EXDEV: Errno = Errno(18);

/// No such device
pub const ENODEV: Errno = Errno(19);

/// Not a directory
pub const ENOTDIR: Errno = Errno(20);

/// Is a directory
pub const EISDIR: Errno = Errno(21);

/// Invalid argument
pub const EINVAL: Errno = Errno(22);

/// File table overflow
pub const ENFILE: Errno = Errno(23);

/// Too many open files
pub const EMFILE: Errno = Errno(24);

/// Not a typewriter
pub const ENOTTY: Errno = Errno(25);

/// Text file busy
pub const ETXTBSY: Errno = Errno(26);

/// File too large
pub const EFBIG: Errno = Errno(27);

/// No space left on device
pub const ENOSPC: Errno = Errno(28);

/// Illegal seek
pub const ESPIPE: Errno = Errno(29);

/// Read-only file system
pub const EROFS: Errno = Errno(30);

/// Too many links
pub const EMLINK: Errno = Errno(31);

/// Broken pipe
pub const EPIPE: Errno = Errno(32);

/// Math argument out of domain of func
pub const EDOM: Errno = Errno(33);

/// Math result not representable
pub const ERANGE: Errno = Errno(34);

/// Resource deadlock would occur
pub const EDEADLK: Errno = Errno(35);

/// File name too long
pub const ENAMETOOLONG: Errno = Errno(36);

/// No record locks available
pub const ENOLCK: Errno = Errno(37);

/// Invalid system call number
pub const ENOSYS: Errno = Errno(38);

/// Directory not empty
pub const ENOTEMPTY: Errno = Errno(39);

/// Too many symbolic links encountered
pub const ELOOP: Errno = Errno(40);

/// No message of desired type
pub const ENOMSG: Errno = Errno(42);

/// Identifier removed
pub const EIDRM: Errno = Errno(43);

/// Channel number out of range
pub const ECHRNG: Errno = Errno(44);

/// Level 2 not synchronized
pub const EL2NSYNC: Errno = Errno(45);

/// Level 3 halted
pub const EL3HLT: Errno = Errno(46);

/// Level 3 reset
pub const EL3RST: Errno = Errno(47);

/// Link number out of range
pub const ELNRNG: Errno = Errno(48);

/// Protocol driver not attached
pub const EUNATCH: Errno = Errno(49);

/// No CSI structure available
pub const ENOCSI: Errno = Errno(50);

/// Level 2 halted
pub const EL2HLT: Errno = Errno(51);

/// Invalid exchange
pub const EBADE: Errno = Errno(52);

/// Invalid request descriptor
pub const EBADR: Errno = Errno(53);

/// Exchange full
pub const EXFULL: Errno = Errno(54);

/// No anode
pub const ENOANO: Errno = Errno(55);

/// Invalid request code
pub const EBADRQC: Errno = Errno(56);

/// Invalid slot
pub const EBADSLT: Errno = Errno(57);

/// Bad font file format
pub const EBFONT: Errno = Errno(59);

/// Device not a stream
pub const ENOSTR: Errno = Errno(60);

/// No data available
pub const ENODATA: Errno = Errno(61);

/// Timer expired
pub const ETIME: Errno = Errno(62);

/// Out of streams resources
pub const ENOSR: Errno = Errno(63);

/// Machine is not on the network
pub const ENONET: Errno = Errno(64);

/// Package not installed
pub const ENOPKG: Errno = Errno(65);

/// Object is remote
pub const EREMOTE: Errno = Errno(66);

/// Link has been severed
pub const ENOLINK: Errno = Errno(67);

/// Advertise error
pub const EADV: Errno = Errno(68);

/// Srmount error
pub const ESRMNT: Errno = Errno(69);

/// Communication error on send
pub const ECOMM: Errno = Errno(70);

/// Protocol error
pub const EPROTO: Errno = Errno(71);

/// Multihop attempted
pub const EMULTIHOP: Errno = Errno(72);

/// RFS specific error
pub const EDOTDOT: Errno = Errno(73);

/// Not a data message
pub const EBADMSG: Errno = Errno(74);

/// Value too large for defined data type
pub const EOVERFLOW: Errno = Errno(75);

/// Name not unique on network
pub const ENOTUNIQ: Errno = Errno(76);

/// File descriptor in bad state
pub const EBADFD: Errno = Errno(77);

/// Remote address changed
pub const EREMCHG: Errno = Errno(78);

/// Can not access a needed shared library
pub const ELIBACC: Errno = Errno(79);

/// Accessing a corrupted shared library
pub const ELIBBAD: Errno = Errno(80);

/// .lib section in a.out corrupted
pub const ELIBSCN: Errno = Errno(81);

/// Attempting to link in too many shared libraries
pub const ELIBMAX: Errno = Errno(82);

/// Cannot exec a shared library directly
pub const ELIBEXEC: Errno = Errno(83);

/// Illegal byte sequence
pub const EILSEQ: Errno = Errno(84);

/// Interrupted system call should be restarted
pub const ERESTART: Errno = Errno(85);

/// Streams pipe error
pub const ESTRPIPE: Errno = Errno(86);

/// Too many users
pub const EUSERS: Errno = Errno(87);

/// Socket operation on non-socket
pub const ENOTSOCK: Errno = Errno(88);

/// Destination address required
pub const EDESTADDRREQ: Errno = Errno(89);

/// Message too long
pub const EMSGSIZE: Errno = Errno(90);

/// Protocol wrong type for socket
pub const EPROTOTYPE: Errno = Errno(91);

/// Protocol not available
pub const ENOPROTOOPT: Errno = Errno(92);

/// Protocol not supported
pub const EPROTONOSUPPORT: Errno = Errno(93);

/// Socket type not supported
pub const ESOCKTNOSUPPORT: Errno = Errno(94);

/// Operation not supported on transport endpoint
pub const EOPNOTSUPP: Errno = Errno(95);

/// Protocol family not supported
pub const EPFNOSUPPORT: Errno = Errno(96);

/// Address family not supported by protocol
pub const EAFNOSUPPORT: Errno = Errno(97);

/// Address already in use
pub const EADDRINUSE: Errno = Errno(98);

/// Cannot assign requested address
pub const EADDRNOTAVAIL: Errno = Errno(99);

/// Network is down
pub const ENETDOWN: Errno = Errno(100);

/// Network is unreachable
pub const ENETUNREACH: Errno = Errno(101);

/// Network dropped connection because of reset
pub const ENETRESET: Errno = Errno(102);

/// Software caused connection abort
pub const ECONNABORTED: Errno = Errno(103);

/// Connection reset by peer
pub const ECONNRESET: Errno = Errno(104);

/// No buffer space available
pub const ENOBUFS: Errno = Errno(105);

/// Transport endpoint is already connected
pub const EISCONN: Errno = Errno(106);

/// Transport endpoint is not connected
pub const ENOTCONN: Errno = Errno(107);

/// Cannot send after transport endpoint shutdown
pub const ESHUTDOWN: Errno = Errno(108);

/// Too many references: cannot splice
pub const ETOOMANYREFS: Errno = Errno(109);

/// Connection timed out
pub const ETIMEDOUT: Errno = Errno(110);

/// Connection refused
pub const ECONNREFUSED: Errno = Errno(111);

/// Host is down
pub const EHOSTDOWN: Errno = Errno(112);

/// No route to host
pub const EHOSTUNREACH: Errno = Errno(113);

/// Operation already in progress
pub const EALREADY: Errno = Errno(114);

/// Operation now in progress
pub const EINPROGRESS: Errno = Errno(115);

/// Stale file handle
pub const ESTALE: Errno = Errno(116);

/// Structure needs cleaning
pub const EUCLEAN: Errno = Errno(117);

/// Not a XENIX named type file
pub const ENOTNAM: Errno = Errno(118);

/// No XENIX semaphores available
pub const ENAVAIL: Errno = Errno(119);

/// Is a named type file
pub const EISNAM: Errno = Errno(120);

/// Remote I/O error
pub const EREMOTEIO: Errno = Errno(121);

/// Quota exceeded
pub const EDQUOT: Errno = Errno(122);

/// No medium found
pub const ENOMEDIUM: Errno = Errno(123);

/// Wrong medium type
pub const EMEDIUMTYPE: Errno = Errno(124);

/// Operation Canceled
pub const ECANCELED: Errno = Errno(125);

/// Required key not available
pub const ENOKEY: Errno = Errno(126);

/// Key has expired
pub const EKEYEXPIRED: Errno = Errno(127);

/// Key has been revoked
pub const EKEYREVOKED: Errno = Errno(128);

/// Key was rejected by service
pub const EKEYREJECTED: Errno = Errno(129);

/// Owner died
pub const EOWNERDEAD: Errno = Errno(130);

/// State not recoverable
pub const ENOTRECOVERABLE: Errno = Errno(131);

/// Operation not possible due to RF-kill
pub const ERFKILL: Errno = Errno(132);

/// Memory page has hardware error
pub const EHWPOISON: Errno = Errno(133);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(1i64, EPERM.into());
        assert_eq!(EPERM, 1i64.into());
    }
}
