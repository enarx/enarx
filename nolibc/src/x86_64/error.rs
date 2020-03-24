// SPDX-License-Identifier: Apache-2.0

//! errno type and constants for x84_64

// Number values generated with:
//
// ```
// bindgen /usr/include/errno.h \
//   | sed -rn 's|pub const (E[A-Z0-9_]*): u32 = ([0-9]+);|\1 = \2,|p' \
//   | sort -g -t= -k2
// ```

// The last 4095 numbers are errrnos.
const ERRNO_BASE: u64 = !0xfff;

enumerate::enumerate! {
    pub enum Number: i64 {
        EPERM = 1,
        ENOENT = 2,
        ESRCH = 3,
        EINTR = 4,
        EIO = 5,
        ENXIO = 6,
        E2BIG = 7,
        ENOEXEC = 8,
        EBADF = 9,
        ECHILD = 10,
        EAGAIN = 11,
        EWOULDBLOCK = 11,
        ENOMEM = 12,
        EACCES = 13,
        EFAULT = 14,
        ENOTBLK = 15,
        EBUSY = 16,
        EEXIST = 17,
        EXDEV = 18,
        ENODEV = 19,
        ENOTDIR = 20,
        EISDIR = 21,
        EINVAL = 22,
        ENFILE = 23,
        EMFILE = 24,
        ENOTTY = 25,
        ETXTBSY = 26,
        EFBIG = 27,
        ENOSPC = 28,
        ESPIPE = 29,
        EROFS = 30,
        EMLINK = 31,
        EPIPE = 32,
        EDOM = 33,
        ERANGE = 34,
        EDEADLK = 35,
        EDEADLOCK = 35,
        ENAMETOOLONG = 36,
        ENOLCK = 37,
        ENOSYS = 38,
        ENOTEMPTY = 39,
        ELOOP = 40,
        ENOMSG = 42,
        EIDRM = 43,
        ECHRNG = 44,
        EL2NSYNC = 45,
        EL3HLT = 46,
        EL3RST = 47,
        ELNRNG = 48,
        EUNATCH = 49,
        ENOCSI = 50,
        EL2HLT = 51,
        EBADE = 52,
        EBADR = 53,
        EXFULL = 54,
        ENOANO = 55,
        EBADRQC = 56,
        EBADSLT = 57,
        EBFONT = 59,
        ENOSTR = 60,
        ENODATA = 61,
        ETIME = 62,
        ENOSR = 63,
        ENONET = 64,
        ENOPKG = 65,
        EREMOTE = 66,
        ENOLINK = 67,
        EADV = 68,
        ESRMNT = 69,
        ECOMM = 70,
        EPROTO = 71,
        EMULTIHOP = 72,
        EDOTDOT = 73,
        EBADMSG = 74,
        EOVERFLOW = 75,
        ENOTUNIQ = 76,
        EBADFD = 77,
        EREMCHG = 78,
        ELIBACC = 79,
        ELIBBAD = 80,
        ELIBSCN = 81,
        ELIBMAX = 82,
        ELIBEXEC = 83,
        EILSEQ = 84,
        ERESTART = 85,
        ESTRPIPE = 86,
        EUSERS = 87,
        ENOTSOCK = 88,
        EDESTADDRREQ = 89,
        EMSGSIZE = 90,
        EPROTOTYPE = 91,
        ENOPROTOOPT = 92,
        EPROTONOSUPPORT = 93,
        ESOCKTNOSUPPORT = 94,
        ENOTSUP = 95,
        EOPNOTSUPP = 95,
        EPFNOSUPPORT = 96,
        EAFNOSUPPORT = 97,
        EADDRINUSE = 98,
        EADDRNOTAVAIL = 99,
        ENETDOWN = 100,
        ENETUNREACH = 101,
        ENETRESET = 102,
        ECONNABORTED = 103,
        ECONNRESET = 104,
        ENOBUFS = 105,
        EISCONN = 106,
        ENOTCONN = 107,
        ESHUTDOWN = 108,
        ETOOMANYREFS = 109,
        ETIMEDOUT = 110,
        ECONNREFUSED = 111,
        EHOSTDOWN = 112,
        EHOSTUNREACH = 113,
        EALREADY = 114,
        EINPROGRESS = 115,
        ESTALE = 116,
        EUCLEAN = 117,
        ENOTNAM = 118,
        ENAVAIL = 119,
        EISNAM = 120,
        EREMOTEIO = 121,
        EDQUOT = 122,
        ENOMEDIUM = 123,
        EMEDIUMTYPE = 124,
        ECANCELED = 125,
        ENOKEY = 126,
        EKEYEXPIRED = 127,
        EKEYREVOKED = 128,
        EKEYREJECTED = 129,
        EOWNERDEAD = 130,
        ENOTRECOVERABLE = 131,
        ERFKILL = 132,
        EHWPOISON = 133,
    }
}

impl Number {
    pub fn from_syscall(ret: u64) -> Option<Self> {
        if ret > ERRNO_BASE {
            let ret = ret as i64;
            Some(Self::from(-ret))
        } else {
            None
        }
    }

    pub fn into_syscall(self) -> u64 {
        -self.0 as u64
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(1i64, Number::EPERM.into());
        assert_eq!(Number::EPERM, 1i64.into());
    }
}
