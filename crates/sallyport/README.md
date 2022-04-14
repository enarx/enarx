# sallyport

API for the hypervisor-microkernel boundary

`sallyport` is a protocol crate for proxying service requests (such as syscalls) from an Enarx Keep
to the host. A [sally port](https://en.wikipedia.org/wiki/Sally_port) is a secure gateway through
which a defending army might "sally forth" from the protection of their fortification.

## Mechanism of action

`sallyport` works by providing the host with the most minimal register context it requires to
perform the syscall on the Keep's behalf. In doing so, the host can immediately call the desired
syscall without any additional logic required.

Guest and host side communicate via a mutually-distrusted shared block of memory.

This crate provides functionality for the guest to execute arbitary requests by proxying requests to the host via
the untrusted block and corresponding functionality for the host to execute the requests contained within the untrusted block.

## Block format

The sallyport [block](item::Block) is a region of memory containing zero or more [items](item::Item).
All items contain the following [header](item::Header):

* size: `usize`
* kind: `usize`

The size parameter includes the full length of the item except the header value. The contents of the item are defined by the value of the [`kind`](item::Kind) parameter. An item with an unknown [`kind`](item::Kind) can be skipped since the length of the item is known from the `size` field. The recipient of an item with an unknown [`kind`](item::Kind) MUST NOT try to interpret or modify the contents of the item in any way.

### Kinds

* `END`: `0`
* `SYSCALL`: `1`
* `GDBCALL`: `2`
* `ENARXCALL`: `3`

#### End

An [`END`](item::Kind::End) item MUST have a `size` of `0`. It has no contents and simply marks the end of items in the block. This communicates the end of the items list to the host. However, the guest MUST NOT rely on the presence of a terminator upon return to the guest.

#### System call

A `SYSCALL` item has the following contents:

* `nmbr`: `usize` - the system call number
* `arg0`: `usize` - the first argument
* `arg1`: `usize` - the second argument
* `arg2`: `usize` - the third argument
* `arg3`: `usize` - the fourth argument
* `arg4`: `usize` - the fifth argument
* `arg5`: `usize` - the sixth argument
* `ret0`: `usize` - the first return value
* `ret1`: `usize` - the second return value
* `data`: `...` - data that can be referenced (optional)

#### GDB call

A `GDBCALL` item has the following contents:

* `nmbr`: `usize` - the [GDB call number](item::gdbcall::Number)
* `arg0`: `usize` - the first argument
* `arg1`: `usize` - the second argument
* `arg2`: `usize` - the third argument
* `arg3`: `usize` - the fourth argument
* `ret`: `usize` - the return value
* `data`: `...` - data that can be referenced (optional)

#### Enarx call

A `ENARXCALL` item has the following contents:

* `nmbr`: `usize` - the [Enarx call number](item::enarxcall::Number)
* `arg0`: `usize` - the first argument
* `arg1`: `usize` - the second argument
* `arg2`: `usize` - the third argument
* `arg3`: `usize` - the fourth argument
* `ret`: `usize` - the return value
* `data`: `...` - data that can be referenced (optional)


The argument values may contain numeric values. However, all pointers MUST be translated to an offset from the beginning of the data section.

### Example

Here's an example of how the `sallyport` protocol might be used to proxy a syscall between
the host and a protected virtual machine:

1. The workload within the Keep makes a `write` syscall.
1. The shim traps all syscalls, and notices this is a `write` syscall.
1. The shim allocates space for an [item header](item::Header), syscall number, six arguments, two return values, as many bytes that the workload wants to write as fits in the block and an [`END`](item::Kind::End) [item header](item::Header).
1. The shim writes the [item header](item::Header), argument values and copies the bytes that the workload wants to write onto the data region of the block. It is now accessible to the host.
1. The shim writes to the allocated section. In the case of the `write` syscall, the shim:
    1. Writes the [item header](item::Header) with item `kind` set to [`Syscall`](item::Kind::Syscall) and size equal to 9 + count of allocated bytes to write (syscall number + arguments + return values + data length).
    1. Writes the request `nmbr` equal to the Linux integral value for [`SYS_write`](libc::SYS_write).
    1. Writes the syscall arguments and return values:
        1. `arg0` = The file descriptor to write to.
        1. `arg1` = The offset starting after the last return value where the bytes have been copied to.
        1. `arg2` = The number of bytes that the `write` syscall should emit from the bytes pointed to in the second parameter.
        1. `arg3` = [`NULL`]
        1. `arg4` = [`NULL`]
        1. `arg5` = [`NULL`]
        1. `ret0` = [`-ENOSYS`](libc::ENOSYS)
        1. `ret1` = `0`
    1. Copies the bytes to write into the allocated section.
1. The shim yields control to the untrusted host, in which host-side Enarx code realizes it must proxy a syscall.
1. The host-side Enarx code can invoke the syscall immediately using the values in the block.
1. Once the syscall is complete, the host-side Enarx code can update the syscall return value section write the syscall return code to it.
1. The host-side Enarx code returns control to the shim.
1. The shim examines the block and propagates any mutated data back to the protected address space. It may then return control to its workload.

License: Apache-2.0
