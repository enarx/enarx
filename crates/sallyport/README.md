[![Workflow Status](https://github.com/enarx/sallyport/workflows/test/badge.svg)](https://github.com/enarx/sallyport/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/sallyport.svg)](https://isitmaintained.com/project/enarx/sallyport "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/sallyport.svg)](https://isitmaintained.com/project/enarx/sallyport "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# sallyport

API for the hypervisor-microkernel boundary

`sallyport` is a protocol crate for proxying service requests (such as syscalls) from an Enarx Keep
to the host. A [sally port](https://en.wikipedia.org/wiki/Sally_port) is a secure gateway through
which a defending army might "sally forth" from the protection of their fortification.

An astute reader may notice that `sallyport` is a thin layer around the Linux syscall ABI as it is
predicated on the conveyance of a service request number (such as `rax` for x86_64) as well as the
maximum number (6) of syscall parameter registers:

| Architecture | arg 1 | arg 2 | arg 3 | arg 4 | arg 5 | arg 6 |
| ------------ | ----- | ----- | ----- | ----- | ----- | ----- |
| x86_64       | rdi   | rsi   | rdx   | r10   | r8    | r9    |

_The above table was taken from the syscall(2) man page_

Note that `sallyport` is meant to generalize over all architectures that Enarx anticipates proxying
syscalls to, not just x86_64 which was listed in the above table for illustration purposes.

### Usage

`sallyport` works by providing the host with the most minimal register context it requires to
perform the syscall on the Keep's behalf. In doing so, the host can immediately call the desired
syscall without any additional logic required. This "register context" is known as a `Message` in
`sallyport` parlance.

The `Message` union has two representations:

1. `Request`: The register context needed to perform a request or syscall. This includes an identifier
and up to the 6 maximum syscall parameter registers expected by the Linux syscall ABI.
2. `Reply`: A response from the host. This representation exists to cater to how each architecture
indicates a return value.

The `Message` union serves as the header for a `Block` struct, which will be examined next.

The `Block` struct is a page-sized buffer which must be written to a page that is accessible
to both the host and the Keep to facilitate request proxying. The region of memory that is
left over after storing the `Message` header on the block should be used for storing additional
parameters that must be shared with the host so it can complete the service request. In the
context of a syscall, this would be the sequence bytes to be written with a `write` syscall.

If the Keep forms a request that requires additional parameter data to be written to the `Block`,
the register context _must_ reflect this. For example, the second parameter to the `write` syscall
is a pointer to the string of bytes to be written. In this case, the `Keep` must ensure the
second register parameter points to the location where the bytes have been written _within the `Block`,
**NOT** a pointer to its protected address space_. Furthermore, once the request has been proxied, it is
the Keep's responsibility to propagate any potentially modified data back to its protected pages.

### Example

Here's an example of how the `sallyport` protocol might be used to proxy a syscall between
the host and a protected virtual machine:

1. The workload within the Keep makes a `write` syscall.
1. The shim traps all syscalls, and notices this is a `write` syscall.
1. The shim writes an empty `Block` onto the page it shares with the untrusted host.
1. The shim copies the bytes that the workload wants to write onto the data region of the `Block`. It is now
accessible to the host.
1. The shim modifies the `Message` header to be a `Request` variant. In the case of the `write` syscall, the shim:
    1. Sets the request `num` to the Linux integral value for `SYS_write`.
    1. Furnishes the register context's syscall arguments:
        1. `arg[0]` = The file descriptor to write to.
        1. `arg[1]` = The address _within the `Block`_ where the bytes have been copied to.
        1. `arg[2]` = The number of bytes that the `write` syscall should emit from the bytes pointed to
        in the second parameter.
1. The shim yields control to the untrusted host, in which host-side Enarx code realizes it must proxy a syscall.
1. The host-side Enarx code can invoke the syscall immediately using the values in the `Block`'s `Message` header.
1. Once the syscall is complete, the host-side Enarx code can update the `Block`'s header and set it to a
`Reply` variant of the `Message` union and write the syscall return code to it.
1. The host-side Enarx code returns control to the shim.
1. The shim examines the `Reply` in the `Message` header of the `Block` and propagates any mutated data back to
the protected address space. It may then return control to its workload.

License: Apache-2.0
