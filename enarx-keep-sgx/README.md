# Overview

This command takes two static binary inputs: shim and code. It creates an
enclave and loads the two static binaries into that memory. It then executes
the enclave at the entry point for the `shim` which sets up the execution
environment inside the enclave and jumps to the entry point for the `code`.

The `code` binary should load on the low end of the enclave space while the
`shim` should load at the high end of the enclave space. This gives ample
room for a heap and stack(s) in between. Leaving some space at the very
beginning and end is customary. Enarx will use this space for things like
thread contexts. So the amount of free space can imply limits on things like
thread count.

The recommended binary locations are at least:

* `shim`: enclave end - 4MiB - `shim` size
* `code`: enclave start + 4MiB

For details on enclave size and position, see the code documentation comments.
