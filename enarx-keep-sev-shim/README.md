# enarx-keep-sev-shim

## Current State
* Exception handling
* Print to stdout and stderr
* Exit codes
* Can run simple static ELF app execution in Ring3 with some basic syscalls
  * C with glibc
  * C with musl
  * rust with `--target x86_64-unknown-linux-musl`

## TODO
* Lots of refactoring!
* Handle more syscalls
* Memory management via mmap() and proxying to enarx-keep-sev
* Thread creation via clone() in enarx-keep-sev and start a new CPU in enarx-keep-sev-shim 

## Testing with nightly

Currently, we need nightly for timers and interrupts.

### KVM
```console
$ cargo build --workspace
$ cargo build -p enarx-keep-sev --examples
$ cd enarx-keep-sev-shim
$ CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="../target/x86_64-unknown-linux-musl/debug/enarx-keep-sev --app ../target/x86_64-unknown-linux-musl/debug/examples/testapp --kernel" \
  cargo +nightly test --features test_kvm
```

### QEMU
```console
$ cd enarx-keep-sev-shim
$ CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER=$(pwd)/qemu-test-runner.sh \
  cargo +nightly test --features qemu
```

## gdb debugging with the kernel

Currently, we need nightly for timers and interrupts.

```console
$ cd enarx-keep-sev-shim
$ CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER=$(pwd)/qemu-test-runner.sh \
  cargo +nightly test --features qemu -- -S -s
```

in another terminal:

```console
$ gdb \
    -ex "add-auto-load-safe-path $(pwd)" \
    -ex "file target/x86_64-unknown-linux-musl/debug/enarx-keep-sev-shim" \
    -ex 'set arch i386:x86-64:intel' \
    -ex 'target remote localhost:1234' \
    -ex 'br _before_jump' -ex 'cont' \
    -ex 'br exec_elf' -ex 'cont'
```

Currently ring 3 elf app execution is not yet supported in qemu.
