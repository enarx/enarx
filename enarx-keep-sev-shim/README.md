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

## Execute an Elf payload

### KVM
```console
$ cargo build --workspace
$ ./target/x86_64-unknown-linux-musl/debug/enarx-keep-sev \
  --shim ./target/x86_64-unknown-linux-musl/debug/enarx-keep-sev-shim \
  --code ./target/x86_64-unknown-linux-musl/debug/payload
```

### QEMU
```console
$ cd enarx-keep-sev-shim
$ cargo build --workspace
$ CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="$(pwd)/qemu-test-runner.sh --code ../target/x86_64-unknown-linux-musl/debug/payload --shim" \
  cargo run --features qemu
```

with kvm
```console
$ cd enarx-keep-sev-shim
$ cargo build --workspace
$ CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="$(pwd)/qemu-test-runner.sh --code ../target/x86_64-unknown-linux-musl/debug/payload --shim" \
  cargo run --features qemu -- -- -enable-kvm
```

## Testing

Currently, nightly is needed for `feature(custom_test_frameworks)`.

### KVM
```console
$ cd enarx-keep-sev-shim
$ cargo build --workspace
$ CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="../target/x86_64-unknown-linux-musl/debug/enarx-keep-sev --code ../target/x86_64-unknown-linux-musl/debug/payload --shim" \
  cargo +nightly test --features test_kvm
```

### QEMU

```console
$ cd enarx-keep-sev-shim
$ cargo build --workspace
$ CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="$(pwd)/qemu-test-runner.sh --code ../target/x86_64-unknown-linux-musl/debug/payload --shim" \
  cargo +nightly test --features test_qemu
```

with kvm:
```console
$ CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="$(pwd)/qemu-test-runner.sh --code ../target/x86_64-unknown-linux-musl/debug/payload --shim" \
  cargo +nightly test --features test_qemu -- -- -enable-kvm
```

## gdb debugging with the `enarx-keep-sev-shim` kernel

Currently, we need nightly for timers and interrupts.

```console
$ cd enarx-keep-sev-shim
$ cargo build --workspace
$ CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="$(pwd)/qemu-test-runner.sh --code ../target/x86_64-unknown-linux-musl/debug/payload --shim" \
  cargo run --features qemu -- -- -S -s
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

to debug the app, continue with:
```console
> br _usermode
> next
> next
> file target/x86_64-unknown-linux-musl/debug/app
> br _start
> br app::main
> cont
```
