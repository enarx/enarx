# Debugging

## Stack Trace

### KVM / SEV

If you encounter unexpected shutdowns or panics like:

```
panicked at 'explicit panic', src/syscall.rs:167:9
TRACE:
  0x000000000000f876
  0x0000000000039d10
  0x0000000000007189
  0x0000000000008d3e
  0x0000000000008b58
P 0x0000000000001279
P 0x000000000000102c
```

or

```
Error: Shutdown Ok(
    kvm_regs {
        rax: 0x29f47,
        rbx: 0x2a014,
        rcx: 0x15475,
        rdx: 0x246e8,
        rsi: 0x269b0,
        rdi: 0x1e2db,
        rsp: 0xffffff8000433900,
        rbp: 0xffffff8000433a70,
        r8: 0x129cb,
        r9: 0x29ed7,
        r10: 0x2a074,
        r11: 0x154f5,
        r12: 0x259b0,
        r13: 0x268f0,
        r14: 0x109ac,
        r15: 0x30889,
        rip: 0xffffff8000230662,
        rflags: 0x10046,
    },
)
```

you might get a meaningful stack backtrace with the `helper/parse-trace.sh` script:

```console
$ ./helper/parse-trace.sh <shim> [<payload>]
```

`parse-trace.sh` needs `addr2line` from `binutils`, so make sure that is installed.

To find the shim with the debug info and not stripped run this:

```console
$ find target -wholename '*linux-musl/*/shim-sev'
```

Then choose either the `debug` or `release`, depending with which version the panic occurred.

## Examples

### From a File
```console
$ ./helper/parse-trace.sh \
  target/debug/build/*/out/internal/shim-sev/x86_64-unknown-linux-musl/debug/shim-sev \
  < traceback.txt
```

### Pipe

```console
$ cargo run -- exec <payload> |& ./helper/parse-trace.sh \
  target/debug/build/*/out/internal/shim-sev/x86_64-unknown-linux-musl/debug/shim-sev 
```

