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
$ ./helper/parse-trace.sh <shim> [<exec>]
```

`parse-trace.sh` needs `addr2line` from `binutils`, so make sure that is installed.

In order to select one of the built shim-kvm artifacts, run this:

```console
$ find target \
  \( -perm -u=x -o -perm -g=x -o -perm -o=x \) \
  -wholename "*debug*bin/enarx_shim_kvm*"
```

Then, you can pick a shim to e.g. an (unexported) shell variable, and
progress further with your debugging session.

Now, let's go through a couple of examples, with `SHIM` containing
the path to the target shim binary.

Parsing traceback from a file:
```console
$ ./helper/parse-trace.sh $SHIM < traceback.txt
```

Reading traceback from pipe:
```console
$ cargo run -- exec <exec> |& ./helper/parse-trace.sh $SHIM
```

## GDB

To enable gdb support, compile enarx with the `gdb` feature:

```console
$ cargo clean
$ cargo build --features gdb
```

### KVM / SEV-SNP

Find the "shim" of the TEE. Normally this is `shim-kvm`:
```console
$ find target -wholename '*linux-musl/*/shim-kvm'
target/debug/build/enarx-f0e8a07172ba3be9/out/internal/shim-kvm/x86_64-unknown-linux-musl/debug/shim-kvm
```

Find the "exec" of the TEE. Normally this is `wasmldr`:
```console
$ find target -wholename '*linux-musl/*/wasmldr'
target/debug/build/enarx-f0e8a07172ba3be9/out/internal/wasmldr/x86_64-unknown-linux-musl/debug/wasmldr
```

Start the TEE:
```console
$ ./target/debug/enarx run ~/git/zerooneone/target/wasm32-wasi/debug/zerooneone.wasm
[…]
Starting GDB session...
symbol-file -o 0xffffff8000000000 <shim>
add-symbol-file -o 0x7f6ffbef8000 <exec>
[…]
Waiting for a GDB connection on "localhost:23456"...
```

You can set the listen address with `--gdblisten <address>`.

Now connect with `gdb` from another terminal and load the symbols from the debug executables as mentioned by the output
with the offsets mentioned. Note: the offsets can vary for every run due to address space layout randomization (ASLR).
```console
$ gdb
[…]
(gdb) symbol-file -o 0xffffff8000000000 target/debug/build/enarx-f0e8a07172ba3be9/out/internal/shim-kvm/x86_64-unknown-linux-musl/debug/shim-kvm
Reading symbols from target/debug/build/enarx-f0e8a07172ba3be9/out/internal/shim-kvm/x86_64-unknown-linux-musl/debug/shim-kvm...

(gdb) add-symbol-file -o 0x7f6ffbef8000 target/debug/build/enarx-f0e8a07172ba3be9/out/internal/wasmldr/x86_64-unknown-linux-musl/debug/wasmldr
add symbol table from file "target/debug/build/enarx-f0e8a07172ba3be9/out/internal/wasmldr/x86_64-unknown-linux-musl/debug/wasmldr" with all sections offset by 0xfbef8000
(y or n) y
[…]

(gdb) target remote localhost:23456
Remote debugging using localhost:23456
[…]
0x00007f434ee83cc9 in _start ()
```

The current execution is stopped in the "exec" executable at the ELF entry point `_start`. You can now start debugging the "exec".

```console
(gdb) br wasmldr::main
Breakpoint 1 at 0x7f434efddbeb: file src/main.rs, line 72.
(gdb) cont
Continuing.

Breakpoint 1, wasmldr::main () at src/main.rs:72
72	    env_logger::Builder::from_default_env().init();
(gdb) list
67	fn main() {
68	    // KEEP-CONFIG HACK: we've inherited stdio and the shim sets
69	    // "RUST_LOG=debug", so this should make logging go to stderr.
70	    // FUTURE: we should have a keep-provided debug channel where we can
71	    // (safely, securely) send logs. Might need our own logger for that..
72	    env_logger::Builder::from_default_env().init();
73	
74	    info!("version {} starting up", env!("CARGO_PKG_VERSION"));
75	
76	    warn!("🌭DEV-ONLY BUILD, NOT FOR PRODUCTION USE🌭");
(gdb) print $pc
$1 = (*mut fn ()) 0x7f434efddbeb <wasmldr::main+11>
(gdb) stepi
0x00007f434efddbf2	72	    env_logger::Builder::from_default_env().init();
(gdb) print $pc
$2 = (*mut fn ()) 0x7f434efddbf2 <wasmldr::main+18>
(gdb) stepi
0x00007f434efddbf9	72	    env_logger::Builder::from_default_env().init();
(gdb) print $pc
$3 = (*mut fn ()) 0x7f434efddbf9 <wasmldr::main+25>
```

### SGX

Before starting the debugging session, make sure you are in the project root
directory, and make a debug build with the `gdb` feature flag:

```
cargo build --features gdb
```

First, an appropriate shim binary for the debugging session must be found. An
existing shim can be selected by issuing:

```console
$ find target \
  \( -perm -u=x -o -perm -g=x -o -perm -o=x \) \
  -wholename "*debug*bin/enarx_shim_sgx*"
```

`wasmtime` is contained to the shim but it is embedded as an anonymous blob.
Therefore, the matching ELF-file of `wasmtime`  must be also found.  An existing
`wasmtime` binary can be selected by issuing:

```console
$ find target \
  \( -perm -u=x -o -perm -g=x -o -perm -o=x \) \
  -wholename "*debug*bin/enarx_exec_wasmtime*"
```

Now, let's go through an example, starting at the point when the target binaries
have been already selected.  The next step would be to find out the virtual
addresses for the symbol resolution, so that GDB will know how to base the
relocation correctly.

Shim's virtual address is visible in `/proc/<pid>/maps`.  Just look up for the
entry with `/dev/sgx_enclave` mapped.  Theoretically it is possible that this is
not the same as shim's base address, as the host could have simply unmapped some
pages from the head.

Likewise, as dictated by `crates/shim-sgx/layout.ld`,  `wasmtime` is probably
placed at the offset `0x40000000`.  For example, if shim's address is
`0x7fcf00000000`, then `wasmtime` is likely located at `0x7fcf00400000`.

To overcome this issue, `enarx`, when built with the `gdb` feature, will print
out the correct addresses to the console before it starts to wait for GDB:

```console
$ ./target/debug/enarx run <wasm-file>
[…]
Starting GDB session...
symbol-file -o 0x7fcf00000000 <shim>
add-symbol-file -o 0x7fcf00400000 <exec>
Waiting for a GDB connection on "localhost:23456"...
```

`enarx` command-line supports `--gdblisten <address>`, when compiled with `gdb`
feature, if a different listen address is preferred over 23456.
