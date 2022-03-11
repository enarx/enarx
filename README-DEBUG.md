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

To find the shim with the debug info and not stripped run this:

```console
$ find target -wholename '*linux-musl/*/shim-kvm'
```

Then choose either the `debug` or `release`, depending with which version the panic occurred.

## Examples

### From a File
```console
$ ./helper/parse-trace.sh \
  target/debug/build/*/out/internal/shim-kvm/x86_64-unknown-linux-musl/debug/shim-kvm \
  < traceback.txt
```

### Pipe

```console
$ cargo run -- exec <exec> |& ./helper/parse-trace.sh \
  target/debug/build/*/out/internal/shim-kvm/x86_64-unknown-linux-musl/debug/shim-kvm 
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

Find the "shim" of the TEE. Normally this is `shim-sgx`:
```console
$ find target -wholename '*linux-musl/*/shim-sgx'
target/debug/build/enarx-f0e8a07172ba3be9/out/internal/shim-sgx/x86_64-unknown-linux-musl/debug/shim-sgx
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
symbol-file -o 0x7fcf00000000 <shim>
symbol-file -o 0x7fcf00400000 <exec>
Waiting for a GDB connection on "localhost:23456"...
```

You can set the listen address with `--gdblisten <address>`.

Now connect with `gdb` from another terminal and load the symbols from the debug executables as mentioned by the output
with the offsets mentioned. Note: the offsets can vary for every run due to address space layout randomization (ASLR).

```console
$ gdb
[…]

(gdb) symbol-file -o 0x7fcf00400000 target/debug/build/enarx-f0e8a07172ba3be9/out/internal/wasmldr/x86_64-unknown-linux-musl/debug/wasmldr
Reading symbols from target/debug/build/enarx-f0e8a07172ba3be9/out/internal/wasmldr/x86_64-unknown-linux-musl/debug/wasmldr...
warning: Missing auto-load script at offset 0 in section .debug_gdb_scripts
of file /home/harald/git/enarx/enarx/target/debug/build/enarx-f0e8a07172ba3be9/out/internal/wasmldr/x86_64-unknown-linux-musl/debug/wasmldr.
Use `info auto-load python-scripts [REGEXP]' to list them.

(gdb) target remote localhost:23456
Remote debugging using localhost:23456
[…]
0x00007f434ee83cc9 in _start ()
```

The current execution is stopped in the "exec" executable at the ELF entry point `_start`. You can now start debugging the "exec".

NOTE: stepping does not work (yet) in SGX.

```console
(gdb) br wasmldr::main
Breakpoint 1 at 0x7fcf007368cb: file src/main.rs, line 72.
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
(gdb) br workload::run
Breakpoint 2 at 0x7fcf005f6c64: file src/workload.rs, line 81.
(gdb) cont
Continuing.

Breakpoint 2, wasmldr::workload::run<alloc::string::String, alloc::string::String, alloc::vec::Vec<u8, alloc::alloc::Global>, alloc::vec::Vec<alloc::string::String, alloc::alloc::Global>, alloc::vec::Vec<(alloc::string::String, alloc::string::String), alloc::alloc::Global>> (bytes=..., args=..., envs=...) at src/workload.rs:81
81	    debug!("configuring wasmtime engine");
(gdb) list
76	pub fn run<T: AsRef<str>, U: AsRef<str>>(
77	    bytes: impl AsRef<[u8]>,
78	    args: impl IntoIterator<Item = T>,
79	    envs: impl IntoIterator<Item = (U, U)>,
80	) -> Result<Box<[wasmtime::Val]>> {
81	    debug!("configuring wasmtime engine");
82	    let mut config = wasmtime::Config::new();
83	    // Support module-linking (https://github.com/webassembly/module-linking)
84	    config.wasm_module_linking(true);
85	    // module-linking requires multi-memory
```
