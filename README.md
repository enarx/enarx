# Enarx
A client for deploying WebAssembly applications into Enarx Keeps.

This is currently a placeholder repository.

In the meantime, please refer to the [project's documentation](https://github.com/enarx/enarx.github.io/wiki/Enarx-Introduction) for more information.

# Setting up the Development Environment

## debian, Ubuntu

Additional packages:
* libssl-dev
* musl-dev
* musl-tools

## Fedora

`musl` is not in the standard repos, so you need to get them from a copr like
 https://copr.fedorainfracloud.org/coprs/taocris/musl/

```bash
# dnf copr enable taocris/musl
# dnf install musl-devel musl-libc-static musl-gcc musl-clang 
```

## Rust

```bash
$ rustup target add x86_64-unknown-linux-musl
```