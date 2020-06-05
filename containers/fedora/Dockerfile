FROM fedora

# Set Rustup install location. Needed to install correctly on a container.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Install musl libc with static library
RUN dnf -y install musl-devel musl-libc-static musl-gcc musl-clang

# Install General Utilities
RUN dnf -y install procps iproute findutils man file diffutils

# Install General Development Tools
RUN dnf -y install git git-subtree vim gdb lldb valgrind strace diffstat patch hub

# Install C Development Environment
RUN dnf -y install gcc clang make

# Install Build Dependencies
RUN dnf -y install glibc-static clang-devel llvm-devel openssl-devel

# Documentation
RUN dnf -y install mscgen graphviz

# Install Rust via rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q
RUN rustup target add x86_64-unknown-linux-musl
RUN rustup component add rustfmt rls clippy

# Install binary crates
RUN cargo install --force cargo-make
RUN cargo install --force cargo-audit
RUN cargo install --force cargo-deny
RUN cargo install --force toml-cli

# Install PyGithub
RUN dnf -y install python3-pip
RUN python3 -m pip install PyGithub

# NOTE: Always keep these as the last steps to ensure up-to-date packages.
RUN rustup update
RUN dnf -y update

CMD /bin/bash
