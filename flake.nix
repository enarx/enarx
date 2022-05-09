{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;
  inputs.fenix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.fenix.url = github:rvolosatovs/fenix?ref=fix/rustc-patch;
  inputs.naersk.url = github:nix-community/naersk;
  inputs.naersk.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, fenix, flake-utils, naersk, ... }:
    # NOTE: musl is only supported on Linux.
    with flake-utils.lib; eachSystem [ system.x86_64-linux ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        rust = fenix.packages."${system}".fromToolchainFile {
          file = "${self}/rust-toolchain.toml";
          sha256 = "sha256-Miyx2cevxtP/Ia2HB9HVN6Z5eT8ITFcoQFvgiK7jVTY=";
        };
      in
      {
        devShell = pkgs.mkShell.override { stdenv = pkgs.stdenvNoCC; } {
          buildInputs = (with pkgs; [
            gcc11
            musl
          ]) ++ [
            rust
          ];

          shellHook = ''
            unset NIX_LDFLAGS_FOR_TARGET
            unset NIX_CFLAGS_COMPILE_FOR_TARGET
          '';
        };

        packages.enarx =
          let
            src = nixpkgs.lib.cleanSource self;

            # Common base derivation to build Enarx crates
            buildEnarxPackage = { src, ... }@extraAttrs:
              let
                cargoToml = with builtins; fromTOML (readFile "${src}/Cargo.toml");
                buildPackage = (naersk.lib.${system}.override {
                  cargo = rust;
                  rustc = rust;
                }).buildPackage;
              in
              buildPackage ({
                inherit src;
                inherit (cargoToml.package) name version;
              } // extraAttrs);

            # Enarx internal static dependencies
            buildEnarxInternalPackage = src: buildEnarxPackage {
              inherit src;

              CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";

              stripAllFlags = [ "--strip-unneeded" ];
              stripAllList = [ "bin" ];
            };
            shimKvm = buildEnarxInternalPackage ./crates/shim-kvm;
            shimSgx = buildEnarxInternalPackage ./crates/shim-sgx;
            execWasmtime = buildEnarxInternalPackage ./crates/exec-wasmtime;
          in
          buildEnarxPackage {
            inherit src;

            ENARX_PREBUILT_shim-kvm = "${shimKvm}/bin/shim-kvm";
            ENARX_PREBUILT_shim-sgx = "${shimSgx}/bin/shim-sgx";
            ENARX_PREBUILT_exec-wasmtime = "${execWasmtime}/bin/exec-wasmtime";

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";

            doCheck = true;
            preCheck = ''
              if [[ -e /dev/kvm ]]; then
                export cargo_test_options="$cargo_test_options -- --skip check_listen_fd"
              else
                header "No KVM support, running only unit tests"
                export cargo_test_options="$cargo_test_options --bins"
              fi
            '';
          };

        defaultPackage = self.packages.${system}.enarx;
      }
    );
}
