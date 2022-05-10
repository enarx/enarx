{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;
  inputs.fenix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.fenix.url = github:rvolosatovs/fenix?ref=fix/rustc-patch;

  outputs = { self, nixpkgs, fenix, flake-utils, ... }:
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

            pkgsCross = import nixpkgs {
              inherit system;
              crossSystem.config = "x86_64-unknown-linux-musl";
            };

            # Common base derivation to build Enarx crates
            buildEnarxPackage = pkgs: extraAttrs:
              let
                cargoToml = with builtins; fromTOML (readFile "${src}/Cargo.toml");
                buildPackage = (pkgs.makeRustPlatform {
                  cargo = rust;
                  rustc = rust;
                }).buildRustPackage;
              in
              buildPackage ({
                inherit (cargoToml.package) name version;

                cargoLock.lockFile = "${extraAttrs.src}/Cargo.lock";
              } // extraAttrs);

          in
          buildEnarxPackage pkgs {
            inherit src;

            postPatch = ''
              patchShebangs ./helper
            '';

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";

            doCheck = false;
            preCheck = ''
              if [[ ! -e /dev/kvm ]]; then
                header "No KVM support, running only unit tests"
                export cargo_test_options="$cargo_test_options --bins --test integration -- wasm::"
              fi
            '';
          };

        defaultPackage = self.packages.${system}.enarx;
      }
    );
}
