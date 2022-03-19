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
          sha256 = "sha256-CSZsqsnfDEL4pfyKRvWU/opdMjvx6vnJwFnkJXL/oBI=";
        };
      in
      {
        devShell = pkgs.mkShell.override { stdenv = pkgs.stdenvNoCC; } {
          buildInputs = (with pkgs; [
            gcc11
            openssl
            musl
          ]) ++ [
            rust
          ];

          nativeBuildInputs = with pkgs; [
            pkg-config
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

            # Enarx internal static dependencies
            buildEnarxInternalPackage = src: buildEnarxPackage pkgsCross {
              inherit src;

              stripAllFlags = [ "--strip-unneeded" ];
              stripAllList = [ "bin" ];
            };
            shimKvm = buildEnarxInternalPackage ./internal/shim-kvm;
            shimSgx = buildEnarxInternalPackage ./internal/shim-sgx;
            wasmldr = buildEnarxInternalPackage ./internal/wasmldr;
          in
          buildEnarxPackage pkgs {
            inherit src;

            postPatch = ''
              patchShebangs ./helper
            '';

            ENARX_PREBUILT_shim-kvm = "${shimKvm}/bin/shim-kvm";
            ENARX_PREBUILT_shim-sgx = "${shimSgx}/bin/shim-sgx";
            ENARX_PREBUILT_wasmldr = "${wasmldr}/bin/wasmldr";

            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.openssl ];

            doCheck = true;
            preCheck = ''
              if [[ ! -e /dev/kvm ]]; then
                header "No KVM support, running only unit tests"
                export cargo_test_options="$cargo_test_options --bins"
              fi
            '';
          };

        defaultPackage = self.packages.${system}.enarx;
      }
    );
}
