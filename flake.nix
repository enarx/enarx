{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  inputs.fenix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.fenix.url = github:nix-community/fenix;
  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;

  outputs = { self, nixpkgs, fenix, flake-utils, ... }:
    # NOTE: musl is only supported on Linux.
    with flake-utils.lib; eachSystem [ system.x86_64-linux ]
      (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          cargoToml = builtins.fromTOML (builtins.readFile "${self}/Cargo.toml");
        in
        {
          defaultPackage = self.packages.${system}.${cargoToml.package.name};

          packages =
            let
              rust = with fenix.packages.${system};
                combine [
                  minimal.cargo
                  minimal.rustc
                  targets.wasm32-wasi.latest.rust-std # required for tests
                  targets.x86_64-unknown-linux-musl.latest.rust-std
                  targets.x86_64-unknown-none.latest.rust-std
                ];

              buildPackage = pkgs: extraArgs: (pkgs.makeRustPlatform {
                rustc = rust;
                cargo = rust;
              }).buildRustPackage
                ({
                  inherit (cargoToml.package) name version;

                  src = pkgs.nix-gitignore.gitignoreRecursiveSource [
                    "*.nix"
                    "*.yml"
                    "/.github"
                    "/docs"
                    "/README-DEBUG.md"
                    "/SECURITY.md"
                    "deny.toml"
                    "flake.lock"
                    "LICENSE"
                    "rust-toolchain.toml"
                  ]
                    self;

                  cargoLock.lockFileContents = builtins.readFile "${self}/Cargo.lock";

                  postPatch = ''
                    patchShebangs ./helper
                  '';
                } // extraArgs);
            in
            {
              "${name}" = buildPackage pkgs { };

              "${name}-static" = buildPackage pkgs.pkgsStatic rec {
                CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
                CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
                CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = with pkgs.pkgsMusl.stdenv; "${cc}/bin/${cc.targetPrefix}gcc";

                depsBuildBuild = [ pkgs.stdenv.cc ];

                meta.mainProgram = name;
              };

              enarx-docker = pkgs.dockerTools.buildImage {
                name = "${cargoToml.package.name}-docker";
                tag = "${cargoToml.package.version}";
                config.Cmd = [ "${self.packages.${system}.enarx}/bin/enarx" ];
              };
            };

          devShell =
            let
              rust = fenix.packages.${system}.fromToolchainFile {
                file = "${self}/rust-toolchain.toml";
              };
            in
            pkgs.mkShell {
              buildInputs = [
                rust
              ];
            };
        }
      );
}
