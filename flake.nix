{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  inputs.fenix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.fenix.url = github:nix-community/fenix;
  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:profianinc/nixpkgs;

  outputs = { self, nixpkgs, fenix, flake-utils, ... }:
    with flake-utils.lib.system; flake-utils.lib.eachSystem [
      aarch64-darwin
      aarch64-linux
      x86_64-darwin
      x86_64-linux
    ]
      (system:
        let
          ignorePatterns = [
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
          ];

          pkgs = nixpkgs.legacyPackages.${system};

          cargo.toml = builtins.fromTOML (builtins.readFile "${self}/Cargo.toml");

          buildPackage = targetPkgs: rustTargets: extraArgs:
            let
              rust = with fenix.packages.${system}; combine (
                [
                  minimal.cargo
                  minimal.rustc
                ]
                ++ map (target: targets.${target}.latest.rust-std) rustTargets
              );
            in
            (targetPkgs.makeRustPlatform {
              rustc = rust;
              cargo = rust;
            }).buildRustPackage
              (extraArgs // {
                inherit (cargo.toml.package) name version;

                src = pkgs.nix-gitignore.gitignoreRecursiveSource ignorePatterns self;

                cargoLock.lockFileContents = builtins.readFile "${self}/Cargo.lock";

                postPatch = ''
                  patchShebangs ./helper
                '';

                buildInputs = pkgs.lib.optional pkgs.stdenv.isDarwin
                  pkgs.darwin.apple_sdk.frameworks.Security;
              });

          dynamicBin = buildPackage pkgs
            ([
              "wasm32-wasi" # required for tests
            ] ++ (if system == aarch64-linux then [
              "aarch64-unknown-linux-musl"
            ] else if system == x86_64-linux then [
              "x86_64-unknown-linux-musl"
              "x86_64-unknown-none" # required for shims
            ] else [ ]))
            {
              cargoTestFlags = [ "wasm::" ];
            };

          staticBin = buildPackage pkgs.pkgsStatic
            (if system == aarch64-linux then [
              "aarch64-unknown-linux-musl"
            ] else if system == x86_64-linux then [
              "x86_64-unknown-linux-musl"
              "x86_64-unknown-none" # required for shims
            ] else if (system == x86_64-darwin || system == aarch64-darwin) then [
              "wasm32-wasi" # required for tests
            ] else [ ])
            {
              CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";

              depsBuildBuild = [
                pkgs.stdenv.cc
              ];

              meta.mainProgram = cargo.toml.package.name;
            };

          aarch64DarwinBin =
            if system == aarch64-darwin then
              staticBin
            else
            # TODO: Support cross-compilation
              throw "cross-compilation not supported, use QEMU";

          aarch64LinuxMuslBin =
            if system == aarch64-linux then
              staticBin
            else
            # TODO: Support cross-compilation
              throw "cross-compilation not supported, use QEMU";


          x86_64DarwinBin =
            if system == x86_64-darwin then
              staticBin
            else
            # TODO: Support cross-compilation
              throw "cross-compilation not supported, use QEMU";

          x86_64LinuxMuslBin =
            if system == x86_64-linux then
              staticBin
            else
            # TODO: Support cross-compilation
              throw "cross-compilation not supported, use QEMU";


          buildImage = bin: pkgs.dockerTools.buildImage {
            inherit (cargo.toml.package) name;
            tag = cargo.toml.package.version;
            contents = [
              bin
            ];
            config.Cmd = [ cargo.toml.package.name ];
            config.Env = [ "PATH=${bin}/bin" ];
          };
        in
        {
          defaultPackage = dynamicBin;

          packages = {
            "${cargo.toml.package.name}" = dynamicBin;
            "${cargo.toml.package.name}-static" = staticBin;
            "${cargo.toml.package.name}-static-oci" = buildImage staticBin;
          } // pkgs.lib.optionalAttrs (system == aarch64-darwin) {
            "${cargo.toml.package.name}-aarch64-apple-darwin" = aarch64DarwinBin;
            "${cargo.toml.package.name}-aarch64-apple-darwin-oci" = buildImage aarch64DarwinBin;
          } // pkgs.lib.optionalAttrs (system == aarch64-linux) {
            "${cargo.toml.package.name}-aarch64-unknown-linux-musl" = aarch64LinuxMuslBin;
            "${cargo.toml.package.name}-aarch64-unknown-linux-musl-oci" = buildImage aarch64LinuxMuslBin;
          } // pkgs.lib.optionalAttrs (system == x86_64-darwin) {
            "${cargo.toml.package.name}-x86_64-apple-darwin" = x86_64DarwinBin;
            "${cargo.toml.package.name}-x86_64-apple-darwin-oci" = buildImage x86_64DarwinBin;
          } // pkgs.lib.optionalAttrs (system == x86_64-linux) {
            "${cargo.toml.package.name}-x86_64-unknown-linux-musl" = x86_64LinuxMuslBin;
            "${cargo.toml.package.name}-x86_64-unknown-linux-musl-oci" = buildImage x86_64LinuxMuslBin;
          };

          devShell = pkgs.mkShell {
            buildInputs = [
              (fenix.packages.${system}.fromToolchainFile {
                file = "${self}/rust-toolchain.toml";
              })
            ];
          };
        }
      );
}
