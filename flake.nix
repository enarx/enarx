{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  inputs.crane.inputs.flake-compat.follows = "flake-compat";
  inputs.crane.inputs.flake-utils.follows = "flake-utils";
  inputs.crane.inputs.nixpkgs.follows = "nixpkgs";
  # TODO: Switch to upstream once https://github.com/ipetkov/crane/pull/126 is merged
  inputs.crane.url = github:rvolosatovs/crane/fix/no_std;
  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:profianinc/nixpkgs;
  inputs.rust-overlay.inputs.flake-utils.follows = "flake-utils";
  inputs.rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  inputs.rust-overlay.url = github:oxalica/rust-overlay;

  outputs = {
    self,
    crane,
    flake-utils,
    nixpkgs,
    rust-overlay,
    ...
  }:
    with flake-utils.lib.system; let
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;

      overlay = final: prev: let
        src =
          final.nix-gitignore.gitignoreRecursiveSource [
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
          ./.;

        rustToolchain = prev.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # mkCraneLib constructs a crane library for specified `pkgs`.
        mkCraneLib = pkgs: (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # hostCraneLib is the crane library for the host native triple.
        hostCraneLib = mkCraneLib final;

        # commonArgs is a set of arguments that is common to all crane invocations.
        commonArgs = with final.lib; {
          inherit
            src
            version
            ;
          pname = "enarx";
        };

        # buildDeps builds dependencies of the crate given `craneLib`.
        # `extraArgs` are passed through to `craneLib.buildDepsOnly` verbatim.
        buildDeps = craneLib: extraArgs:
          craneLib.buildDepsOnly (commonArgs
            // {
              cargoExtraArgs = "-j $NIX_BUILD_CORES --all-features";
              # Remove binary dependency specification, since that breaks on generated "dummy source"
              extraDummyScript = ''
                sed -i '/^artifact = "bin"$/d' $out/Cargo.toml
                sed -i '/^target = ".*"$/d' $out/Cargo.toml
              '';
            }
            // extraArgs);

        # hostCargoArtifacts are the cargo artifacts built for the host native triple.
        hostCargoArtifacts = buildDeps hostCraneLib {};

        # TODO: Use `--workspace` once https://github.com/enarx/enarx/issues/2270 is resolved
        #checks.clippy = hostCraneLib.cargoClippy (hostArtifactCommonArgs // {cargoClippyExtraArgs = "--all-targets --workspace -- --deny warnings";});
        checks.clippy = hostCraneLib.cargoClippy (commonArgs
          // {
            cargoArtifacts = hostCargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            cargoExtraArgs = "-j $NIX_BUILD_CORES --all-features";
          });
        checks.fmt = hostCraneLib.cargoFmt commonArgs;
        checks.nextest = hostCraneLib.cargoNextest (commonArgs
          // {
            cargoArtifacts = hostCargoArtifacts;
            cargoExtraArgs = "-j $NIX_BUILD_CORES";
          });

        # buildPackage builds using `craneLib`.
        # `extraArgs` are passed through to `craneLib.buildPackage` verbatim.
        buildPackage = craneLib: extraArgs:
          craneLib.buildPackage (commonArgs
            // {
              cargoExtraArgs = "-j $NIX_BUILD_CORES";

              installPhaseCommand = ''
                mkdir -p $out/bin
                cp target/''${CARGO_BUILD_TARGET:+''${CARGO_BUILD_TARGET}/}''${CARGO_PROFILE:-release}/enarx $out/bin/enarx
              '';
            }
            // extraArgs);

        # hostBin is the binary built for host native triple.
        hostBin = with final.lib;
          buildPackage hostCraneLib {
            buildInputs =
              optional final.stdenv.isDarwin
              final.darwin.apple_sdk.frameworks.Security;

            cargoArtifacts = hostCargoArtifacts;
            cargoExtraArgs = "-j $NIX_BUILD_CORES";
          };

        # pkgsFor constructs a package set for specified `crossSystem`.
        pkgsFor = crossSystem: let
          localSystem = final.hostPlatform.system;
        in
          if localSystem == crossSystem
          then final
          else if crossSystem == x86_64-darwin
          then throw "cross compilation to x86_64-darwin not supported due to https://github.com/NixOS/nixpkgs/issues/180771"
          else
            import nixpkgs {
              inherit
                crossSystem
                localSystem
                ;
            };

        # buildPackageFor builds for `target` using `crossSystem` toolchain.
        # `extraArgs` are passed through to `buildPackage` verbatim.
        # NOTE: Upstream only provides binary caches for a subset of supported systems.
        buildPackageFor = crossSystem: target: extraArgs:
          with final.lib; let
            pkgs = pkgsFor crossSystem;
            cc = pkgs.stdenv.cc;
            kebab2snake = replaceStrings ["-"] ["_"];
            commonCrossArgs = {
              depsBuildBuild = [
                cc
              ];

              buildInputs =
                optional pkgs.stdenv.isDarwin
                pkgs.darwin.apple_sdk.frameworks.Security;

              CARGO_BUILD_TARGET = target;
              ${"CARGO_TARGET_${toUpper (kebab2snake target)}_LINKER"} = "${cc.targetPrefix}cc";
            };
            craneLib = mkCraneLib pkgs;
          in
            buildPackage craneLib (commonCrossArgs
              // {
                cargoArtifacts = buildDeps craneLib commonCrossArgs;
              }
              // extraArgs);

        aarch64DarwinBin = buildPackageFor aarch64-darwin "aarch64-apple-darwin" {
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };

        aarch64LinuxMuslBin = buildPackageFor aarch64-linux "aarch64-unknown-linux-musl" {
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };

        x86_64DarwinBin = buildPackageFor x86_64-darwin "x86_64-apple-darwin" {
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };

        x86_64LinuxMuslBin = buildPackageFor x86_64-linux "x86_64-unknown-linux-musl" {
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };

        buildImage = bin:
          final.dockerTools.buildImage {
            name = "enarx";
            tag = version;
            contents = [
              bin
            ];
            config.Cmd = ["enarx"];
            config.Env = ["PATH=${bin}/bin"];
          };
      in {
        enarx = hostBin;
        enarx-aarch64-apple-darwin = aarch64DarwinBin;
        enarx-aarch64-apple-darwin-oci = buildImage aarch64DarwinBin;
        enarx-aarch64-unknown-linux-musl = aarch64LinuxMuslBin;
        enarx-aarch64-unknown-linux-musl-oci = buildImage aarch64LinuxMuslBin;
        enarx-x86_64-apple-darwin = x86_64DarwinBin;
        enarx-x86_64-apple-darwin-oci = buildImage x86_64DarwinBin;
        enarx-x86_64-unknown-linux-musl = x86_64LinuxMuslBin;
        enarx-x86_64-unknown-linux-musl-oci = buildImage x86_64LinuxMuslBin;

        enarxChecks = checks;
        enarxRustToolchain = rustToolchain;
      };
    in
      {
        overlays.default = overlay;
      }
      // flake-utils.lib.eachSystem [
        aarch64-darwin
        aarch64-linux
        powerpc64le-linux
        x86_64-darwin
        x86_64-linux
      ]
      (
        system: let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              # NOTE: Order is important
              rust-overlay.overlays.default
              overlay
            ];
          };
        in {
          formatter = pkgs.alejandra;

          checks = pkgs.enarxChecks;

          packages = with pkgs.lib;
            {
              default = pkgs.enarx;
            }
            // genAttrs ([
                "enarx"
                "enarx-aarch64-unknown-linux-musl"
                "enarx-aarch64-unknown-linux-musl-oci"
                "enarx-x86_64-unknown-linux-musl"
                "enarx-x86_64-unknown-linux-musl-oci"
              ]
              ++ optionals (system == aarch64-darwin || system == x86_64-darwin) [
                "enarx-aarch64-apple-darwin"
                "enarx-aarch64-apple-darwin-oci"
              ]
              ++ optionals (system == x86_64-darwin) [
                # cross compilation to x86_64-darwin not supported due to https://github.com/NixOS/nixpkgs/issues/180771
                "enarx-x86_64-apple-darwin"
                "enarx-x86_64-apple-darwin-oci"
              ]) (name: pkgs.${name});

          devShells.default = pkgs.mkShell {
            buildInputs = [
              pkgs.enarxRustToolchain
              pkgs.openssl
            ];
          };
        }
      );
}
