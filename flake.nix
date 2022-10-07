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

        craneLib = (crane.mkLib final).overrideToolchain rustToolchain;

        commonArgs = {
          inherit
            src
            version
            ;
          pname = "enarx";

          buildInputs =
            final.lib.optional final.stdenv.isDarwin
            final.darwin.apple_sdk.frameworks.Security;
        };

        cargoArtifacts = craneLib.buildDepsOnly (commonArgs
          // {
            cargoExtraArgs = "-j $NIX_BUILD_CORES --all-features";

            # Remove binary dependency specification, since that breaks on generated "dummy source"
            extraDummyScript = ''
              sed -i '/^artifact = "bin"$/d' $out/Cargo.toml
              sed -i '/^target = ".*"$/d' $out/Cargo.toml
            '';
          });

        commonArtifactArgs = commonArgs // {inherit cargoArtifacts;};

        # TODO: Use `--workspace` once https://github.com/enarx/enarx/issues/2270 is resolved
        #checks.clippy = craneLib.cargoClippy (commonArtifactArgs // {cargoClippyExtraArgs = "--all-targets --workspace -- --deny warnings";});
        checks.clippy = craneLib.cargoClippy (commonArtifactArgs
          // {
            cargoExtraArgs = "-j $NIX_BUILD_CORES --all-features";

            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
        checks.fmt = craneLib.cargoFmt commonArgs;

        buildPackage = extraArgs:
          craneLib.buildPackage (commonArtifactArgs
            // {
              cargoExtraArgs = "-j $NIX_BUILD_CORES";
              cargoTestExtraArgs = "wasm::";

              installPhaseCommand = ''
                mkdir -p $out/bin
                cp target/''${CARGO_BUILD_TARGET:+''${CARGO_BUILD_TARGET}/}''${CARGO_PROFILE:-release}/enarx $out/bin/enarx
              '';
            }
            // extraArgs);

        nativeBin = buildPackage {};
        aarch64DarwinBin = buildPackage {
          CARGO_BUILD_TARGET = "aarch64-apple-darwin";
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };
        aarch64LinuxMuslBin = buildPackage {
          CARGO_BUILD_TARGET = "aarch64-unknown-linux-musl";
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };
        x86_64DarwinBin = buildPackage {
          CARGO_BUILD_TARGET = "x86_64-apple-darwin";
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };
        x86_64LinuxMuslBin = buildPackage {
          CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
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
        enarx = nativeBin;
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

          packages =
            {
              default = pkgs.enarx;
            }
            // pkgs.lib.genAttrs [
              "enarx"
              "enarx-aarch64-apple-darwin"
              "enarx-aarch64-apple-darwin-oci"
              "enarx-aarch64-unknown-linux-musl"
              "enarx-aarch64-unknown-linux-musl-oci"
              "enarx-x86_64-apple-darwin"
              "enarx-x86_64-apple-darwin-oci"
              "enarx-x86_64-unknown-linux-musl"
              "enarx-x86_64-unknown-linux-musl-oci"
            ] (name: pkgs.${name});

          devShells.default = pkgs.mkShell {
            buildInputs = [
              pkgs.enarxRustToolchain
              pkgs.openssl
            ];
          };
        }
      );
}
