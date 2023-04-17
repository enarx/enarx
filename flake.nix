{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  inputs.nixify.url = github:haraldh/nixify;

  outputs = {nixify, ...}: let
  in
    with nixify.lib;
      rust.mkFlake {
        src = ./.;

        ignorePaths = [
          "/.codecov.yml"
          "/.github"
          "/.gitignore"
          "/.mailmap"
          "/crates/enarx-config/LICENSE"
          "/crates/exec-wasmtime/LICENSE"
          "/crates/sallyport/.gitignore"
          "/crates/sallyport/LICENSE"
          "/crates/shim-kvm/LICENSE"
          "/crates/shim-kvm/README.md"
          "/crates/shim-sgx/LICENSE"
          "/deny.toml"
          "/docs"
          "/flake.lock"
          "/flake.nix"
          "/helper"
          "/LICENSE"
          "/README-DEBUG.md"
          "/release"
          "/SECURITY.md"
          "/shell.nix"
        ];

        clippy.allFeatures = true;
        clippy.allTargets = true;
        clippy.deny = ["warnings"];

        targets.x86_64-unknown-none = false;

        buildOverrides = {
          pkgs,
          buildInputs ? [],
          ...
        } @ args:
          with pkgs.lib;
          with (args.pkgsCross or pkgs); {
            buildInputs =
              buildInputs
              ++ optional stdenv.targetPlatform.isDarwin darwin.apple_sdk.frameworks.Security;
          };

        withDevShells = {
          pkgs,
          devShells,
          ...
        }:
          with pkgs.lib;
            extendDerivations {
              buildInputs =
                [
                  pkgs.openssl
                ]
                ++ optional pkgs.stdenv.isDarwin pkgs.darwin.apple_sdk.frameworks.Security;
            }
            devShells;
      };
}
