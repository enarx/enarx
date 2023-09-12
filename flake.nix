{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  inputs.nixify.url = github:rvolosatovs/nixify/v0.1.0;

  outputs = {nixify, ...}: let
  in
    with nixify.lib;
      rust.mkFlake {
        src = ./.;

        excludePaths = [
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

        targets.armv7-unknown-linux-musleabihf = false;
        targets.wasm32-wasi = false;
        targets.x86_64-pc-windows-gnu = false;

        buildOverrides = {
          pkgs,
          pkgsCross ? pkgs,
          ...
        }: {buildInputs ? [], ...}:
          with pkgsCross;
          with pkgs.lib; {
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
                ++ optional pkgs.stdenv.buildPlatform.isDarwin pkgs.darwin.apple_sdk.frameworks.Security;
            }
            devShells;
      };
}
