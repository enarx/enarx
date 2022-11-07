{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  # NOTE: https://github.com/rvolosatovs/nixify/commit/e714e8244d3736c6bd3168f4de87f519db4a507c following this commit
  # introduced a bug, once that is fixed the dependency should be unpinned
  inputs.nixify.url = github:rvolosatovs/nixify/e87cbcb1ba3f43dbf99901312c70e6d566a21fb6;

  # Temporary override transitive `nixify` dependencies to benefit from updates.
  inputs.nixify.inputs.nixpkgs.follows = "nixpkgs";
  inputs.nixify.inputs.rust-overlay.follows = "rust-overlay";
  inputs.nixpkgs.url = github:nixos/nixpkgs/nixpkgs-22.05-darwin;
  inputs.rust-overlay.url = github:oxalica/rust-overlay;

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
