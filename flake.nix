{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;
  inputs.rust-overlay.inputs.flake-utils.follows = "flake-utils";
  inputs.rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  inputs.rust-overlay.url = github:oxalica/rust-overlay;

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        buildInputs = (with pkgs; [
          gcc11
          openssl.dev
          musl.dev
        ]) ++ [
          rust
        ];

        nativeBuildInputs = with pkgs; [
          pkg-config
        ];

        unsetEnv = pkgs.lib.concatMapStringsSep "\n" (var: "unset ${var}") [
          "NIX_LDFLAGS_FOR_TARGET"
          "NIX_CFLAGS_COMPILE_FOR_TARGET"
        ];

        stdenv = pkgs.stdenvNoCC;

        stdenvOverride = { inherit stdenv; };
      in
      {
        devShell = pkgs.mkShell.override stdenvOverride {
          inherit buildInputs nativeBuildInputs;

          shellHook = unsetEnv;
        };
      }
    );
}
