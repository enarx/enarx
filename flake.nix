{
  description = "Tools for deploying WebAssembly into Enarx Keeps.";

  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;
  inputs.fenix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.fenix.url = github:nix-community/fenix;

  outputs = { self, nixpkgs, fenix, flake-utils, ... }:
    # NOTE: musl is only supported on Linux.
    with flake-utils.lib; eachSystem [ system.x86_64-linux ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ ];
        };

        rust = fenix.packages."${system}".fromToolchainFile {
          file = ./rust-toolchain.toml;
          sha256 = "0939qjwhpk366pnf3lbsbnmlj0h5x8nskbcz2lyjwhz4f2hna7w5";
        };

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
