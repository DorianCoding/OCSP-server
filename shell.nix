{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    cargo-audit
    clippy
    rustfmt
    rust-analyzer
    git
    openssl
    libmysqlclient
    sqlite
    postgresql
    pkg-config
  ];

  shellHook = ''
    rustfmt --edition 2024 src/*.rs
    cargo audit
  '';

  RUST_BACKTRACE = 1;
}
