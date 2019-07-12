{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = [ pkgs.openssl_1_1 pkgs.pkg-config ];
}
