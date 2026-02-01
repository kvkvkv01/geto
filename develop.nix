{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "geto-dev";

  buildInputs = with pkgs; [
    # Build tools
    gcc
    gnumake
    pkg-config

    # Required libraries
    sqlite
    openssl

    # Testing and debugging
    valgrind
    gdb

    # Development utilities
    curl
    jq
    python3

    # Container tools (optional, for integration tests)
    docker

    # Documentation
    man
  ];

  shellHook = ''
        echo "Environment ready. Libraries: sqlite, openssl"
  '';

  # Set library paths for compilation
  NIX_LDFLAGS = "-L${pkgs.sqlite.out}/lib -L${pkgs.openssl.out}/lib";
  NIX_CFLAGS_COMPILE = "-I${pkgs.sqlite.dev}/include -I${pkgs.openssl.dev}/include";

  # Ensure pkg-config finds the libraries
  PKG_CONFIG_PATH = "${pkgs.sqlite.dev}/lib/pkgconfig:${pkgs.openssl.dev}/lib/pkgconfig";
}
