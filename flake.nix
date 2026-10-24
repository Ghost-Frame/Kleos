{
  description = "Kleos -- persistent semantic memory and cognitive infrastructure for AI agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Pin the toolchain to the workspace's declared rust-version so Nix
        # builds cannot silently drift above/below the MSRV in Cargo.toml.
        rustToolchain = pkgs.rust-bin.stable."1.94.0".default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
        };

        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
          protobuf
          clang
        ];

        buildInputs = with pkgs; [
          openssl
          sqlite
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.darwin.apple_sdk.frameworks.Security
          pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
        ];

        # nixpkgs has no PolyForm entry; describe the LICENSE file directly.
        # Noncommercial terms are not free, so Nix requires allowUnfree to build.
        polyformNoncommercial = {
          spdxId = "PolyForm-Noncommercial-1.0.0";
          fullName = "PolyForm Noncommercial License 1.0.0";
          url = "https://polyformproject.org/licenses/noncommercial/1.0.0/";
          free = false;
        };

        # Common environment variables for building
        buildEnv = {
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          # ort (ONNX Runtime) uses load-dynamic, so no build-time dep needed.
          # Users who want embedding support should set ORT_DYLIB_PATH at runtime.
        };
      in
      {
        packages = {
          kleos-server = pkgs.rustPlatform.buildRustPackage {
            pname = "kleos-server";
            version = "0.3.2";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            inherit nativeBuildInputs buildInputs;
            env = buildEnv;
            buildAndTestSubdir = "kleos-server";
            doCheck = false; # tests require runtime services
            meta = {
              description = "Kleos memory server -- persistent semantic memory for AI agents";
              license = polyformNoncommercial;
              mainProgram = "kleos-server";
            };
          };

          kleos-cli = pkgs.rustPlatform.buildRustPackage {
            pname = "kleos-cli";
            version = "0.3.2";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            inherit nativeBuildInputs buildInputs;
            env = buildEnv;
            buildAndTestSubdir = "kleos-cli";
            doCheck = false;
            meta = {
              description = "Kleos CLI -- command-line client for the Kleos memory server";
              license = polyformNoncommercial;
              mainProgram = "kleos-cli";
            };
          };

          kleos-mcp = pkgs.rustPlatform.buildRustPackage {
            pname = "kleos-mcp";
            version = "0.3.2";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            inherit nativeBuildInputs buildInputs;
            env = buildEnv;
            buildAndTestSubdir = "kleos-mcp";
            doCheck = false;
            meta = {
              description = "Kleos MCP server -- Model Context Protocol integration for LLM tools";
              license = polyformNoncommercial;
              mainProgram = "kleos-mcp";
            };
          };

          default = self.packages.${system}.kleos-server;
        };

        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs buildInputs;
          env = buildEnv;

          shellHook = ''
            echo "Kleos development shell"
            echo "  Rust: $(rustc --version)"
            echo "  protoc: $(protoc --version)"
          '';
        };
      });
}
