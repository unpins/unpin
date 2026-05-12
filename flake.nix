{
  description = "Standalone build of unpin";

  nixConfig = {
    extra-substituters = [ "https://unpins.cachix.org" ];
    extra-trusted-public-keys = [ "unpins.cachix.org-1:DDaShjbZ8VvcqxeTcAU3kV9vxZQBlyb7V/uLBHfTynI=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    unpins-lib.url = "github:unpins/nix-lib/v1";
  };

  outputs = { self, nixpkgs, unpins-lib }:
    let
      ulib = unpins-lib.lib;
      nixpkgsFor = ulib.forAllNative (system: import nixpkgs { inherit system; });

      src = nixpkgs.lib.cleanSourceWith {
        src = ./.;
        filter = path: _:
          let base = baseNameOf (toString path); in
          !(builtins.elem base [ "target" "result" "result-win" ".github" ]);
      };

      mkUnpin = { rustPlatform, env ? {}, auditable ? true }:
        (rustPlatform.buildRustPackage {
          pname = "unpin";
          version = "0.1.0";
          inherit src auditable env;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;
        }).overrideAttrs (_: { stripAllList = [ "bin" ]; });

      nativeUnpin = system:
        mkUnpin {
          rustPlatform = nixpkgsFor.${system}.pkgsStatic.rustPlatform;
          env.RUSTFLAGS = "-C relocation-model=static";
        };

      # auditable=false: rustc 1.91 + LTO + cargo-auditable overflows mingw's
      # 32-bit relocation limit. Plain `cargo build --target` skips auditable.
      windowsUnpin = mkUnpin {
        rustPlatform = nixpkgsFor.x86_64-linux.pkgsCross.mingwW64.rustPlatform;
        auditable = false;
      };

      darwinX86Unpin = mkUnpin {
        rustPlatform = nixpkgsFor.aarch64-darwin.pkgsCross.x86_64-darwin.rustPlatform;
      };

      nativePackages = ulib.forAllNative (system: { default = nativeUnpin system; });
    in
    {
      packages = nativePackages // {
        x86_64-linux = nativePackages.x86_64-linux // {
          "windows-x86_64" = windowsUnpin;
        };
        aarch64-darwin = nativePackages.aarch64-darwin // {
          "darwin-x86_64" = darwinX86Unpin;
        };
      };

      apps = ulib.forAllNative (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/unpin";
        };
      });
    };
}
