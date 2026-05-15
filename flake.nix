{
  description = "Standalone build of unpin";

  nixConfig = {
    extra-substituters = [ "https://unpins.cachix.org" ];
    extra-trusted-public-keys = [ "unpins.cachix.org-1:DDaShjbZ8VvcqxeTcAU3kV9vxZQBlyb7V/uLBHfTynI=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    unpins-lib.url = "github:unpins/nix-lib";
  };

  outputs = { self, nixpkgs, unpins-lib }:
    let
      ulib = unpins-lib.lib;
      nixpkgsFor = ulib.forAllNative (system: import nixpkgs { inherit system; });

      version = (nixpkgs.lib.importTOML ./Cargo.toml).package.version;

      src = nixpkgs.lib.cleanSourceWith {
        src = ./.;
        filter = path: _:
          let base = baseNameOf (toString path); in
          !(builtins.elem base [ "target" "result" "result-win" ".github" ]);
      };

      mkUnpin = { rustPlatform, env ? {}, auditable ? true }:
        (rustPlatform.buildRustPackage {
          pname = "unpin";
          inherit version src auditable env;
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

      # rustc injects `-liconv` on darwin targets. The default cross stdenv
      # ships libiconv as a dylib → the binary carries an LC_LOAD_DYLIB for
      # libiconv.2.dylib, which action-build rejects (Apple's ABI contract
      # only covers libSystem + libobjc + Frameworks; /usr/lib/libiconv is
      # de-facto stable but not contractually). Prepending pkgsStatic.libiconv
      # to buildInputs makes the linker see libiconv.a first and emit no
      # dylib load command. Only libiconv goes through pkgsStatic — the rest
      # of the cross stays non-static so the cctools/xar-static cascade
      # (broken upstream for cross-darwin, see fake-cross-darwin-blocked memory)
      # never gets pulled in.
      darwinX86Unpin =
        let cross = nixpkgsFor.aarch64-darwin.pkgsCross.x86_64-darwin; in
        (mkUnpin { rustPlatform = cross.rustPlatform; }).overrideAttrs (old: {
          buildInputs = [ cross.pkgsStatic.libiconv ] ++ (old.buildInputs or [ ]);
        });

      # musl targets default to +crt-static, so plain `pkgsCross.musl32.rustPlatform`
      # already yields a static binary. Going through `pkgsStatic` on top would
      # force a static-rustc rebuild (uncached, ~10GB tmpfs blowup).
      linuxI686Unpin = mkUnpin {
        rustPlatform = nixpkgsFor.x86_64-linux.pkgsCross.musl32.rustPlatform;
      };

      # Cross from aarch64-linux to muslpi (armv6l-musleabihf). Same +crt-static
      # default as musl32 above. Built on the ubuntu-24.04-arm GH runner so
      # this attr lives under packages.aarch64-linux.
      linuxArmv7lUnpin = mkUnpin {
        rustPlatform = nixpkgsFor.aarch64-linux.pkgsCross.muslpi.rustPlatform;
      };

      nativePackages = ulib.forAllNative (system: { default = nativeUnpin system; });
    in
    {
      packages = nativePackages // {
        x86_64-linux = nativePackages.x86_64-linux // {
          "windows-x86_64" = windowsUnpin;
          "linux-i686" = linuxI686Unpin;
        };
        aarch64-linux = nativePackages.aarch64-linux // {
          "linux-armv7l" = linuxArmv7lUnpin;
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
