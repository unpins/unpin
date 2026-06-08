{
  description = "Standalone build of unpin";

  nixConfig = {
    extra-substituters = [ "https://unpins.cachix.org" ];
    extra-trusted-public-keys = [ "unpins.cachix.org-1:DDaShjbZ8VvcqxeTcAU3kV9vxZQBlyb7V/uLBHfTynI=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    unpins-lib.url = "github:unpins/nix-lib";
    # rustup-distributed toolchain. Pulls `rust-std-<triple>` as a binary
    # download for each cross target — avoids the multi-hour cross-rustc
    # bootstrap that pkgsCross.<x>.rustPlatform triggers for musl targets
    # not pre-built on cache.nixos.org (i686-musl, muslpi, musl-power,
    # riscv64-musl).
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, unpins-lib, rust-overlay }:
    let
      ulib = unpins-lib.lib;
      nixpkgsFor = ulib.forAllNative (system: import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      });

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
          # buildInputs above only covers the target (x86_64) link. In this
          # arm→x86 cross the proc-macros are compiled for the BUILD host
          # (aarch64) and rustc links each as a `.dylib` with `-liconv`; the
          # build→build cc-wrapper has no libiconv in its path, so that link
          # fails on a cold cache. This build normally escapes it because the
          # proc-macro dylibs are already on cachix — but that's luck, not
          # correctness (proven by unpins/unpin-readme, a fresh crate with the
          # same flake, failing here until this flag landed). `depsBuildBuild`
          # does NOT populate the flag under buildRustPackage; push the `-L`
          # straight onto the var the build→build wrapper reads,
          # `NIX_LDFLAGS_<suffixSalt>` (salt = arm64_apple_darwin), with the
          # build-arch (aarch64) libiconv, not the x86_64 target one.
          NIX_LDFLAGS_arm64_apple_darwin = "-L${cross.buildPackages.libiconv}/lib";
        });

      # Rustup-distributed toolchain with every cross target we ship. rustup
      # supplies `rust-std-<triple>` as a precompiled tarball, so adding a
      # target costs a download instead of the ~40 min `pkgsCross.<x>.rustc`
      # source build. The same toolchain drv is shared by every mkCross call
      # below, so all 4 musl crosses fetch it exactly once.
      rustToolchain = pkgs: pkgs.rust-bin.stable.latest.default.override {
        targets = [
          "i686-unknown-linux-musl"
          "armv7-unknown-linux-musleabihf"
          "powerpc64le-unknown-linux-musl"
          "riscv64gc-unknown-linux-musl"
        ];
      };

      # Cross build for musl targets: rust-overlay rustc (native binary, no
      # source build) + rustup's `rust-std-<triple>` + the cross C toolchain
      # bundled in `crossPkgs.stdenv` for ring/xz2 (have C+asm) and the final
      # link. Replaces the old `pkgsCross.<x>.rustPlatform` path that built
      # cross-rustc from source.
      #
      # Why crossPkgs.makeRustPlatform (not pkgs.makeRustPlatform): the cross
      # stdenv generates `cargoBuildHook` with `--target <triple>` baked in
      # and pre-sets `CC_<TARGET>` / `CARGO_TARGET_<TARGET>_LINKER` to the
      # cross toolchain. Native makeRustPlatform hardcodes the build host's
      # target instead, which `CARGO_BUILD_TARGET` env can't override (the
      # hook passes `--target` on the cargo command line). The rustc/cargo
      # override threads rust-overlay's native binary through unchanged.
      mkCross = crossPkgs:
        let rust = rustToolchain crossPkgs.buildPackages; in
        mkUnpin {
          rustPlatform = crossPkgs.makeRustPlatform { cargo = rust; rustc = rust; };
          auditable = false;
          # rust-overlay's musl target specs default to `crt-static = false`
          # (rustup's convention), unlike nixpkgs's pkgsStatic which flips it
          # on. Without the explicit `+crt-static` the binary keeps a musl
          # dynamic-link interpreter and action-build's portability check
          # rejects it.
          env.RUSTFLAGS = "-C target-feature=+crt-static";
        };

      linuxI686Unpin   = mkCross nixpkgsFor.x86_64-linux.pkgsCross.musl32;
      linuxPpc64leUnpin = mkCross nixpkgsFor.x86_64-linux.pkgsCross.musl-power;

      # riscv64-musl isn't pre-cooked in pkgsCross — spell the triple out.
      linuxRiscv64Unpin = mkCross (import nixpkgs {
        system = "x86_64-linux";
        overlays = [ rust-overlay.overlays.default ];
        crossSystem = { config = "riscv64-unknown-linux-musl"; };
      });

      # Built on the ubuntu-24.04-arm GH runner, so this attr lives under
      # packages.aarch64-linux.
      linuxArmv7lUnpin = mkCross nixpkgsFor.aarch64-linux.pkgsCross.muslpi;

      nativePackages = ulib.forAllNative (system: { default = nativeUnpin system; });
    in
    {
      packages = nativePackages // {
        x86_64-linux = nativePackages.x86_64-linux // {
          "windows-x86_64" = windowsUnpin;
          "linux-i686" = linuxI686Unpin;
          "linux-ppc64le" = linuxPpc64leUnpin;
          "linux-riscv64" = linuxRiscv64Unpin;
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
