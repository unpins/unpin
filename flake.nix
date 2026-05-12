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

      # Source filtered to keep cargo-relevant files only.
      src = nixpkgs.lib.cleanSourceWith {
        src = ./.;
        filter = path: _type:
          let base = baseNameOf (toString path); in
          !(builtins.elem base [ "target" "result" "result-win" ".github" ]);
      };

      # Build the unpin crate against a given (cross or native) rustPlatform.
      # `stripAllList = [ "bin" ]` enables -s strip on $out/bin (default is -S,
      # which leaves part of the symbol table).
      #
      # `pkgs` is the host-platform pkgs (used only for the nativeBuildInputs
      # toolchain — cmake + perl + python3 are needed by `mbedtls-sys-auto`'s
      # vendored C build).
      # `hostPkgs` is the build-machine pkgs (for cmake/perl/python3 that run
      # during the build). `rustPlatform` may be native or cross.
      # `bindgenHook` is taken from the SAME rustPlatform as the rust toolchain,
      # so bindgen gets the right `--target` for `mbedtls-sys-auto` (cross
      # mismatches give `ssize_t (4) vs pointer size (8)` panics).
      mkUnpin = { hostPkgs, rustPlatform, env ? {}, auditable ? true, extraNativeBuildInputs ? [] }:
        (rustPlatform.buildRustPackage {
          pname = "unpin";
          version = "0.1.0";
          inherit src auditable;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [
            hostPkgs.cmake
            hostPkgs.perl
            hostPkgs.python3
            rustPlatform.bindgenHook
          ] ++ extraNativeBuildInputs;
          inherit env;
          # CI runs `cargo test` directly; tests touch ~/.local and the network.
          doCheck = false;
        }).overrideAttrs (_: { stripAllList = [ "bin" ]; });

      # Native build: pkgsStatic on Linux yields a fully static musl binary.
      # On Darwin libSystem stays dynamic (Apple constraint) but the result
      # is /nix/store-free and portable across any macOS.
      #
      # `relocation-model=static` keeps `file` reporting `statically linked`
      # instead of `static-pie linked` (the unpins/action-build CI greps for
      # the former literally). Costs ASLR but stays fully static.
      nativeUnpin = system:
        let pkgs = nixpkgsFor.${system}; in
        mkUnpin {
          hostPkgs = pkgs;
          rustPlatform = pkgs.pkgsStatic.rustPlatform;
          env.RUSTFLAGS = "-C relocation-model=static";
        };

      # Cross-build: Linux x86_64 → Windows x86_64 (mingw-w64).
      # `auditable = false` disables nixpkgs' cargo-auditable wrapper —
      # without this, the wrapper injects an `AUDITABLE_VERSION_INFO`
      # section + an extra rustc-pass that, combined with LTO under rustc
      # 1.91 (the cross toolchain in nixpkgs 25.11), inflates `.rdata` past
      # the 32-bit signed offset that mingw's `IMAGE_REL_AMD64_ADDR32`
      # relocations allow ("relocation truncated to fit"). Plain
      # `cargo build --release --target x86_64-pc-windows-gnu` on a 1.93
      # host doesn't go through cargo-auditable, hence no error there.
      windowsUnpin =
        let
          pkgs = nixpkgsFor.x86_64-linux;
          cross = pkgs.pkgsCross.mingwW64;
        in
        mkUnpin {
          hostPkgs = pkgs;
          rustPlatform = cross.rustPlatform;
          auditable = false;
        };

      # Cross-build: aarch64-darwin → x86_64-darwin. Same single-runner
      # pattern as windowsUnpin (one runner produces both arches), used to
      # avoid the increasingly-scarce macos-13 native Intel runner.
      #
      # Plain `cross.rustPlatform` (NOT `cross.pkgsStatic.rustPlatform`)
      # because the pkgsStatic view triggers a rebuild of the cross
      # cctools/ld64 toolchain in its "static" variant, which fails on
      # `xar-static-arm64-apple-darwin`: configure errors with "Cannot
      # build without libxml2" — the cross-static libxml2 chain is broken
      # upstream. We get the same /nix/store-free property as the native
      # build because unpin's only C dep is mbedtls (vendored, statically
      # linked into the rustc output via mbedtls-sys-auto); everything
      # else is pure Rust, so the produced Mach-O references only
      # libSystem.dylib.
      #
      # `hostPkgs.libiconv` in nativeBuildInputs is required for the
      # mbedtls-sys-auto *build.rs* link step: rustc injects `-liconv`
      # into the host (aarch64-darwin) link command, but the cross
      # rustPlatform's environment doesn't put it on the linker search
      # path by default. Native darwin builds don't hit this because the
      # native stdenv resolves libiconv from libSystem via different
      # plumbing.
      darwinX86Unpin =
        let
          pkgs = nixpkgsFor.aarch64-darwin;
          cross = pkgs.pkgsCross.x86_64-darwin;
        in
        mkUnpin {
          hostPkgs = pkgs;
          rustPlatform = cross.rustPlatform;
          extraNativeBuildInputs = [ pkgs.libiconv ];
        };

      nativePackages = ulib.forAllNative (system: {
        default = nativeUnpin system;
      });
    in
    {
      packages = nativePackages // {
        x86_64-linux = nativePackages.x86_64-linux // {
          # Address as: packages.x86_64-linux."windows-x86_64" (see workflow).
          "windows-x86_64" = windowsUnpin;
        };
        aarch64-darwin = nativePackages.aarch64-darwin // {
          # Address as: packages.aarch64-darwin."darwin-x86_64".
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
