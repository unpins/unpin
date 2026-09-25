# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`unpin` is the Rust CLI installer of the unpins project: it fetches a program from a GitHub release, verifies its checksum, and runs it (`unpin <pkg> …`, the default) or installs it into a bin dir on `PATH`. A bare name resolves to the curated catalog (`unpins/<name>`); `owner/repo[@version]` works for any release. Workspace-wide conventions live in `../docs/CLAUDE.md` — read it first; `../docs/embedded-metadata.md`, `embedded-man.md` and `helper-verbs.md` specify formats this crate implements.

## Commits

- **Do not add trailers to commit messages** — no `Co-Authored-By:` or any other trailer line. This overrides the harness default (project-wide rule: `../docs/contributing.md`).
- Commit and push from this directory (its own repo), never from the workspace root.
- `CHANGELOG.md` entries (under `[Unreleased]`) state what changed and its user-visible impact — no justification of why the new behaviour is better.

## Commands

```bash
cargo build
cargo test --locked                     # the whole suite (unit tests live in-module, #[cfg(test)])
cargo test <name_substring>             # a single test
cargo fmt --check
cargo clippy --all-targets
cargo clippy --target x86_64-pc-windows-gnu --all-targets   # cfg(windows) code is invisible to the host build

nix build .                                              # release binary (static), as CI ships it
nix build '.#packages.x86_64-linux."windows-x86_64"'     # unpin.exe (mingw)
bash .github/smoke-scenario.sh "$(pwd)/result/bin/unpin" # live end-to-end session (install/run/man/update/uninstall); set GITHUB_TOKEN
```

- **Lint gate before every commit:** `cargo fmt --check` and `cargo clippy --all-targets` with zero warnings, on the host **and** the Windows target. Scoped `#[allow]` with a one-line justification only for genuine false positives; never crate-wide.
- `nix build` runs no tests (`doCheck = false`); `test.yml` is the only place they run — natively on linux x86_64/aarch64 and macOS, and on Windows by cross-building the test exe with mingw (`cargo test --target x86_64-pc-windows-gnu --no-run`) and running it on `windows-latest`. Locally, run that exe on the Windows VM or under wine (see `../CLAUDE.md`).
- `mandoc-sys` is a git dependency pinned by rev; bumping it means updating its hash in `flake.nix` (`cargoLockOutputHashes`).
- The `Makefile` (`slim`, `slim-nightly`) is only for size experiments; releases come from the flake.

## Architecture

- **`main.rs`** — clap CLI and command dispatch. Each command builds a `ctx::Ctx` once (config + auth header + HTTP client + verbose) and passes `&Ctx` down; it is `Sync` because extract workers share it.
- **`platform.rs`** — the OS boundary. Everything path/link/exec-specific goes through here: symlinks on Unix, `<name>.exe` NTFS **hardlinks** in `%LOCALAPPDATA%\unpin\` on Windows (with a real `read_link` via `FindFirstFileNameW`, so link bookkeeping is shared with Unix), `run_foreground` (exec on Unix; wait on Windows), and the install lock (`InstallLock`). Keep `cfg` branches here rather than spreading them.
- **`install/`** — the install/update pipeline shared by `install` and `update` (`pipeline::run_pipeline_v2`): parallel preflight (`spec` parses/validates `owner/name@version`, `github` fetches the release, `asset` picks the asset and its SHA-256) → parallel extract into a sibling `<vdir>.part` → link (`linker` creates bin-dir links per executable and honours embedded aliases). `.part` dirs must be skipped by anything that enumerates installed versions.
- **`archive.rs`** — extraction of attacker-controlled archives; all writes are scoped with `cap_std` (`openat2(RESOLVE_BENEATH)` on Linux), so traversal is refused at the syscall layer. Don't bypass it with plain `std::fs` paths built from archive names.
- **`sigint.rs`** — the ctrl-c handler owns the transient state (held locks, `.part` dirs, in-flight extractions via one atomic): on interrupt it cancels extractions, waits for them, removes leftovers and releases locks. New transient on-disk state must register here.
- **`progress.rs`** — single-render-thread TEA UI: workers send `Msg`s over a channel and never write to stderr; the render thread redraws the whole frame. Prompts during a live block go through its `Reporter`; `install/prompt.rs` is the plain (no live bars) path.
- **Embedded metadata** — catalog binaries carry a ZIP of `unpin/*` entries (aliases, man pages, README). `meta.rs` locates and reads it, `bundle.rs` exposes it, `aliases.rs` applies the multicall alias policy, and `render/` renders `man` (via `mandoc-sys`, in-process) and `readme` (termimad) through a shared pager.
- **`setup.rs`** — `unpin install` with no package self-installs the running binary as the `unpins/unpin` package and ensures the bin dir is on `PATH`.
- **`readurl.rs`** — `#[no_mangle]` hook the static-musl DNS-fallback C shim (from `nix-lib`) calls for DoH; never called from Rust.
- **`http.rs`** — minreq/rustls transport; DNS-failure detection and the user hint happen where the transport error is produced.
