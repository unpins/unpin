# Changelog

Notable changes to `unpin`. This project follows [Semantic
Versioning](https://semver.org).

## [Unreleased]

### Fixed
- A package name typed with different capitals than its GitHub repository
  (`unpin install Tree`, `unpin install UNPINS/tree`) installed a second copy
  of the package, with its own `list` entry, which took over the first one's
  commands. Such a name is now refused in every command, with the right
  spelling suggested ("did you mean `tree`?"). A copy already installed under
  another spelling, or under the old name of a repository since renamed on
  GitHub, no longer updates: reinstall it under the current name
  (`unpin uninstall Tree && unpin install tree`).
- After `unpin clean` removed a package's only version, `info` and
  `uninstall` still reported it as installed while `list` did not.
- Building unpin for Windows with a MinGW-w64 12 toolchain failed with
  "redefinition of 'vasprintf'".
- Two `unpin` processes working on the same package could both proceed at
  once — often on Windows, rarely elsewhere — and `clean` could remove a
  version the self-install had just placed. A failed or interrupted install
  no longer leaves lock files, empty directories or (on Windows) its `.part`
  folder behind, and a ctrl-c after one package had failed could remove
  another `unpin`'s install of that package while it was running.
- ctrl-c while `unpin run` waits for its program goes to the program
  alone, and its exit code is unpin's. unpin used to exit under it, leaving
  a program that handles ctrl-c (vim, a Python prompt) running on its own.
- An interrupted `unpin uninstall` or `unpin clean` could leave a partly
  removed version, which `unpin run` then started.
- Windows: `unpin run` exits with its program's whole exit code; one above
  255 (a crash, or ctrl-c's 0xC000013A) was cut to its low byte.
- Installing a multicall package (e.g. `mtools`) no longer warns that its
  own name "is provided by more than one binary in this package".
- Windows: when `%LOCALAPPDATA%` was spelled differently from the disk (an
  8.3 short name, or other capitals), `unpin clean` removed installed
  versions as orphans.

### Security
- Built on nixpkgs 26.05 (was 25.11), with the catalog's musl CVE patches.

## [0.4.0] — 2026-06-15 (developer-only)

### Added
- `-q`/`--quiet` for `install`, `update`, `uninstall`, and `clean` — silences
  progress and summary lines; only errors print. Pair with `-y` for unattended
  runs.
- `unpin uninstall` (no names) now keeps unpin itself; pass `--all` to remove it
  too.
- Opt-in DNS fallback for hosts where the system resolver is unreachable. Off by
  default; enable with `UNPIN_DNS="1.1.1.1 8.8.8.8"` or `dns = ...` in the config.
  Escalates to DNS-over-HTTPS when UDP/53 is blocked.

### Changed
- `prune` is renamed to `clean` (no alias kept).
- Windows: uninstalling unpin removes its folder from your user `PATH` once no
  other link remains in it.
- Windows: programs go on `PATH` as real `<name>.exe` hardlinks, not `.cmd`
  wrappers. Breaking for 0.3.0 installs — reinstall the affected packages.
- unpin's man page is embedded by the release pipeline; `cargo install` builds
  carry no embedded manual.
- `--help` is colored and wraps to the terminal width.
- Reads zstd-compressed embedded metadata; older deflate packages still work.
- The install summary reads as a sentence (`Installed as rg`).
- A download row keeps one stable name for its whole lifetime.

### Removed
- `unpin bundle` — `man` and `readme` are now builtins.

## [0.3.0] — 2026-06-08 (developer-only, dropped)

Initial feature set:

- Run by default — `unpin ffmpeg -version` fetches, verifies its SHA-256, and
  runs; `unpin install` puts a program on `PATH`.
- The unpins catalog — `unpin install htop` resolves to `unpins/htop`; any
  `owner/repo[@version]` works too. Single self-contained binaries, native to
  Linux, macOS, and Windows.
- Full management cycle — `update`, `uninstall`, `list`, `info`, `prune`;
  parallel downloads with a live progress display; multicall aliases.
- Self-install — `unpin install` with no package; no root.
- Helper verbs — `unpin man coreutils ls` renders embedded manuals.
- Shell completions for bash, zsh, fish, and elvish.
