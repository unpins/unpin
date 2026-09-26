# Changelog

Notable changes to `unpin`. This project follows [Semantic
Versioning](https://semver.org).

## [Unreleased]

### Removed
- The `--no-data` option and the `data` config setting. No package in the
  catalog publishes the separate data file they controlled: a package that
  needs data files at runtime carries them inside its binary. `unpin` no longer
  looks for that file, and a release that still has one (only `nmap v7.99-1`)
  now installs as the bare binary — pick a newer version of it instead.

## [0.5.0] - 2026-09-26

### Fixed
- A package name typed with other capitals (`unpin install Tree`) installed a
  second copy of the package, which took over the first one's commands. Such a
  name is now refused, with the right spelling suggested. A copy already
  installed under another spelling no longer updates — reinstall it under the
  current name.
- After `unpin clean` removed a package's only version, `info` and `uninstall`
  still reported it as installed while `list` did not.
- Two `unpin` processes working on the same package could both proceed at
  once, often on Windows, and one could remove what the other had just
  installed.
- A failed or interrupted install left lock files, empty directories and, on
  Windows, its `.part` folder behind. `unpin clean` also removes the lock
  files 0.4 left inside each package's directory.
- An interrupted `unpin uninstall` or `unpin clean` could leave a partly
  removed version, which `unpin run` then started.
- ctrl-c during `unpin run` goes to the program alone. unpin used to exit
  under it, leaving a program that handles ctrl-c (vim, a Python prompt)
  running on its own.
- Windows: `unpin run` cut an exit code above 255 — a crash, or ctrl-c — to
  its low byte.
- Windows: adding unpin's folder to your PATH turned the PATH's `%VARIABLE%`
  references into fixed paths, and the folder could be added twice or left
  behind by an uninstall.
- Windows: `unpin clean` removed installed versions as orphans when
  `%LOCALAPPDATA%` was spelled differently from the disk.
- Installing a multicall package (e.g. `mtools`) warned that its own name "is
  provided by more than one binary in this package".
- Building unpin for Windows with a MinGW-w64 12 toolchain failed with
  "redefinition of 'vasprintf'".

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
