# Changelog

Notable changes to `unpin`. This project follows [Semantic
Versioning](https://semver.org).

## [Unreleased]

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
