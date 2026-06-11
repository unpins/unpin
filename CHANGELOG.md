# Changelog

Notable changes to `unpin`. This project follows [Semantic
Versioning](https://semver.org).

## [0.4.0] — 2026-06-10

### Added
- **`unpin uninstall --keep-unpin`** uninstalls every package except unpin
  itself. A bare `unpin uninstall` (no names) now points this option out before
  it removes unpin along with everything else.
- **Opt-in DNS fallback for hosts where the system resolver is unreachable.**
  On a host that can't reach any DNS server — some containers, Android, a
  dead/blocked nameserver — downloads fail to resolve. `unpin` can now resolve
  through a public DNS server instead, but it stays **off by default** so it
  never second-guesses your resolver. When an error looks like a failed name
  resolution, `unpin` prints a short hint with both ways to turn it on: set
  `UNPIN_DNS="1.1.1.1 8.8.8.8"` for a single run, or add `dns = 1.1.1.1 8.8.8.8`
  to the config file — which every unpins program then honors, not just `unpin`.
  A normal answer, including a deliberate "no such host", is always respected;
  the fallback escalates to DNS-over-HTTPS when UDP/53 is blocked. See
  `unpin --help`.

### Changed
- **`prune` is renamed to `clean`.** Same behavior — remove dangling links and
  unused version dirs. No alias is kept; update any scripts that called
  `unpin prune`.
- **Windows: uninstalling unpin itself now takes its folder back off your user
  PATH** once no other installed package's link remains in it, instead of
  leaving a dangling entry. (Unix leaves the shell-profile line in place.)
- **Windows: programs go on `PATH` as real `<name>.exe` NTFS hardlinks**, not
  `.cmd` wrappers. They now resolve everywhere an `.exe` does — cmd,
  PowerShell, git-bash/MSYS, WSL interop — and `unpin list`/`info` can show
  which version a link points at. Breaking for v0.3.0 installs (no `.cmd`
  migration): reinstall the affected packages.
- **unpin's own man page is embedded by the release pipeline**, through the
  same metadata overlay every catalog package uses, instead of a special
  compiled-in copy. `unpin man unpin` works as before on release binaries; a
  source build via `cargo install` carries no embedded manual.
- **`--help` is colored and wraps to the terminal width.** Section headers
  yellow, commands/flags/literals green (same palette throughout, including
  the Auth/Networking/Config footer and the DNS hint), prose re-flows to the
  terminal; piped output stays plain. The banner now carries the project
  slogan, and `--jobs`'s default is described as what it is (one worker per
  package, max 4).
- Reads **zstd-compressed embedded metadata**, so `unpin man <pkg>` and
  `unpin bundle` keep working as catalog packages shrink their embedded man
  pages. Backward-compatible: older (deflate) packages still read fine.
- **The install summary line reads as a sentence** —
  `Installed ls, cat with aliases zcat, unxz (1 alias skipped)`. Binaries ride
  bare after the verb, aliases get a `with alias(es)` clause, and notes trail in
  parentheses.
- **A download row keeps one stable name.** It used to flip between
  `owner/repo` and `name version` mid-download and back; now it shows a single
  identity the whole time and merely gains the resolved version once it's known
  (`BurntSushi/ripgrep 15.1.0`), never repeating the version on the finished
  row. Catalog programs render by their bare name (`jq`, not `unpins/jq`),
  third-party ones keep `owner/repo`, and `install` and `run` now look
  identical.

## [0.3.0] — 2026-06-08

**First public release** (earlier versions were internal). `unpin` arrives
with its core feature set complete:

- **Run by default** — `unpin ffmpeg -version` fetches the program from a
  GitHub release, verifies its SHA-256, and runs it; nothing is installed.
  Putting it on `PATH` is the explicit `unpin install`.
- **The unpins catalog** — a catalog name (`unpin install htop`) resolves to
  `unpins/htop`: curated programs built as single self-contained binaries,
  natively for Linux, macOS, and Windows. Any `owner/repo[@version]` installs
  from that repo's releases just the same.
- **The full management cycle** — `update`, `uninstall`, `list`, `info`,
  `prune`; parallel downloads with a live progress display; multicall
  aliases (`coreutils` can install its applets as commands).
- **Self-install** — `unpin install` with no package moves the downloaded
  binary into place and offers to put its directory on `PATH`. No root.
- **Helper verbs and embedded metadata** — `unpin man coreutils ls` renders
  the manual embedded in the package's own binary (via the `man` package);
  `unpin bundle` exposes the raw entries.
- **Shell completions** for bash, zsh, fish, and elvish, generated from the
  real parser.
