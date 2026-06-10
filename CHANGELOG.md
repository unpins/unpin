# Changelog

Notable changes to `unpin`. This project follows [Semantic
Versioning](https://semver.org).

## [Unreleased]

### Added
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
- **`--help` is colored and wraps to the terminal width.** Section headers
  yellow, commands/flags/literals green (same palette throughout, including
  the Auth/Networking/Config footer and the DNS hint), prose re-flows to the
  terminal; piped output stays plain. The banner now carries the project
  slogan, and `--jobs`'s default is described as what it is (one worker per
  package, max 4).
- Reads **zstd-compressed embedded metadata**, so `unpin man <pkg>` and
  `unpin bundle` keep working as catalog packages shrink their embedded man
  pages. Backward-compatible: older (deflate) packages still read fine.
