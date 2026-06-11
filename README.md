# unpin

> Install programs straight from GitHub releases — no root, no distro packages.

`unpin` is the CLI installer of the [unpins](https://unpins.org) project. It
fetches a program from a GitHub release, verifies its checksum, and either
runs it on the spot or drops it in your PATH.

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://unpins.org/demo/unpin-demo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://unpins.org/demo/unpin-demo-light.svg">
    <img alt="unpin demo — run a program straight from a GitHub release, then install several from the curated catalog in parallel" src="https://unpins.org/demo/unpin-demo-dark.svg">
  </picture>
</div>

```sh
# Running without a subcommand fetches and runs the program — nothing is installed (the default):
unpin ffmpeg -version

# Install from the curated catalog (a name with no owner resolves to unpins/<name>):
unpin install htop

# Or install from any GitHub release:
unpin install BurntSushi/ripgrep
```

## The unpins catalog

A name with no owner installs from the [unpins catalog](https://unpins.org/packages.html),
a curated set of common programs that we build as single self-contained
binaries. `unpin install jq` resolves to [`unpins/jq`](https://github.com/unpins/jq)
and works the same on Linux, macOS, and Windows. You're not limited to the
catalog: give `unpin` any `owner/repo[@version]` and it installs from that
GitHub release.

## Install

The official builds are at **<https://unpins.org>**. Each platform gets a
single self-contained binary. Download yours, then run `unpin install` — it
moves the binary into place and offers to add that directory to your `PATH`:

```sh
# Linux
curl -fsSLo unpin "https://unpins.org/unpin-$(uname -m)-linux"
chmod +x unpin
./unpin install

# macOS
curl -fsSLo unpin "https://unpins.org/unpin-$(uname -m)-darwin"
chmod +x unpin
./unpin install
```

```powershell
# Windows (PowerShell or cmd; needs Windows 10 1803+ for bundled curl)
curl.exe -fsSLo unpin.exe https://unpins.org/unpin-x86_64-windows.exe
.\unpin.exe install
```

`unpin install` needs no root: it drops the binary in `~/.local/bin`
(Linux/macOS) or `%LOCALAPPDATA%\unpin` (Windows) — a user directory — and only
edits your `PATH` after asking. Open a new shell for the change to take effect.

Linux builds cover six architectures — x86_64, aarch64, armv7l, i686, ppc64le,
and riscv64; macOS builds cover Intel and Apple Silicon; Windows is x86_64.
The `$(uname -m)` in the URL picks the right one.

Every build has a `.sha256` file at the same URL with `.sha256` appended —
compare it against `sha256sum unpin` (Linux), `shasum -a 256 unpin` (macOS),
or `CertUtil -hashfile unpin.exe SHA256` (Windows) to verify the download.

### From source via Cargo

```sh
cargo install --git https://github.com/unpins/unpin --locked
```

This builds `unpin` from the latest commit and drops it in `~/.cargo/bin`.
Requires a Rust toolchain (edition 2024, MSRV matches the latest stable).
Native TLS uses an embedded `mbedtls` build, so `cmake`, `perl`, `python3`,
and `libclang` need to be available — install them through your package
manager if `cargo install` complains.

One caveat: the opt-in [DNS fallback](#no-dns-android-minimal-containers) is
linked into the official binaries by the Nix build — a Cargo build doesn't
include it, so `UNPIN_DNS` and the `dns` config key have no effect there.

### From source via Nix

```sh
nix build github:unpins/unpin
./result/bin/unpin --version
```

The flake outputs self-contained binaries for Linux/macOS and a cross-built `.exe` for
Windows. See `flake.nix` for the build matrix.

## Usage

```text
unpin [run] <repo> [args...] Fetch and execute a binary without linking (default command)
unpin install                Self-install: move this binary into place and add it to PATH
unpin install <repo>...      Install one or more packages onto PATH
unpin update [<name>...]     Pull newer releases (all packages if no names)
unpin uninstall [<name>...]  Uninstall one or more packages (all if no names)
unpin list                   List installed packages
unpin info <name>...         Show details for packages (installed or not)
unpin prune                  Drop old versions, keep the active one
unpin completion <shell>     Print a shell completion script
```

Running without a subcommand runs the program; installing onto `PATH` is the
explicit `unpin install`. Helper verbs dispatch the same way — `unpin man
coreutils ls` runs the [`man`](https://github.com/unpins/man) package (a
patched mandoc) on coreutils' embedded manual.

Common flags:

| Flag                | Meaning                                                    |
| ------------------- | ---------------------------------------------------------- |
| `-y`, `--yes`       | Skip confirmation prompts                                  |
| `-j N`, `--jobs N`  | Parallel workers for download + extract (default: one per package, max 4) |
| `--pick`            | Always prompt when multiple release assets match           |
| `-v`, `--verbose`   | Print every HTTP request and the release assets filtered out |
| `-V`, `--version`   | Print `unpin <version>`                                    |

A `<repo>` is `owner/name[@version]`. When the owner is omitted, `unpins` is
assumed — so `unpin install htop` resolves to `unpins/htop`. When `@version`
is omitted, the latest release is used.

## No DNS? (Android, minimal containers)

On a host that can't reach any DNS server — Android has no `/etc/resolv.conf`,
a barebones container may ship none, a nameserver may be dead or blocked —
downloads fail with a resolver error. unpin and every program from the catalog
can resolve through a public DNS server instead, but that fallback is **off by
default**: it never second-guesses a working resolver, and even when enabled it
only kicks in when the system resolver can't be reached at all. On such a
failure unpin prints a short hint with both ways to turn it on:

```sh
# one run:
UNPIN_DNS="1.1.1.1 8.8.8.8" unpin install htop

# always — add to unpin's config file (~/.config/unpin/config on Linux/macOS,
# %APPDATA%\unpin\config on Windows); every unpins program honours it, not
# just unpin:
dns = 1.1.1.1 8.8.8.8
```

The value is a space-separated list of IPv4 literals, tried in order over
UDP/53 and then DNS-over-HTTPS for networks that also block port 53.
`UNPIN_DNS` overrides the config for a single run.

## Shell completion

`unpin completion <shell>` prints a script that hooks the binary into your
shell's completion. Generated dynamically by the parser, so it always matches
the installed version's commands and flags.

```sh
# bash
unpin completion bash > ~/.local/share/bash-completion/completions/unpin

# zsh — add ~/.zfunc to fpath in ~/.zshrc, then:
unpin completion zsh > ~/.zfunc/_unpin

# fish
unpin completion fish > ~/.config/fish/completions/unpin.fish

# elvish
unpin completion elvish >> ~/.config/elvish/rc.elv
```

Start a new shell session to pick up the completion.

## License

MIT. Packaged programs keep their upstream licenses — see the
[packages page](https://unpins.org/packages.html).
