# unpin

> Install single-binary CLI tools straight from GitHub releases — no root, no distro, no dependencies.

`unpin` is the bootstrap CLI of the [unpins](https://unpins.org) project. It
fetches a pre-built binary from a GitHub release, verifies its checksum, and
drops it in your PATH.

```sh
unpin install BurntSushi/ripgrep
rg --version
```

## Install

The official builds are at **<https://unpins.org>**. They are statically linked
and download in one step:

```sh
# Linux
curl -sLo ~/.local/bin/unpin "https://unpins.org/unpin-$(uname -m)-linux"
chmod +x ~/.local/bin/unpin

# macOS
curl -sLo ~/.local/bin/unpin "https://unpins.org/unpin-$(uname -m)-darwin"
chmod +x ~/.local/bin/unpin
```

```powershell
# Windows (PowerShell)
$DEST = "$env:LOCALAPPDATA\unpin"
mkdir $DEST -Force > $null
irm https://unpins.org/unpin-x86_64-windows.exe -OutFile "$DEST\unpin.exe"
```

Ensure `~/.local/bin` (Linux/macOS) or `%LOCALAPPDATA%\unpin` (Windows) is in
your `PATH`.

### From source via Cargo

```sh
cargo install --git https://github.com/unpins/unpin --locked
```

This builds `unpin` from the latest commit and drops it in `~/.cargo/bin`.
Requires a Rust toolchain (edition 2024, MSRV matches the latest stable).
Native TLS uses an embedded `mbedtls` build, so `cmake`, `perl`, `python3`,
and `libclang` need to be available — install them through your package
manager if `cargo install` complains.

### From source via Nix

```sh
nix build github:unpins/unpin
./result/bin/unpin --version
```

The flake outputs static binaries for Linux/macOS and a cross-built `.exe` for
Windows. See `flake.nix` for the build matrix.

## Usage

```text
unpin [run] <repo> [args...] Fetch and execute a binary without linking (default command)
unpin install <repo>...      Install one or more packages onto PATH
unpin update [<name>...]     Pull newer releases (all packages if no names)
unpin remove <name>...       Uninstall packages
unpin list                   List installed packages
unpin info <name>...         Show details for installed packages
unpin prune                  Drop old versions, keep the active one
unpin completion <shell>     Print a shell completion script
```

A bare name with no command runs the package; installing onto `PATH` is the
explicit `unpin install`. Helper verbs dispatch the same way — `unpin man
coreutils ls` runs the [`man`](https://github.com/unpins/man) package (a
patched mandoc) on coreutils' embedded manual.

Common flags:

| Flag                | Meaning                                                    |
| ------------------- | ---------------------------------------------------------- |
| `-y`, `--yes`       | Skip confirmation prompts                                  |
| `-j N`, `--jobs N`  | Parallel workers for download + extract (default: min(N, 4)) |
| `--pick`            | Always prompt when multiple release assets match           |
| `-v`, `--verbose`   | Show filtered-out assets and the reason                    |
| `-V`, `--version`   | Print `unpin <version>`                                    |

A `<repo>` is `owner/name[@version]`. When the owner is omitted, `unpins` is
assumed — so `unpin install htop` resolves to `unpins/htop`. When `@version`
is omitted, the latest release is used.

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

MIT. Packaged tools keep their upstream licenses — see the
[packages page](https://unpins.org/packages.html).
