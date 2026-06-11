use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

mod aliases;
mod archive;
mod bundle;
mod config;
mod ctx;
mod github;
mod help;
mod http;
mod install;
mod meta;
mod panic;
mod platform;
mod progress;
// Provides `unpin_readurl`, the optional generic HTTP-fetch hook the static-musl
// DNS fallback shim (nix-lib/dns-fallback) calls to do DoH when UDP/53 is
// blocked. Linked, never called from Rust — kept by `#[no_mangle]`, bound by
// the C archive.
mod readurl;
mod setup;
mod sigint;

// The palette help.rs mirrors for the hand-written parts: section headers
// yellow, typeable literals green (the scheme gleam uses).
const STYLES: clap::builder::Styles = clap::builder::Styles::styled()
    .header(clap::builder::styling::AnsiColor::Yellow.on_default())
    .usage(clap::builder::styling::AnsiColor::Yellow.on_default())
    .literal(clap::builder::styling::AnsiColor::Green.on_default());

#[derive(Parser, Debug)]
#[command(name = "unpin", version, styles = STYLES)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Install one or more packages from GitHub releases onto your PATH. With no package, installs unpin itself: moves this binary into place and adds it to PATH.
    Install(InstallCmd),
    /// Update one, several, or (with no args) all installed packages.
    Update(UpdateCmd),
    /// Uninstall one, several, or (with no args) all installed packages.
    Uninstall(UninstallCmd),
    /// List installed packages.
    List,
    /// Show details about one or more packages (installed or remote).
    Info(InfoCmd),
    /// Remove dangling links and unused version dirs from the unpin cache.
    Clean,
    /// Run a package's binary without installing it (no entry added to PATH). Default command — `unpin owner/repo` is equivalent to `unpin run owner/repo`.
    Run(RunCmd),
    /// Print a shell completion script. Pipe it to your shell's completion directory (see README).
    Completion(CompletionCmd),
    /// Inspect a package's embedded metadata bundle — its `unpin/*` entries (stable interface used by helper packages such as `man`).
    Bundle(BundleCmd),
    /// (internal) Detached cleanup helper for Windows self-(un)install: delete a
    /// stray file and/or unpin's own repo dir once the spawning process exits.
    #[command(hide = true)]
    Reap(ReapCmd),
}

impl Cmd {
    /// `Ok(code)` carries the desired process exit code. Most subcommands
    /// produce 0 on success; `run` forwards the child's exit code so callers
    /// can chain unpin into shell pipelines without losing failure signals.
    fn run(self, paths: &platform::Paths) -> Result<i32, String> {
        match self {
            Cmd::Install(c) => c.run(paths).map(|()| 0),
            Cmd::Update(c) => c.run(paths).map(|()| 0),
            Cmd::Uninstall(c) => c.run(paths).map(|()| 0),
            Cmd::List => install::list(paths).map(|()| 0),
            Cmd::Info(c) => c.run(paths).map(|()| 0),
            Cmd::Clean => install::clean(paths).map(|()| 0),
            Cmd::Run(c) => c.run(paths),
            Cmd::Completion(c) => c.run().map(|()| 0),
            Cmd::Bundle(c) => c.run(paths).map(|()| 0),
            Cmd::Reap(c) => {
                c.run();
                Ok(0)
            }
        }
    }
}

#[derive(Args, Debug)]
struct InstallCmd {
    #[command(flatten)]
    flags: InstallUpdateFlags,
    /// owner/repo (or a catalog name for unpins/<name>), optionally with @version. Omit to self-install unpin.
    #[arg(value_name = "PKG")]
    pkgs: Vec<String>,
}

impl InstallCmd {
    fn run(self, paths: &platform::Paths) -> Result<(), String> {
        // No package = self-install: relocate this binary into `bin` and put
        // that dir on PATH. Only `-y` matters here (skip the PATH prompt).
        if self.pkgs.is_empty() {
            return setup::run(paths, self.flags.assume_yes, self.flags.force);
        }
        let (ctx, opts) = self.flags.resolve(paths);
        install::install_many(&ctx, &opts, &self.pkgs)
    }
}

#[derive(Args, Debug)]
struct UpdateCmd {
    #[command(flatten)]
    flags: InstallUpdateFlags,
    /// names of installed packages; empty = update all
    #[arg(value_name = "NAME")]
    names: Vec<String>,
}

impl UpdateCmd {
    fn run(self, paths: &platform::Paths) -> Result<(), String> {
        let (ctx, opts) = self.flags.resolve(paths);
        install::update(&ctx, &opts, &self.names)
    }
}

#[derive(Args, Debug)]
struct UninstallCmd {
    /// Skip prompts
    #[arg(short = 'y', long = "yes")]
    assume_yes: bool,
    /// installed package name; empty = uninstall all (with confirmation)
    #[arg(value_name = "NAME")]
    names: Vec<String>,
}

impl UninstallCmd {
    fn run(self, paths: &platform::Paths) -> Result<(), String> {
        install::uninstall_many(paths, &self.names, self.assume_yes)
    }
}

/// Hidden cleanup helper spawned by the Windows self-(un)install janitors. The
/// spawning parent — which still holds the exact paths in memory — passes them
/// here as arguments; this process does nothing but the deletes and exits, so
/// the parent can finish removing files/dirs it couldn't unlink while running.
#[derive(Args, Debug)]
struct ReapCmd {
    /// Stray files to delete (the copied-from download after a self-install,
    /// or tombstones of busy bin links after a self-uninstall). Repeatable.
    #[arg(long)]
    file: Vec<std::path::PathBuf>,
    /// unpin's own repo dir to remove, owner dir pruned (after a self-uninstall).
    #[arg(long)]
    dir: Option<std::path::PathBuf>,
}

impl ReapCmd {
    fn run(self) {
        setup::reap(self.file, self.dir);
    }
}

#[derive(Args, Debug)]
struct InfoCmd {
    /// Print every HTTP request and show release assets that were filtered out
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
    /// installed name, owner/repo, or a catalog name for unpins/<name>
    #[arg(value_name = "PKG", required = true)]
    pkgs: Vec<String>,
}

impl InfoCmd {
    fn run(self, paths: &platform::Paths) -> Result<(), String> {
        let ctx = ctx::Ctx::new(self.verbose, paths.clone());
        install::info_many(&ctx, &self.pkgs)
    }
}

// `disable_help_flag`: everything after the package belongs to the package, so
// `-h`/`--help` must reach the tool (e.g. `unpin owner/repo --help` shows the
// tool's help, not run's). `run`'s own help stays reachable via `unpin help run`
// and the top-level `unpin --help`.
#[derive(Args, Debug)]
#[command(disable_help_flag = true)]
struct RunCmd {
    /// Always prompt to choose the asset (instead of auto-picking)
    #[arg(short = 'p', long = "pick")]
    pick: bool,
    /// Skip prompts (e.g. proceed without a SHA-256 checksum)
    #[arg(short = 'y', long = "yes")]
    assume_yes: bool,
    /// Re-resolve the latest release from GitHub instead of running a cached version
    #[arg(long = "refresh")]
    refresh: bool,
    /// Print every HTTP request and show release assets that were filtered out
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
    /// owner/repo (or a catalog name for unpins/<name>), optionally with @version
    #[arg(value_name = "PKG")]
    pkg: String,
    /// arguments forwarded to the binary
    #[arg(
        value_name = "ARG",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    args: Vec<String>,
}

impl RunCmd {
    fn run(self, paths: &platform::Paths) -> Result<i32, String> {
        let ctx = ctx::Ctx::new(self.verbose, paths.clone());
        install::run(
            &ctx,
            &self.pkg,
            &self.args,
            self.pick,
            self.assume_yes,
            self.refresh,
        )
    }
}

#[derive(Args, Debug)]
struct CompletionCmd {
    /// bash | zsh | fish | elvish
    #[arg(value_name = "SHELL")]
    shell: Shell,
}

impl CompletionCmd {
    fn run(self) -> Result<(), String> {
        use std::io::Write;
        let mut cmd = Cli::command();
        // Generate into memory first: `Vec<u8>` writes never fail, so
        // clap_complete's internal `.expect()` on write errors can't fire and
        // turn a full disk / EIO into a panic that bypasses main()'s error
        // handler. Then surface a real stdout write error as a String. A broken
        // pipe is handled earlier by the default SIGPIPE disposition (see
        // panic.rs), so it exits quietly rather than reaching here.
        let mut buf: Vec<u8> = Vec::new();
        clap_complete::generate(self.shell.generator(), &mut cmd, "unpin", &mut buf);
        std::io::stdout()
            .write_all(&buf)
            .map_err(|e| format!("write completions: {e}"))
    }
}

#[derive(Args, Debug)]
struct BundleCmd {
    #[command(subcommand)]
    op: BundleOp,
}

#[derive(Subcommand, Debug)]
enum BundleOp {
    /// List every entry in the bundle (`path<TAB>size`, or `path<TAB>-> target` for a `.so` symlink).
    List {
        /// Package whose binary to read (installed name, or `unpin` for the running binary)
        #[arg(value_name = "PKG")]
        pkg: String,
    },
    /// Print one entry's bytes to stdout; prints nothing if the entry (or the whole bundle) is absent.
    Dump {
        /// Package whose binary to read (installed name, or `unpin` for the running binary)
        #[arg(value_name = "PKG")]
        pkg: String,
        /// Entry path, e.g. `unpin/aliases`
        #[arg(value_name = "ENTRY")]
        entry: String,
    },
}

impl BundleCmd {
    fn run(self, paths: &platform::Paths) -> Result<(), String> {
        match self.op {
            BundleOp::List { pkg } => bundle::list(paths, &pkg),
            BundleOp::Dump { pkg, entry } => bundle::dump(paths, &pkg, &entry),
        }
    }
}

#[derive(Args, Debug)]
struct InstallUpdateFlags {
    /// Skip prompts
    #[arg(short = 'y', long = "yes")]
    assume_yes: bool,
    /// Reinstall even if already present: re-download and re-extract over the
    /// cached version (self-install just refreshes the placed binary and links)
    #[arg(short = 'f', long = "force")]
    force: bool,
    /// Parallel downloads (default: one per package, max 4)
    #[arg(
        short = 'j',
        long = "jobs",
        value_name = "N",
        default_value_t = 0,
        hide_default_value = true
    )]
    jobs: u8,
    /// Always prompt to choose the asset (instead of auto-picking)
    #[arg(short = 'p', long = "pick")]
    pick: bool,
    /// Print every HTTP request and show release assets that were filtered out
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
    /// Skip the per-release runtime data tarball (overrides config `data = true`)
    #[arg(long = "no-data")]
    no_data: bool,
    /// Install multi-call aliases declared by the package (overrides config `aliases = no/ask`)
    #[arg(long = "aliases")]
    aliases_yes: bool,
    /// Skip multi-call aliases (overrides config; wins over --aliases/--ask-aliases)
    #[arg(long = "no-aliases")]
    aliases_no: bool,
    /// Prompt before installing aliases (overrides config `aliases = yes/no`; loses to --no-aliases)
    #[arg(long = "ask-aliases")]
    aliases_ask: bool,
}

impl InstallUpdateFlags {
    fn resolve(&self, paths: &platform::Paths) -> (ctx::Ctx, install::InstallOptions) {
        let ctx = ctx::Ctx::new(self.verbose, paths.clone());
        let alias_override =
            resolve_alias_override(self.aliases_yes, self.aliases_no, self.aliases_ask);
        let opts = install::InstallOptions::resolve(
            &ctx,
            self.assume_yes,
            self.jobs,
            self.pick,
            self.no_data,
            self.force,
            alias_override,
        );
        (ctx, opts)
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "lower")]
enum Shell {
    Bash,
    Zsh,
    Fish,
    Elvish,
}

impl Shell {
    fn generator(self) -> clap_complete::Shell {
        match self {
            Shell::Bash => clap_complete::Shell::Bash,
            Shell::Zsh => clap_complete::Shell::Zsh,
            Shell::Fish => clap_complete::Shell::Fish,
            Shell::Elvish => clap_complete::Shell::Elvish,
        }
    }
}

/// Subcommands clap accepts. `help` is auto-generated by clap (we don't
/// `disable_help_subcommand`); listing it here keeps it out of the default-
/// `install` retry path and the subcommand-help classification.
const SUBCOMMANDS: &[&str] = &[
    "install",
    "update",
    "uninstall",
    "list",
    "info",
    "clean",
    "run",
    "completion",
    "bundle",
    "reap",
    "help",
];

enum HelpKind {
    None,
    TopLevel,
    Subcommand,
}

/// Decide whether the invocation will trigger top-level help, subcommand
/// help, or neither — used to gate the banner (any help) and auth footer
/// (top-level help only). Mirrors clap's own routing for `--help`/`-h`
/// and the auto `help` subcommand.
fn classify_help(pre_ddash: &[&str]) -> HelpKind {
    // An invocation that resolves to `run` — explicit `run …`, or the default-
    // run injection (a leading token that is neither a subcommand nor a
    // top-level help/version flag) — forwards *all* of its args to the package,
    // `--help`/`-h` included. So it never triggers unpin's own help banner. This
    // mirrors `parse_args`' retry condition.
    let first = pre_ddash.first().copied().unwrap_or("");
    let resolves_to_run = first == "run"
        || (!first.is_empty()
            && !SUBCOMMANDS.contains(&first)
            && !matches!(first, "--help" | "-h" | "--version" | "-V"));
    if resolves_to_run {
        return HelpKind::None;
    }
    if pre_ddash.first() == Some(&"help") {
        return match pre_ddash.get(1) {
            Some(a) if SUBCOMMANDS.contains(a) && *a != "help" => HelpKind::Subcommand,
            _ => HelpKind::TopLevel,
        };
    }
    if let Some(h) = pre_ddash.iter().position(|a| *a == "--help" || *a == "-h") {
        let s = pre_ddash
            .iter()
            .position(|a| SUBCOMMANDS.contains(a) && *a != "help");
        return if s.is_none_or(|s| h < s) {
            HelpKind::TopLevel
        } else {
            HelpKind::Subcommand
        };
    }
    HelpKind::None
}

/// Parse argv. If the user didn't lead with a subcommand or top-level flag,
/// try a second pass with `run` injected as the default subcommand — so
/// `unpin owner/repo [args...]` runs the package, and `unpin man coreutils ls`
/// dispatches the `man` verb to the `man` package (a catalog name is now run, not
/// installed; installing is the explicit `unpin install`). On retry failure,
/// return the original error so clap's error usage line doesn't expose the
/// injected prefix.
fn parse_args(raw: &[String]) -> Result<Cli, clap::Error> {
    let e1 = match Cli::try_parse_from(raw) {
        Ok(c) => return Ok(c),
        Err(e) => e,
    };
    let first = raw.get(1).map(String::as_str).unwrap_or("");
    let can_retry = !first.is_empty()
        && !SUBCOMMANDS.contains(&first)
        && !matches!(first, "--help" | "-h" | "--version" | "-V");
    if can_retry {
        let mut prefixed = Vec::with_capacity(raw.len() + 1);
        prefixed.push(raw[0].clone());
        prefixed.push("run".to_owned());
        prefixed.extend_from_slice(&raw[1..]);
        if let Ok(c) = Cli::try_parse_from(&prefixed) {
            return Ok(c);
        }
    }
    Err(e1)
}

/// Resolve `--aliases` / `--ask-aliases` / `--no-aliases` to an explicit
/// override, or `None` to fall back to config.
///
/// Precedence (safest wins so a mistaken `--aliases` next to `--no-aliases`
/// doesn't install): `--no-aliases` > `--ask-aliases` > `--aliases`.
fn resolve_alias_override(yes: bool, no: bool, ask: bool) -> Option<aliases::AliasMode> {
    if no {
        Some(aliases::AliasMode::No)
    } else if ask {
        Some(aliases::AliasMode::Ask)
    } else if yes {
        Some(aliases::AliasMode::Yes)
    } else {
        None
    }
}

fn main() -> ExitCode {
    panic::install();
    panic::restore_sigpipe_default();
    sigint::install();
    // Build the pre-`--` view used to classify unpin's own help banner. After a
    // package spec (`unpin owner/repo …` or `unpin run owner/repo …`) every arg
    // — `--help`/`--version` included — is forwarded to the tool, so the banner
    // is gated on the invocation NOT resolving to `run` (see classify_help) and
    // clap's top-level `version`/`help` flags (not propagated to subcommands)
    // handle the bare `unpin --version` / `unpin --help` cases.
    let raw: Vec<String> = std::env::args().collect();
    let pre_ddash: Vec<&str> = raw
        .iter()
        .skip(1)
        .map(String::as_str)
        .take_while(|a| *a != "--")
        .collect();
    let help_kind = classify_help(&pre_ddash);
    if !matches!(help_kind, HelpKind::None) {
        help::banner();
        println!();
    }

    // Resolve the install paths once, up front. Held as a `Result` so that
    // help/usage output still renders when `$HOME` is unset (the footer just
    // shows the config path as unresolved) — only an actual command treats a
    // missing base dir as a hard error.
    let paths = platform::Paths::resolve();

    let cli = match parse_args(&raw) {
        Ok(c) => c,
        Err(err) => {
            let code = err.exit_code() as u8;
            err.print().ok();
            if matches!(help_kind, HelpKind::TopLevel) {
                help::footer(paths.as_ref().ok().map(|p| p.config.as_path()));
            }
            return ExitCode::from(code);
        }
    };
    let paths = match paths {
        Ok(p) => p,
        Err(e) => {
            eprintln!("unpin: {e}");
            return ExitCode::FAILURE;
        }
    };
    match cli.command.run(&paths) {
        Ok(0) => ExitCode::SUCCESS,
        // Child exit codes are 8-bit on Unix (waitpid masks the low byte); on
        // Windows they fit a DWORD but ExitCode caps at u8 anyway. Truncating
        // is the same thing the shell does after a child dies, so callers see
        // the conventional value.
        Ok(code) => ExitCode::from((code & 0xff) as u8),
        Err(e) => {
            eprintln!("unpin: {e}");
            // `e` is often just a summary ("N operation(s) failed") — the
            // per-request errors were printed (and classified) where they
            // were born, in the http layer. Its latch is the signal.
            if http::saw_dns_failure() {
                help::dns_hint(&paths.config);
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        std::iter::once("unpin")
            .chain(parts.iter().copied())
            .map(String::from)
            .collect()
    }

    /// The `run` args actually parsed for an invocation, or `None` if it didn't
    /// resolve to `run` (e.g. it was a different verb or a clap short-circuit).
    fn run_args(parts: &[&str]) -> Option<Vec<String>> {
        match parse_args(&argv(parts)).ok()?.command {
            Cmd::Run(c) => Some(c.args),
            _ => None,
        }
    }

    #[test]
    fn version_flag_forwards_to_the_package_in_the_default_run_path() {
        // `unpin owner/repo --version` must reach the tool, not print unpin's.
        assert_eq!(
            run_args(&["BurntSushi/ripgrep", "--version"]).as_deref(),
            Some(&["--version".to_string()][..])
        );
        assert_eq!(
            run_args(&["BurntSushi/ripgrep", "-V"]).as_deref(),
            Some(&["-V".to_string()][..])
        );
    }

    #[test]
    fn version_flag_forwards_with_an_explicit_run_verb() {
        assert_eq!(
            run_args(&["run", "owner/repo", "--version"]).as_deref(),
            Some(&["--version".to_string()][..])
        );
        assert_eq!(
            run_args(&["run", "owner/repo", "--", "--version"]).as_deref(),
            Some(&["--version".to_string()][..])
        );
    }

    #[test]
    fn top_level_version_flag_is_clap_native_not_a_run() {
        // `unpin --version` / `-V` short-circuit in clap (DisplayVersion), so
        // they neither parse as `run` nor reach the package.
        for flag in ["--version", "-V"] {
            let err =
                parse_args(&argv(&[flag])).expect_err("top-level version should short-circuit");
            assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        }
    }

    #[test]
    fn help_flag_forwards_to_the_package_after_a_pkg_spec() {
        // Everything after the package is the tool's, including --help/-h —
        // both in the default-run path and after an explicit `run`.
        for flag in ["--help", "-h"] {
            assert_eq!(
                run_args(&["BurntSushi/ripgrep", flag]).as_deref(),
                Some(&[flag.to_string()][..]),
                "default-run should forward {flag}"
            );
            assert_eq!(
                run_args(&["run", "owner/repo", flag]).as_deref(),
                Some(&[flag.to_string()][..]),
                "explicit run should forward {flag}"
            );
        }
    }

    #[test]
    fn classify_help_skips_the_banner_for_run_invocations() {
        // A package spec forwards --help to the tool, so unpin's banner must
        // not fire — neither in the default-run path nor after `run`.
        assert!(matches!(
            classify_help(&["owner/repo", "--help"]),
            HelpKind::None
        ));
        assert!(matches!(
            classify_help(&["run", "owner/repo", "--help"]),
            HelpKind::None
        ));
        assert!(matches!(
            classify_help(&["owner/repo", "-h"]),
            HelpKind::None
        ));
    }

    #[test]
    fn classify_help_still_recognizes_unpins_own_help() {
        // unpin's own help paths keep their banner.
        assert!(matches!(classify_help(&["--help"]), HelpKind::TopLevel));
        assert!(matches!(classify_help(&["-h"]), HelpKind::TopLevel));
        assert!(matches!(classify_help(&["help"]), HelpKind::TopLevel));
        assert!(matches!(
            classify_help(&["install", "--help"]),
            HelpKind::Subcommand
        ));
        assert!(matches!(
            classify_help(&["help", "install"]),
            HelpKind::Subcommand
        ));
        assert!(matches!(classify_help(&["list"]), HelpKind::None));
    }

    /// `force` on the `Install` flags for an invocation, or `None` if it didn't
    /// parse as `install`.
    fn install_force(parts: &[&str]) -> Option<bool> {
        match parse_args(&argv(parts)).ok()?.command {
            Cmd::Install(c) => Some(c.flags.force),
            _ => None,
        }
    }

    #[test]
    fn force_flag_parses_on_install() {
        // The bug this guards: `--force`/`-f` used to be an unknown argument,
        // so the whole command was rejected.
        assert_eq!(
            install_force(&["install", "--force", "owner/repo"]),
            Some(true)
        );
        assert_eq!(install_force(&["install", "-f", "owner/repo"]), Some(true));
        assert_eq!(install_force(&["install", "owner/repo"]), Some(false));
    }

    #[test]
    fn force_flag_parses_on_self_install() {
        // `unpin install --force` with no package — the self-install path.
        match parse_args(&argv(&["install", "--force"]))
            .expect("self-install --force should parse")
            .command
        {
            Cmd::Install(c) => {
                assert!(c.flags.force);
                assert!(c.pkgs.is_empty(), "no package = self-install");
            }
            other => panic!("expected install, got {other:?}"),
        }
    }

    #[test]
    fn force_flag_parses_on_update_too() {
        // `force` rides the shared install/update flags, so update gets it free.
        let force = |parts: &[&str]| match parse_args(&argv(parts)).ok()?.command {
            Cmd::Update(c) => Some(c.flags.force),
            _ => None,
        };
        assert_eq!(force(&["update", "--force"]), Some(true));
        assert_eq!(force(&["update"]), Some(false));
    }
}
