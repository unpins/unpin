use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

mod aliases;
mod archive;
mod config;
mod ctx;
mod github;
mod http;
mod install;
mod panic;
mod platform;
mod sigint;

#[derive(Parser, Debug)]
#[command(name = "unpin", version)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Install one or more packages from GitHub releases. Default command — `unpin owner/repo` is equivalent to `unpin install owner/repo`.
    Install(InstallCmd),
    /// Update one, several, or (with no args) all installed packages.
    Update(UpdateCmd),
    /// Remove one, several, or (with no args) all installed packages.
    Remove(RemoveCmd),
    /// List installed packages.
    List,
    /// Show details about one or more packages (installed or remote).
    Info(InfoCmd),
    /// Remove dangling links and unused version dirs from the unpin cache.
    Prune,
    /// Run a package's binary without installing it (no entry added to PATH).
    Run(RunCmd),
    /// Print a shell completion script. Pipe it to your shell's completion directory (see README).
    Completion(CompletionCmd),
}

impl Cmd {
    fn run(self) -> Result<(), String> {
        match self {
            Cmd::Install(c) => c.run(),
            Cmd::Update(c) => c.run(),
            Cmd::Remove(c) => c.run(),
            Cmd::List => install::list(),
            Cmd::Info(c) => c.run(),
            Cmd::Prune => install::prune(),
            Cmd::Run(c) => c.run(),
            Cmd::Completion(c) => c.run(),
        }
    }
}

#[derive(Args, Debug)]
struct InstallCmd {
    #[command(flatten)]
    flags: InstallUpdateFlags,
    /// owner/repo (or bare name for unpins/<name>), optionally with @version
    #[arg(value_name = "PKG", required = true)]
    pkgs: Vec<String>,
}

impl InstallCmd {
    fn run(self) -> Result<(), String> {
        let (ctx, opts) = self.flags.resolve();
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
    fn run(self) -> Result<(), String> {
        let (ctx, opts) = self.flags.resolve();
        install::update(&ctx, &opts, &self.names)
    }
}

#[derive(Args, Debug)]
struct RemoveCmd {
    /// Skip prompts
    #[arg(short = 'y', long = "yes")]
    assume_yes: bool,
    /// installed package name; empty = remove all (with confirmation)
    #[arg(value_name = "NAME")]
    names: Vec<String>,
}

impl RemoveCmd {
    fn run(self) -> Result<(), String> {
        install::remove_many(&self.names, self.assume_yes)
    }
}

#[derive(Args, Debug)]
struct InfoCmd {
    /// Print every HTTP request and show release assets that were filtered out
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
    /// installed name, owner/repo, or bare name for unpins/<name>
    #[arg(value_name = "PKG", required = true)]
    pkgs: Vec<String>,
}

impl InfoCmd {
    fn run(self) -> Result<(), String> {
        let ctx = ctx::Ctx::new(self.verbose);
        install::info_many(&ctx, &self.pkgs)
    }
}

#[derive(Args, Debug)]
struct RunCmd {
    /// Always prompt to choose the asset (instead of auto-picking)
    #[arg(short = 'p', long = "pick")]
    pick: bool,
    /// Print every HTTP request and show release assets that were filtered out
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
    /// owner/repo (or bare name for unpins/<name>), optionally with @version
    #[arg(value_name = "PKG")]
    pkg: String,
    /// arguments forwarded to the binary
    #[arg(value_name = "ARG", trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

impl RunCmd {
    fn run(self) -> Result<(), String> {
        let ctx = ctx::Ctx::new(self.verbose);
        install::run(&ctx, &self.pkg, &self.args, self.pick)
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
        let mut cmd = Cli::command();
        clap_complete::generate(self.shell.generator(), &mut cmd, "unpin", &mut std::io::stdout());
        Ok(())
    }
}

#[derive(Args, Debug)]
struct InstallUpdateFlags {
    /// Skip prompts
    #[arg(short = 'y', long = "yes")]
    assume_yes: bool,
    /// Parallel downloads (default: min(N, 4))
    #[arg(short = 'j', long = "jobs", value_name = "N", default_value_t = 0, hide_default_value = true)]
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
    fn resolve(&self) -> (ctx::Ctx, install::InstallOptions) {
        let ctx = ctx::Ctx::new(self.verbose);
        let alias_override =
            resolve_alias_override(self.aliases_yes, self.aliases_no, self.aliases_ask);
        let opts = install::InstallOptions::resolve(
            &ctx,
            self.assume_yes,
            self.jobs,
            self.pick,
            self.no_data,
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

fn print_banner() {
    println!(
        "unpin {} — install binaries from GitHub releases",
        env!("CARGO_PKG_VERSION")
    );
    println!("https://unpins.org");
}

fn print_auth_footer() {
    println!();
    println!("Auth (optional, raises GitHub API rate limit from 60/h to 5000/h):");
    println!("  GITHUB_TOKEN | GH_TOKEN          token from env var");
    println!("  use_gh_auth = true (in config)   use `gh auth token`");
    println!();
    println!("Config file: {}", platform::config_path().display());
    println!("  Flat `key = value` with `#` comments. Recognized keys:");
    println!("    http_timeout = <seconds>   per-request HTTP timeout (default: 30)");
    println!("    use_gh_auth  = true|false  shell out to `gh auth token` (default: false)");
    println!("    data         = true|false  download per-release data tarball  (default: true)");
    println!("    aliases      = yes|no|ask  install multi-call aliases declared by");
    println!("                               catalog packages (default: yes; non-catalog");
    println!("                               <owner>/<repo> installs always skip)");
}

/// Subcommands clap accepts. `help` is auto-generated by clap (we don't
/// `disable_help_subcommand`); listing it here keeps it out of the default-
/// `install` retry path and the subcommand-help classification.
const SUBCOMMANDS: &[&str] = &[
    "install",
    "update",
    "remove",
    "list",
    "info",
    "prune",
    "run",
    "completion",
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
/// try a second pass with `install` injected as the default subcommand.
/// On retry failure, return the original error so clap's error usage line
/// doesn't expose the injected prefix.
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
        prefixed.push("install".to_owned());
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
    sigint::install();
    // Look for --version / --help only in args BEFORE `--` so that
    // `unpin run pkg -- --version` forwards the flag to the child instead of
    // being intercepted here.
    let raw: Vec<String> = std::env::args().collect();
    let pre_ddash: Vec<&str> = raw
        .iter()
        .skip(1)
        .map(String::as_str)
        .take_while(|a| *a != "--")
        .collect();
    if pre_ddash.iter().any(|a| *a == "--version" || *a == "-V") {
        println!("unpin {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let help_kind = classify_help(&pre_ddash);
    if !matches!(help_kind, HelpKind::None) {
        print_banner();
        println!();
    }

    let cli = match parse_args(&raw) {
        Ok(c) => c,
        Err(err) => {
            let code = err.exit_code() as u8;
            err.print().ok();
            if matches!(help_kind, HelpKind::TopLevel) {
                print_auth_footer();
            }
            return ExitCode::from(code);
        }
    };
    match cli.command.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("unpin: {e}");
            ExitCode::FAILURE
        }
    }
}
