use std::process::ExitCode;

use bpaf::{Parser, construct, positional, pure, short};

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

#[derive(Clone, Debug)]
enum Cmd {
    Install {
        assume_yes: bool,
        jobs: u8,
        pick: bool,
        verbose: bool,
        no_data: bool,
        aliases_yes: bool,
        aliases_no: bool,
        aliases_ask: bool,
        pkgs: Vec<String>,
    },
    Update {
        assume_yes: bool,
        jobs: u8,
        pick: bool,
        verbose: bool,
        no_data: bool,
        aliases_yes: bool,
        aliases_no: bool,
        aliases_ask: bool,
        names: Vec<String>,
    },
    Remove {
        assume_yes: bool,
        names: Vec<String>,
    },
    List,
    Info {
        verbose: bool,
        pkgs: Vec<String>,
    },
    Prune,
    Run {
        pick: bool,
        verbose: bool,
        pkg: String,
        args: Vec<String>,
    },
    Completion {
        shell: Shell,
    },
}

#[derive(Clone, Copy, Debug)]
enum Shell {
    Bash,
    Zsh,
    Fish,
    Elvish,
}

impl std::str::FromStr for Shell {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bash" => Ok(Shell::Bash),
            "zsh" => Ok(Shell::Zsh),
            "fish" => Ok(Shell::Fish),
            "elvish" => Ok(Shell::Elvish),
            _ => Err(format!(
                "unknown shell '{s}' (supported: bash, zsh, fish, elvish)"
            )),
        }
    }
}

fn yes_flag() -> impl Parser<bool> {
    short('y').long("yes").help("Skip prompts").switch()
}

fn jobs_flag() -> impl Parser<u8> {
    short('j')
        .long("jobs")
        .help("Parallel downloads (default: min(N, 4))")
        .argument::<u8>("N")
        .fallback(0)
}

fn pick_flag() -> impl Parser<bool> {
    short('p')
        .long("pick")
        .help("Always prompt to choose the asset (instead of auto-picking)")
        .switch()
}

fn verbose_flag() -> impl Parser<bool> {
    short('v')
        .long("verbose")
        .help("Print every HTTP request and show release assets that were filtered out")
        .switch()
}

fn no_data_flag() -> impl Parser<bool> {
    bpaf::long("no-data")
        .help("Skip the per-release runtime data tarball (overrides config `data = true`)")
        .switch()
}

fn aliases_yes_flag() -> impl Parser<bool> {
    bpaf::long("aliases")
        .help("Install multi-call aliases declared by the package (overrides config `aliases = no/ask`)")
        .switch()
}

fn aliases_no_flag() -> impl Parser<bool> {
    bpaf::long("no-aliases")
        .help("Skip multi-call aliases (overrides config; wins over --aliases/--ask-aliases)")
        .switch()
}

fn aliases_ask_flag() -> impl Parser<bool> {
    bpaf::long("ask-aliases")
        .help("Prompt before installing aliases (overrides config `aliases = yes/no`; loses to --no-aliases)")
        .switch()
}

fn cli() -> bpaf::OptionParser<Cmd> {
    let install = {
        let yes = yes_flag();
        let jobs = jobs_flag();
        let pick = pick_flag();
        let verbose = verbose_flag();
        let no_data = no_data_flag();
        let aliases_yes = aliases_yes_flag();
        let aliases_no = aliases_no_flag();
        let aliases_ask = aliases_ask_flag();
        let pkgs = positional::<String>("PKG")
            .help("owner/repo (or bare name for unpins/<name>), optionally with @version")
            .some("expected at least one package");
        construct!(Cmd::Install {
            assume_yes(yes), jobs, pick, verbose, no_data, aliases_yes, aliases_no, aliases_ask, pkgs
        })
            .to_options()
            .descr("Install one or more packages from GitHub releases. Default command — `unpin owner/repo` is equivalent to `unpin install owner/repo`.")
            .command("install")
    };

    let update = {
        let yes = yes_flag();
        let jobs = jobs_flag();
        let pick = pick_flag();
        let verbose = verbose_flag();
        let no_data = no_data_flag();
        let aliases_yes = aliases_yes_flag();
        let aliases_no = aliases_no_flag();
        let aliases_ask = aliases_ask_flag();
        let names = positional::<String>("NAME")
            .help("names of installed packages; empty = update all")
            .many();
        construct!(Cmd::Update {
            assume_yes(yes), jobs, pick, verbose, no_data, aliases_yes, aliases_no, aliases_ask, names
        })
        .to_options()
        .descr("Update one, several, or (with no args) all installed packages.")
        .command("update")
    };

    let remove = {
        let yes = yes_flag();
        let names = positional::<String>("NAME")
            .help("installed package name; empty = remove all (with confirmation)")
            .many();
        construct!(Cmd::Remove { assume_yes(yes), names })
            .to_options()
            .descr("Remove one, several, or (with no args) all installed packages.")
            .command("remove")
    };

    let list = pure(Cmd::List)
        .to_options()
        .descr("List installed packages.")
        .command("list");

    let info = {
        let verbose = verbose_flag();
        let pkgs = positional::<String>("PKG")
            .help("installed name, owner/repo, or bare name for unpins/<name>")
            .some("expected at least one package");
        construct!(Cmd::Info { verbose, pkgs })
            .to_options()
            .descr("Show details about one or more packages (installed or remote).")
            .command("info")
    };

    let prune = pure(Cmd::Prune)
        .to_options()
        .descr("Remove dangling links and unused version dirs from the unpin cache.")
        .command("prune");

    let run = {
        let pick = pick_flag();
        let verbose = verbose_flag();
        let pkg = positional::<String>("PKG")
            .help("owner/repo (or bare name for unpins/<name>), optionally with @version");
        let args = positional::<String>("ARG")
            .help("arguments forwarded to the binary")
            .strict()
            .many();
        construct!(Cmd::Run {
            pick,
            verbose,
            pkg,
            args
        })
        .to_options()
        .descr("Run a package's binary without installing it (no entry added to PATH).")
        .command("run")
    };

    let completion = {
        let shell = positional::<Shell>("SHELL").help("bash | zsh | fish | elvish");
        construct!(Cmd::Completion { shell })
            .to_options()
            .descr("Print a shell completion script. Pipe it to your shell's completion directory (see README).")
            .command("completion")
    };

    construct!([install, update, remove, list, info, prune, run, completion])
        .to_options()
        .usage("Usage: unpin [COMMAND] ...")
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

fn term_width() -> usize {
    console::Term::stdout()
        .size_checked()
        .map(|(_rows, cols)| cols as usize)
        .unwrap_or(80)
        .clamp(40, 120)
}

const SUBCOMMANDS: &[&str] = &[
    "install",
    "update",
    "remove",
    "list",
    "info",
    "prune",
    "run",
    "completion",
];

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
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let pre_ddash: Vec<&str> = raw
        .iter()
        .map(String::as_str)
        .take_while(|a| *a != "--")
        .collect();
    if pre_ddash.iter().any(|a| *a == "--version" || *a == "-V") {
        println!("unpin {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let is_help = pre_ddash.iter().any(|a| *a == "--help" || *a == "-h");
    let is_top_help = is_help && !pre_ddash.iter().any(|a| SUBCOMMANDS.contains(a));
    if is_help {
        print_banner();
        println!();
    }

    // Default command is `install`: if the first arg isn't a known subcommand
    // (or top-level help/version), treat the invocation as `install <args...>`.
    let mut args = raw;
    let needs_install_prefix = match args.first().map(String::as_str) {
        None => false,
        Some(first) => {
            !SUBCOMMANDS.contains(&first)
                && first != "--help"
                && first != "-h"
                && first != "--version"
                && first != "-V"
        }
    };
    if needs_install_prefix {
        args.insert(0, "install".to_owned());
    }

    let bpaf_args = bpaf::Args::from(args.as_slice()).set_name("unpin");
    let cmd = match cli().run_inner(bpaf_args) {
        Ok(c) => c,
        Err(err) => {
            err.print_message(term_width());
            if is_top_help {
                print_auth_footer();
            }
            return ExitCode::from(err.exit_code() as u8);
        }
    };
    let result = match cmd {
        Cmd::Install {
            assume_yes,
            jobs,
            pick,
            verbose,
            no_data,
            aliases_yes,
            aliases_no,
            aliases_ask,
            pkgs,
        } => {
            let ctx = ctx::Ctx::new(verbose);
            let alias_override = resolve_alias_override(aliases_yes, aliases_no, aliases_ask);
            let opts = install::InstallOptions::resolve(
                &ctx,
                assume_yes,
                jobs,
                pick,
                no_data,
                alias_override,
            );
            install::install_many(&ctx, &opts, &pkgs)
        }
        Cmd::Update {
            assume_yes,
            jobs,
            pick,
            verbose,
            no_data,
            aliases_yes,
            aliases_no,
            aliases_ask,
            names,
        } => {
            let ctx = ctx::Ctx::new(verbose);
            let alias_override = resolve_alias_override(aliases_yes, aliases_no, aliases_ask);
            let opts = install::InstallOptions::resolve(
                &ctx,
                assume_yes,
                jobs,
                pick,
                no_data,
                alias_override,
            );
            install::update(&ctx, &opts, &names)
        }
        Cmd::Remove { assume_yes, names } => install::remove_many(&names, assume_yes),
        Cmd::List => install::list(),
        Cmd::Info { verbose, pkgs } => {
            let ctx = ctx::Ctx::new(verbose);
            install::info_many(&ctx, &pkgs)
        }
        Cmd::Prune => install::prune(),
        Cmd::Run {
            pick,
            verbose,
            pkg,
            args,
        } => {
            let ctx = ctx::Ctx::new(verbose);
            install::run(&ctx, &pkg, &args, pick)
        }
        Cmd::Completion { shell } => {
            // bpaf's `autocomplete` feature exposes hidden `--bpaf-complete-style-<shell>`
            // flags that print the script for that shell. We re-enter the parser with
            // that flag so users see a clean `unpin completion <shell>` interface.
            let flag = match shell {
                Shell::Bash => "--bpaf-complete-style-bash",
                Shell::Zsh => "--bpaf-complete-style-zsh",
                Shell::Fish => "--bpaf-complete-style-fish",
                Shell::Elvish => "--bpaf-complete-style-elvish",
            };
            let argv = [flag];
            let inner_args = bpaf::Args::from(&argv[..]).set_name("unpin");
            match cli().run_inner(inner_args) {
                Ok(_) => Err("completion: unexpected Ok from bpaf".to_owned()),
                Err(err) => {
                    err.print_message(term_width());
                    return ExitCode::from(err.exit_code() as u8);
                }
            }
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("unpin: {e}");
            ExitCode::FAILURE
        }
    }
}
