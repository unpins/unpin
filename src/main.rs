use std::process::ExitCode;

use bpaf::{construct, positional, pure, short, Parser};

mod archive;
mod github;
mod http;
mod install;
mod panic;
mod platform;
mod sigint;

#[derive(Clone, Debug)]
enum Cmd {
    Install { assume_yes: bool, jobs: u8, pick: bool, verbose: bool, pkgs: Vec<String> },
    Update { assume_yes: bool, jobs: u8, pick: bool, verbose: bool, names: Vec<String> },
    Remove { assume_yes: bool, names: Vec<String> },
    List,
    Info { pkgs: Vec<String> },
    Prune,
    Run { pkg: String, args: Vec<String> },
    Completion { shell: Shell },
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
            _ => Err(format!("unknown shell '{s}' (supported: bash, zsh, fish, elvish)")),
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
        .help("Show release assets that were filtered out")
        .switch()
}

fn cli() -> bpaf::OptionParser<Cmd> {
    let install = {
        let yes = yes_flag();
        let jobs = jobs_flag();
        let pick = pick_flag();
        let verbose = verbose_flag();
        let pkgs = positional::<String>("PKG")
            .help("owner/repo (or bare name for unpins/<name>), optionally with @version")
            .some("expected at least one package");
        construct!(Cmd::Install { assume_yes(yes), jobs, pick, verbose, pkgs })
            .to_options()
            .descr("Install one or more packages from GitHub releases. Default command — `unpin owner/repo` is equivalent to `unpin install owner/repo`.")
            .command("install")
    };

    let update = {
        let yes = yes_flag();
        let jobs = jobs_flag();
        let pick = pick_flag();
        let verbose = verbose_flag();
        let names = positional::<String>("NAME")
            .help("names of installed packages; empty = update all")
            .many();
        construct!(Cmd::Update { assume_yes(yes), jobs, pick, verbose, names })
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

    let info = positional::<String>("PKG")
        .help("installed name, owner/repo, or bare name for unpins/<name>")
        .some("expected at least one package")
        .map(|pkgs| Cmd::Info { pkgs })
        .to_options()
        .descr("Show details about one or more packages (installed or remote).")
        .command("info");

    let prune = pure(Cmd::Prune)
        .to_options()
        .descr("Remove dangling links and unused version dirs from the unpin cache.")
        .command("prune");

    let run = {
        let pkg = positional::<String>("PKG").help("owner/repo (or bare name for unpins/<name>), optionally with @version");
        let args = positional::<String>("ARG")
            .help("arguments forwarded to the binary")
            .strict()
            .many();
        construct!(Cmd::Run { pkg, args })
            .to_options()
            .descr("Run a package's binary without installing it (no entry added to PATH).")
            .command("run")
    };

    let completion = {
        let shell = positional::<Shell>("SHELL")
            .help("bash | zsh | fish | elvish");
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
    println!("  UNPIN_GITHUB_TOKEN | GITHUB_TOKEN | GH_TOKEN   token from env var");
    println!("  UNPIN_USE_GH_AUTH=1                            use `gh auth token`");
}

fn term_width() -> usize {
    console::Term::stdout()
        .size_checked()
        .map(|(_rows, cols)| cols as usize)
        .unwrap_or(80)
        .clamp(40, 120)
}

const SUBCOMMANDS: &[&str] = &[
    "install", "update", "remove", "list", "info", "prune", "run", "completion",
];

fn main() -> ExitCode {
    panic::install();
    sigint::install();
    // Look for --version / --help only in args BEFORE `--` so that
    // `unpin run pkg -- --version` forwards the flag to the child instead of
    // being intercepted here.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let pre_ddash: Vec<&str> = raw.iter().map(String::as_str).take_while(|a| *a != "--").collect();
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
        Cmd::Install { assume_yes, jobs, pick, verbose, pkgs } => {
            install::install_many(&pkgs, assume_yes, jobs, pick, verbose)
        }
        Cmd::Update { assume_yes, jobs, pick, verbose, names } => {
            install::update(&names, assume_yes, jobs, pick, verbose)
        }
        Cmd::Remove { assume_yes, names } => install::remove_many(&names, assume_yes),
        Cmd::List => install::list(),
        Cmd::Info { pkgs } => install::info_many(&pkgs),
        Cmd::Prune => install::prune(),
        Cmd::Run { pkg, args } => install::run(&pkg, &args),
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
