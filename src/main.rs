use std::process::ExitCode;

use bpaf::{construct, positional, pure, short, Parser};

mod archive;
mod github;
mod http;
mod install;
mod panic;
mod sigint;

#[derive(Clone, Debug)]
enum Cmd {
    Install { assume_yes: bool, jobs: u8, pick: bool, verbose: bool, pkgs: Vec<String> },
    Update { assume_yes: bool, jobs: u8, pick: bool, verbose: bool, names: Vec<String> },
    Remove { names: Vec<String> },
    List,
    Info { pkg: String },
    Prune,
    Run { pkg: String, args: Vec<String> },
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
    bpaf::long("pick")
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
            .descr("Install one or more packages from GitHub releases.")
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

    let remove = positional::<String>("NAME")
        .help("installed package name")
        .some("expected at least one package")
        .map(|names| Cmd::Remove { names })
        .to_options()
        .descr("Remove one or more installed packages.")
        .command("remove");

    let list = pure(Cmd::List)
        .to_options()
        .descr("List installed packages.")
        .command("list");

    let info = positional::<String>("PKG")
        .help("installed name, owner/repo, or bare name for unpins/<name>")
        .map(|pkg| Cmd::Info { pkg })
        .to_options()
        .descr("Show details about an installed package, or a remote release if not installed.")
        .command("info");

    let prune = pure(Cmd::Prune)
        .to_options()
        .descr("Remove dangling unpin-managed symlinks from ~/.local/bin.")
        .command("prune");

    let run = {
        let pkg = positional::<String>("PKG").help("owner/repo (or bare name for unpins/<name>), optionally with @version");
        let args = positional::<String>("ARG")
            .help("arguments forwarded to the binary")
            .strict()
            .many();
        construct!(Cmd::Run { pkg, args })
            .to_options()
            .descr("Download a package into a temp dir and run it without installing.")
            .command("run")
    };

    construct!([install, update, remove, list, info, prune, run]).to_options()
}

fn print_banner() {
    println!(
        "unpin {} — install binaries from GitHub releases",
        env!("CARGO_PKG_VERSION")
    );
    println!("https://unpins.org");
}

const SUBCOMMANDS: &[&str] = &[
    "install", "update", "remove", "list", "info", "prune", "run",
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
    if pre_ddash.iter().any(|a| *a == "--help" || *a == "-h") {
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
            err.print_message(80);
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
        Cmd::Remove { names } => install::remove_many(&names),
        Cmd::List => install::list(),
        Cmd::Info { pkg } => install::info(&pkg),
        Cmd::Prune => install::prune(),
        Cmd::Run { pkg, args } => install::run(&pkg, &args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("unpin: {e}");
            ExitCode::FAILURE
        }
    }
}
