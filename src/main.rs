use std::process::ExitCode;

use bpaf::{construct, positional, pure, short, Parser};

mod archive;
mod github;
mod http;
mod install;
mod panic;

#[derive(Clone, Debug)]
enum Cmd {
    Install { assume_yes: bool, pkgs: Vec<String> },
    Update { assume_yes: bool, names: Vec<String> },
    Remove { names: Vec<String> },
    List,
    Info { pkg: String },
    Prune,
    Run { pkg: String, args: Vec<String> },
}

fn yes_flag() -> impl Parser<bool> {
    short('y').long("yes").help("Skip prompts").switch()
}

fn cli() -> bpaf::OptionParser<Cmd> {
    let install = {
        let yes = yes_flag();
        let pkgs = positional::<String>("PKG")
            .help("owner/repo (or bare name for unpins/<name>), optionally with @version")
            .some("expected at least one package");
        construct!(Cmd::Install { assume_yes(yes), pkgs })
            .to_options()
            .descr("Install one or more packages from GitHub releases.")
            .command("install")
    };

    let update = {
        let yes = yes_flag();
        let names = positional::<String>("NAME")
            .help("names of installed packages; empty = update all")
            .many();
        construct!(Cmd::Update { assume_yes(yes), names })
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

    construct!([install, update, remove, list, info, prune, run])
        .to_options()
        .descr("unpin — install binaries from GitHub releases.")
}

fn main() -> ExitCode {
    panic::install();
    let cmd = cli().run();
    let result = match cmd {
        Cmd::Install { assume_yes, pkgs } => install::install_many(&pkgs, assume_yes),
        Cmd::Update { assume_yes, names } => install::update(&names, assume_yes),
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
