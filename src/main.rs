use std::process::ExitCode;

use bpaf::{construct, positional, pure, Parser};

mod aliases;
mod archive;
mod github;
mod install;
mod panic;

#[derive(Clone, Debug)]
enum Cmd {
    Install(String),
    Update(Vec<String>),
    Remove(String),
    List,
}

fn cli() -> bpaf::OptionParser<Cmd> {
    let install = positional::<String>("PKG")
        .help("alias or owner/repo, optionally with @version")
        .map(Cmd::Install)
        .to_options()
        .descr("Install a package from a GitHub release.")
        .command("install");

    let update = positional::<String>("NAME")
        .help("names of installed packages; empty = update all")
        .many()
        .map(Cmd::Update)
        .to_options()
        .descr("Update one, several, or (with no args) all installed packages.")
        .command("update");

    let remove = positional::<String>("NAME")
        .help("installed package name")
        .map(Cmd::Remove)
        .to_options()
        .descr("Remove an installed package.")
        .command("remove");

    let list = pure(Cmd::List)
        .to_options()
        .descr("List installed packages.")
        .command("list");

    construct!([install, update, remove, list])
        .to_options()
        .descr("ghp — install binaries from GitHub releases.")
}

fn main() -> ExitCode {
    panic::install();
    let cmd = cli().run();
    let result = match cmd {
        Cmd::Install(pkg) => install::install(&pkg),
        Cmd::Update(names) => install::update(&names),
        Cmd::Remove(name) => install::remove(&name),
        Cmd::List => install::list(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ghp: {e}");
            ExitCode::FAILURE
        }
    }
}
