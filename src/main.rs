use std::process::ExitCode;

use argh::FromArgs;

mod aliases;
mod archive;
mod github;
mod install;
mod panic;

/// ghp — install binaries from GitHub releases.
#[derive(FromArgs)]
struct Cli {
    #[argh(subcommand)]
    cmd: Cmd,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Cmd {
    Install(InstallCmd),
    Update(UpdateCmd),
    Remove(RemoveCmd),
    List(ListCmd),
}

/// Install a package from a GitHub release.
#[derive(FromArgs)]
#[argh(subcommand, name = "install")]
struct InstallCmd {
    /// alias or owner/repo, optionally with @version
    #[argh(positional)]
    pkg: String,
}

/// Update one, several, or (with no args) all installed packages.
#[derive(FromArgs)]
#[argh(subcommand, name = "update")]
struct UpdateCmd {
    /// names of installed packages; empty = update all
    #[argh(positional)]
    names: Vec<String>,
}

/// Remove an installed package.
#[derive(FromArgs)]
#[argh(subcommand, name = "remove")]
struct RemoveCmd {
    /// installed package name
    #[argh(positional)]
    name: String,
}

/// List installed packages.
#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
struct ListCmd {}

fn main() -> ExitCode {
    panic::install();
    let cli: Cli = argh::from_env();
    let result = match cli.cmd {
        Cmd::Install(c) => install::install(&c.pkg),
        Cmd::Update(c) => install::update(&c.names),
        Cmd::Remove(c) => install::remove(&c.name),
        Cmd::List(_) => install::list(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ghp: {e}");
            ExitCode::FAILURE
        }
    }
}
