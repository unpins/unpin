//! `unpin install` with no package = self-install. Relocate the running
//! binary into the managed `bin` dir and make sure that dir is on `PATH`.
//!
//! The flow a first-time user hits: download `unpin` anywhere with `curl`,
//! run `unpin install`. We move the binary to `bin/unpin[.exe]`, then (with a
//! prompt) add `bin` to `PATH` — editing the right shell profile on Unix, or
//! the per-user `Path` registry value on Windows. Running it again once it's
//! already in place just reports that and re-checks `PATH`.
//!
//! Windows can't delete the running `.exe`, so when we have to *copy* (the
//! download lives on another volume) rather than rename, the freshly placed
//! copy is re-spawned as a silent janitor — keyed by [`CLEANUP_ENV`] — to
//! remove the original once this process exits and unlocks it.

use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::platform::{self, Paths};

/// Internal handoff env var. When set, names the original download path that a
/// freshly relocated Windows copy should delete. A process that sees it acts
/// purely as a janitor (delete the file, exit) and does nothing else.
const CLEANUP_ENV: &str = "UNPIN_CLEANUP_ORIGIN";

/// On-disk file name for unpin's own binary in `bin` — the real executable,
/// not a `.cmd` wrapper (those forward to *package* binaries under `data`).
const SELF_NAME: &str = if cfg!(windows) { "unpin.exe" } else { "unpin" };

/// Entry point for `unpin install` with no package argument.
pub fn run(paths: &Paths, assume_yes: bool) -> Result<(), String> {
    // Janitor handoff (Windows copy path): delete the named origin and exit
    // silently. Must be the very first thing — this process exists only to
    // reap the file the parent couldn't delete while it was still running.
    if let Some(origin) = env::var_os(CLEANUP_ENV) {
        janitor_delete(Path::new(&origin));
        return Ok(());
    }

    let current =
        env::current_exe().map_err(|e| format!("cannot locate the running unpin binary: {e}"))?;
    let dest = paths.bin.join(SELF_NAME);

    if dest.exists() && same_file(&current, &dest) {
        println!("unpin is already installed at {}", dest.display());
    } else {
        let reloc = relocate(&current, &dest)?;
        println!("Installed unpin to {}", dest.display());
        #[cfg(windows)]
        if let Relocation::CopiedOriginRemains(origin) = &reloc {
            spawn_janitor(&dest, origin);
        }
        // Bind on non-Windows so the `reloc` value is always "used".
        let _ = &reloc;
    }

    match ensure_on_path(&paths.bin, assume_yes)? {
        PathOutcome::AlreadyOnPath => {
            println!("{} is already on your PATH.", paths.bin.display());
        }
        PathOutcome::Added(note) => {
            println!("{note}");
        }
        PathOutcome::Skipped(instruction) => {
            println!("{instruction}");
        }
    }
    Ok(())
}

/// Outcome of [`relocate`]. On Unix the origin is always gone (a running
/// binary's path can be unlinked); on Windows a cross-volume copy leaves it
/// behind for the janitor.
enum Relocation {
    Moved,
    #[cfg_attr(not(windows), allow(dead_code))]
    CopiedOriginRemains(PathBuf),
}

/// Move `current` to `dest`. Prefer an atomic rename (same volume); fall back
/// to copy + best-effort delete of the source for a cross-volume move. The
/// copy fallback is also the Windows self-relocation path — there the running
/// `.exe` can't be deleted, so the source is reported as remaining.
fn relocate(current: &Path, dest: &Path) -> Result<Relocation, String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    // A stale older copy at `dest` would make a Windows rename fail and a Unix
    // rename silently replace it; remove it first so both paths behave the
    // same. It is never the running binary (that's `current`, handled by the
    // already-installed check before we get here).
    if dest.exists() {
        let _ = fs::remove_file(dest);
    }

    if fs::rename(current, dest).is_ok() {
        platform::ensure_executable(dest)?;
        return Ok(Relocation::Moved);
    }

    fs::copy(current, dest).map_err(|e| {
        format!(
            "copy {} -> {}: {e}",
            current.display(),
            dest.display()
        )
    })?;
    platform::ensure_executable(dest)?;
    match fs::remove_file(current) {
        Ok(()) => Ok(Relocation::Moved),
        Err(_) => Ok(Relocation::CopiedOriginRemains(current.to_path_buf())),
    }
}

/// True if both paths resolve to the same file. Canonicalization fails when
/// `dest` doesn't exist yet (first install) — that's a clean "not the same".
fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Re-spawn the just-placed `unpin.exe` as a detached janitor that deletes
/// `origin` once we exit and release the file lock. Best-effort: if the spawn
/// itself fails the stray download just lingers, which is harmless.
#[cfg(windows)]
fn spawn_janitor(dest: &Path, origin: &Path) {
    use std::process::Command;
    let _ = Command::new(dest)
        .arg("install")
        .env(CLEANUP_ENV, origin)
        .spawn();
}

/// Delete `origin`, retrying briefly: the parent that spawned us may not have
/// exited yet, so on Windows the file can still be locked for a moment.
fn janitor_delete(origin: &Path) {
    use std::time::Duration;
    for _ in 0..50 {
        if !origin.exists() || fs::remove_file(origin).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

enum PathOutcome {
    AlreadyOnPath,
    /// PATH was changed; the string is the full user-facing note (what changed
    /// plus how to pick it up in the current shell).
    Added(String),
    /// Nothing was changed; the string tells the user how to do it by hand.
    Skipped(String),
}

/// Ensure `bin` is on `PATH`, prompting first. Already there → no-op. Declined,
/// or non-interactive without `-y` → return manual instructions rather than
/// silently editing a profile / the registry.
fn ensure_on_path(bin: &Path, assume_yes: bool) -> Result<PathOutcome, String> {
    if bin_on_path(bin) {
        return Ok(PathOutcome::AlreadyOnPath);
    }

    // Work out exactly what we'd change *before* asking, so the prompt can name
    // the file and the line (Unix) and so an already-configured profile skips
    // the prompt entirely.
    let prompt = match plan_path_change(bin)? {
        PathPlan::AlreadyConfigured(note) => return Ok(PathOutcome::Added(note)),
        PathPlan::Pending { prompt } => prompt,
    };

    let proceed = if assume_yes {
        true
    } else if !io::stdin().is_terminal() {
        return Ok(PathOutcome::Skipped(manual_instruction(bin)));
    } else {
        confirm(&prompt)
    };
    if !proceed {
        return Ok(PathOutcome::Skipped(manual_instruction(bin)));
    }

    apply_path_change(bin)
}

/// What the platform layer would do to put `bin` on `PATH`, decided before we
/// prompt. Keeps the "is it worth asking, and what do we tell the user we'll
/// do" decision next to the platform that knows the mechanism.
enum PathPlan {
    /// The persistent store (a shell profile / the user `Path`) already
    /// references `bin` — it's just not in *this* session. Nothing to write;
    /// the string is the reload hint. (Windows always offers to add, so its
    /// `plan_path_change` never builds this — the idempotency lives in the
    /// PowerShell write instead.)
    #[cfg_attr(windows, allow(dead_code))]
    AlreadyConfigured(String),
    /// Not configured yet. `prompt` spells out the exact change to confirm
    /// (the target file and line on Unix).
    Pending { prompt: String },
}

/// Whether `bin` is already an entry in the current process `PATH`. Uses
/// `env::split_paths` so the separator is correct per-OS, and canonicalizes
/// both sides so `~/.local/bin` vs a symlinked spelling still compare equal.
fn bin_on_path(bin: &Path) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    let target = fs::canonicalize(bin).ok();
    env::split_paths(&path).any(|p| {
        p == bin || (target.is_some() && fs::canonicalize(&p).ok() == target)
    })
}

/// A small yes/no prompt, defaulting to **yes** (this is the recommended
/// action and is reversible). Anything starting with `n`/`N` is no.
fn confirm(question: &str) -> bool {
    eprint!("{question} [Y/n] ");
    io::stderr().flush().ok();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    !matches!(line.trim_start().chars().next(), Some('n') | Some('N'))
}

#[cfg(unix)]
fn manual_instruction(bin: &Path) -> String {
    format!(
        "To use unpin, add this to your shell profile and reopen your shell:\n  export PATH=\"{}:$PATH\"",
        bin.display()
    )
}

#[cfg(windows)]
fn manual_instruction(bin: &Path) -> String {
    format!(
        "To use unpin, add this folder to your PATH and open a new terminal:\n  {}",
        bin.display()
    )
}

/// Append `bin` to `PATH` persistently. Unix: edit the shell profile that
/// matches `$SHELL`. Windows: write the per-user `Path` registry value.
/// Pick the shell profile to edit and the line that puts `bin` on `PATH`,
/// keyed off the `$SHELL` basename. fish has its own PATH syntax; everything
/// else uses a POSIX `export`. An unknown shell falls back to `~/.profile`,
/// read by most POSIX login shells. Pure (no I/O) so it can be unit-tested.
#[cfg(unix)]
fn unix_profile_for(shell: &str, home: &Path, bin: &Path) -> (PathBuf, String) {
    let bin_disp = bin.display().to_string();
    match shell {
        "fish" => (
            home.join(".config/fish/config.fish"),
            format!("fish_add_path {bin_disp}"),
        ),
        "zsh" => (
            home.join(".zshrc"),
            format!("export PATH=\"{bin_disp}:$PATH\""),
        ),
        "bash" => (
            home.join(".bashrc"),
            format!("export PATH=\"{bin_disp}:$PATH\""),
        ),
        _ => (
            home.join(".profile"),
            format!("export PATH=\"{bin_disp}:$PATH\""),
        ),
    }
}

/// Resolve `$SHELL` to its basename and the profile/line we'd write. Shared by
/// the plan (to build the prompt) and the apply (to do the write) so they can't
/// disagree on which file gets edited.
#[cfg(unix)]
fn unix_target(bin: &Path) -> Result<(PathBuf, String), String> {
    let shell = env::var("SHELL").unwrap_or_default();
    let shell = Path::new(&shell)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let home = env::var_os("HOME").map(PathBuf::from).ok_or("$HOME is not set")?;
    Ok(unix_profile_for(shell, &home, bin))
}

#[cfg(unix)]
fn plan_path_change(bin: &Path) -> Result<PathPlan, String> {
    let (profile, line) = unix_target(bin)?;

    // Idempotent: if the profile already mentions this bin dir, don't prompt or
    // append a second entry (e.g. the user edited it before, or re-runs setup
    // in a shell that hasn't been reopened yet).
    let existing = fs::read_to_string(&profile).unwrap_or_default();
    if existing.contains(&bin.display().to_string()) {
        return Ok(PathPlan::AlreadyConfigured(format!(
            "{} is already configured in {}. Open a new shell (or `source {}`).",
            bin.display(),
            profile.display(),
            profile.display()
        )));
    }

    Ok(PathPlan::Pending {
        prompt: format!(
            "{} is not on your PATH. Add this line to {}?\n  {}\n",
            bin.display(),
            profile.display(),
            line
        ),
    })
}

#[cfg(unix)]
fn apply_path_change(bin: &Path) -> Result<PathOutcome, String> {
    let (profile, line) = unix_target(bin)?;

    if let Some(parent) = profile.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let block = format!("\n# added by unpin\n{line}\n");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&profile)
        .map_err(|e| format!("open {}: {e}", profile.display()))?;
    f.write_all(block.as_bytes())
        .map_err(|e| format!("write {}: {e}", profile.display()))?;

    Ok(PathOutcome::Added(format!(
        "Added {} to PATH in {}. Open a new shell (or `source {}`) to use it.",
        bin.display(),
        profile.display(),
        profile.display()
    )))
}

/// Windows can't cheaply distinguish "already in the user Path but not live"
/// without a query, so we always offer to add; the idempotent PowerShell write
/// reports back whether it actually changed anything.
#[cfg(windows)]
fn plan_path_change(bin: &Path) -> Result<PathPlan, String> {
    Ok(PathPlan::Pending {
        prompt: format!("{} is not on your PATH. Add it to your user PATH?", bin.display()),
    })
}

#[cfg(windows)]
fn apply_path_change(bin: &Path) -> Result<PathOutcome, String> {
    use std::process::Command;

    let bin_disp = bin.display().to_string();
    // PowerShell single-quoted literal: the only escape is `'` → `''`.
    let escaped = bin_disp.replace('\'', "''");
    // Read the *user* Path (not the merged process PATH), append our folder if
    // absent, write it back, and broadcast the change to new processes — all
    // of which `[Environment]::SetEnvironmentVariable(..,'User')` handles. No
    // `setx` (it truncates at 1024 chars and clobbers REG_EXPAND_SZ).
    let script = format!(
        "$b='{escaped}'; \
         $p=[Environment]::GetEnvironmentVariable('Path','User'); \
         if (-not $p) {{ $p='' }}; \
         $parts = $p -split ';' | Where-Object {{ $_ -ne '' }}; \
         if ($parts -notcontains $b) {{ \
             $new = if ($p) {{ \"$p;$b\" }} else {{ $b }}; \
             [Environment]::SetEnvironmentVariable('Path', $new, 'User'); \
             'added' \
         }} else {{ 'present' }}"
    );

    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("run powershell to update PATH: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "powershell failed to update PATH: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // The script echoes whether it actually wrote the value or found it there.
    let already = String::from_utf8_lossy(&out.stdout).trim() == "present";
    Ok(PathOutcome::Added(if already {
        format!(
            "{} was already in your user PATH. Open a new terminal to use it.",
            bin.display()
        )
    } else {
        format!(
            "Added {} to your user PATH. Open a new terminal to use it.",
            bin.display()
        )
    }))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn unix_profile_matches_shell() {
        let home = Path::new("/home/u");
        let bin = Path::new("/home/u/.local/bin");

        let (p, line) = unix_profile_for("bash", home, bin);
        assert_eq!(p, home.join(".bashrc"));
        assert_eq!(line, "export PATH=\"/home/u/.local/bin:$PATH\"");

        let (p, line) = unix_profile_for("zsh", home, bin);
        assert_eq!(p, home.join(".zshrc"));
        assert!(line.starts_with("export PATH="));

        let (p, line) = unix_profile_for("fish", home, bin);
        assert_eq!(p, home.join(".config/fish/config.fish"));
        assert_eq!(line, "fish_add_path /home/u/.local/bin");

        // Unknown shell → ~/.profile with a POSIX export.
        let (p, line) = unix_profile_for("nu", home, bin);
        assert_eq!(p, home.join(".profile"));
        assert!(line.starts_with("export PATH="));
    }
}
