//! `unpin install` with no package = self-install. Register the running binary
//! as the `unpins/unpin` package — exactly the layout a normal install
//! produces — and make sure the `bin` dir is on `PATH`.
//!
//! The flow a first-time user hits: download `unpin` anywhere with `curl`, run
//! `unpin install`. We drop the binary into its version dir under `data` and
//! link it into `bin` via the regular linker, so `unpin update` self-updates,
//! `unpin list` shows it, and `unpin uninstall` removes it like any package.
//! Then (with a prompt) we add `bin` to `PATH` — editing the right shell
//! profile on Unix, or the per-user `Path` registry value on Windows.
//!
//! Windows can't delete the running `.exe`, so when we have to *copy* (the
//! download lives on another volume) rather than rename, the freshly placed
//! copy is re-spawned as a detached `unpin reap --file <origin>` (a hidden
//! janitor subcommand) to remove the original once this process exits and
//! unlocks it. The self-uninstall sibling spawns `unpin reap --dir <repo>` the
//! same way. The exact path is passed as an argument — carried from the
//! parent's memory, never re-derived or read from the ambient environment.

use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::install;
use crate::platform::{self, Paths};

/// On-disk file name for unpin's own binary inside its version dir — the real
/// executable. The `bin` entry that points at it is a symlink (Unix) or an
/// NTFS hardlink (Windows), created by the linker like any package's.
const SELF_NAME: &str = if cfg!(windows) { "unpin.exe" } else { "unpin" };

/// Entry point for `unpin install` with no package argument. `force` reinstalls
/// even when this binary is already the installed one — though there's nothing
/// to relocate then (it's in place), so force only refreshes the link + PATH.
pub fn run(paths: &Paths, assume_yes: bool, force: bool) -> Result<(), String> {
    let current =
        env::current_exe().map_err(|e| format!("cannot locate the running unpin binary: {e}"))?;
    let spec = install::self_spec();
    let tag = spec.version.clone().unwrap_or_default();
    let vdir = paths.version_dir(&spec.owner, &spec.name, &tag);
    // The binary lives at `<vdir>/unpin[.exe]`; the PATH entry is the link the
    // linker creates next to the other packages' links.
    let dest = vdir.join(SELF_NAME);
    let link = paths.bin.join(platform::link_filename(&spec.name));

    if dest.exists() && same_file(&current, &dest) {
        // We ARE the installed binary — there's nothing to relocate (a copy
        // onto itself would just delete the file). Re-link (idempotent) and
        // re-check PATH. `--force` can't redo a no-op relocation, so it only
        // changes the message.
        install::link_installed(paths, &spec, &vdir, assume_yes)?;
        if force {
            println!(
                "Reinstalled unpin {tag} ({}) — already in place, links refreshed.",
                link.display()
            );
        } else {
            println!("unpin {tag} is already installed ({}).", link.display());
        }
    } else {
        // Windows: replacing the registered binary in place (same-version
        // re-bootstrap from a fresh download) severs the bin hardlink's
        // introspectability — once `relocate` removes `dest`'s name, the bin
        // entry is a sole-name file that the linker's sweep can no longer
        // map to this package and would treat as foreign (prompting, or
        // skipping the refresh entirely without a tty). Drop the link now,
        // while `read_link` still resolves it; the linker recreates it right
        // after. Best-effort: on failure the linker's foreign-file prompt is
        // the (pre-existing) fallback.
        #[cfg(windows)]
        if dest.exists() && platform::read_link(&link).is_some_and(|t| t.starts_with(&vdir)) {
            let _ = fs::remove_file(&link);
        }
        let reloc = relocate(&current, &dest)?;
        install::link_installed(paths, &spec, &vdir, assume_yes)?;
        println!("Installed unpin {tag} ({}).", link.display());
        #[cfg(windows)]
        if let Relocation::CopiedOriginRemains(origin) = &reloc {
            // Spawn the `.exe` we just placed under packages\ as the janitor.
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

    fs::copy(current, dest)
        .map_err(|e| format!("copy {} -> {}: {e}", current.display(), dest.display()))?;
    platform::ensure_executable(dest)?;
    match fs::remove_file(current) {
        Ok(()) => Ok(Relocation::Moved),
        Err(_) => Ok(Relocation::CopiedOriginRemains(current.to_path_buf())),
    }
}

/// True if both paths resolve to the same file. Canonicalization fails when
/// `dest` doesn't exist yet (first install) — that's a clean "not the same".
/// Windows compares file identity instead: the running unpin is usually the
/// bin-dir *hardlink* of the registered `packages\` binary, and two hardlink
/// names of one file never canonicalize equal.
fn same_file(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        platform::is_same_file(a, b)
    }
    #[cfg(unix)]
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Re-spawn the just-placed `unpin.exe` as a detached `unpin reap --file
/// <origin>` that deletes `origin` once we exit and release the file lock.
/// Best-effort: if the spawn itself fails the stray download just lingers,
/// which is harmless. The exact origin path is passed as an argument, so the
/// reaper never has to re-derive or guess it.
#[cfg(windows)]
fn spawn_janitor(dest: &Path, origin: &Path) {
    use std::process::Command;
    let _ = Command::new(dest)
        .arg("reap")
        .arg("--file")
        .arg(origin)
        .spawn();
}

/// Delete `origin`, retrying briefly: the parent that spawned us may not have
/// exited yet, so on Windows the file can still be locked for a moment.
#[cfg(windows)]
fn janitor_delete(origin: &Path) {
    use std::time::Duration;
    for _ in 0..50 {
        if !origin.exists() || fs::remove_file(origin).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Like [`janitor_delete`] but for a whole directory — unpin's repo dir on a
/// self-uninstall, retried until the just-exited parent's `.exe` is unlocked.
/// Once the repo dir is gone, prune the now-empty owner dir too, mirroring the
/// normal uninstall path (which `uninstall_one` skips via an early return on
/// the self-uninstall branch). `remove_dir` only succeeds on an empty dir, so
/// an owner that still holds other packages is a harmless no-op.
#[cfg(windows)]
fn janitor_delete_dir(dir: &Path) {
    use std::time::Duration;
    for _ in 0..50 {
        if !dir.exists() || fs::remove_dir_all(dir).is_ok() {
            if let Some(owner) = dir.parent() {
                let _ = fs::remove_dir(owner);
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Entry point for the hidden `unpin reap` subcommand: the janitor body that a
/// detached copy runs to finish a Windows self-(un)install. Each `--file` is a
/// stray file to unlink (a copied-from download, or the tombstone of a busy
/// bin link); `dir` is unpin's own repo dir to remove (and its now-empty owner
/// pruned). All paths come straight from the spawning parent's memory as CLI
/// arguments — never re-derived. A no-op off Windows, where the reaper is
/// never spawned.
pub fn reap(files: Vec<PathBuf>, dir: Option<PathBuf>) {
    #[cfg(windows)]
    {
        for f in &files {
            janitor_delete(f);
        }
        if let Some(d) = dir {
            janitor_delete_dir(&d);
        }
    }
    #[cfg(not(windows))]
    let _ = (files, dir);
}

/// True if the running image lives inside `dir` — i.e. uninstalling `dir`
/// would have to delete the very file we're executing, which Windows forbids.
/// Covers both spellings of "inside": executing the `packages\` binary
/// directly (path containment), and executing its bin-dir *hardlink* — the
/// usual case since the PATH entry is a hardlink — where `read_link` maps the
/// running name to its `packages\` co-name.
#[cfg(windows)]
pub fn running_from(dir: &Path) -> bool {
    let Ok(exe) = env::current_exe() else {
        return false;
    };
    if let (Ok(e), Ok(d)) = (fs::canonicalize(&exe), fs::canonicalize(dir))
        && e.starts_with(&d)
    {
        return true;
    }
    platform::read_link(&exe).is_some_and(|t| t.starts_with(dir))
}

/// Copy the running exe to `%TEMP%` so it can later be spawned as the
/// janitor for a self-uninstall. Must run **before** the uninstall link
/// sweep: the running image is usually the bin-dir hardlink, and once the
/// sweep deletes/renames that name, `current_exe()`'s recorded path is stale
/// and the copy would fail.
///
/// The staged copy's name carries our PID so concurrent or back-to-back
/// self-uninstalls don't collide on a single fixed path — a still-running or
/// still-locked earlier copy would make `fs::copy` to a shared name fail and
/// abort the cleanup. The copy is left in `%TEMP%` (it can't delete itself);
/// the OS reclaims it.
#[cfg(windows)]
pub fn stage_janitor() -> Result<PathBuf, String> {
    let current = env::current_exe().map_err(|e| format!("locate self: {e}"))?;
    let tmp = env::temp_dir().join(format!("unpin-reap-{}.exe", std::process::id()));
    fs::copy(&current, &tmp).map_err(|e| format!("stage janitor: {e}"))?;
    Ok(tmp)
}

/// Spawn the [`stage_janitor`] copy as a detached `unpin reap --dir <dir>
/// [--file <f>]…` so it can `remove_dir_all` unpin's own repo dir — including
/// the no-longer-running exe — once this process exits. Every path is passed
/// verbatim from the parent's memory as an argument, never re-derived.
#[cfg(windows)]
pub fn spawn_dir_janitor(staged: &Path, dir: &Path, files: &[PathBuf]) -> Result<(), String> {
    use std::process::Command;
    let mut cmd = Command::new(staged);
    cmd.arg("reap").arg("--dir").arg(dir);
    // Tombstones of busy bin links (our own sidelined hardlink) that could
    // only be renamed, not deleted, while this process runs.
    for f in files {
        cmd.arg("--file").arg(f);
    }
    cmd.spawn().map_err(|e| format!("spawn janitor: {e}"))?;
    Ok(())
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
    env::split_paths(&path)
        .any(|p| p == bin || (target.is_some() && fs::canonicalize(&p).ok() == target))
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
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("$HOME is not set")?;
    Ok(unix_profile_for(shell, &home, bin))
}

/// Whether `bin` already appears as a *PATH list entry* in `contents` (a shell
/// profile), as opposed to merely occurring as a substring. So
/// `/home/u/.local/bin` does NOT match `…/bin-old`, `…/binutils`, or a `…/bin/x`
/// subdir. Comment lines (`#…`) are skipped so a passing mention in prose can't
/// suppress a needed edit. Pure (no I/O), so it can be unit-tested.
///
/// `std::env::split_paths` only splits on the list separator (`:`), but profile
/// lines are shell *source*, not bare PATH values — the dir is wrapped in
/// `export PATH="…:$PATH"`, single quotes, or fish's `fish_add_path …`. So we
/// split on the full set of chars that bound a component in those forms (the
/// separator, quotes, `=`, whitespace) and compare each token to `bin` with
/// `Path` equality, which is component-wise: a prefix or subdir can't masquerade
/// as a match, and a trailing slash is normalised away.
#[cfg(unix)]
fn profile_has_path_entry(contents: &str, bin: &Path) -> bool {
    if bin.as_os_str().is_empty() {
        return false;
    }
    contents
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(|l| l.split([':', '"', '\'', '=', ' ', '\t']))
        .filter(|t| !t.is_empty())
        .any(|t| Path::new(t) == bin)
}

#[cfg(unix)]
fn plan_path_change(bin: &Path) -> Result<PathPlan, String> {
    let (profile, line) = unix_target(bin)?;

    // Idempotent: if the profile already lists this bin dir, don't prompt or
    // append a second entry (e.g. the user edited it before, or re-runs setup
    // in a shell that hasn't been reopened yet).
    let existing = fs::read_to_string(&profile).unwrap_or_default();
    if profile_has_path_entry(&existing, bin) {
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
        prompt: format!(
            "{} is not on your PATH. Add it to your user PATH?",
            bin.display()
        ),
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

/// Remove `dir` from the per-user `Path` registry value, if present. The mirror
/// of `apply_path_change` (which only ever adds): the Windows self-uninstall
/// path calls this once the shared bin dir holds no more managed links, so
/// unpin doesn't leave a dangling PATH entry pointing at a gone directory.
/// Returns `Ok(true)` when an entry was actually removed. Unix has no
/// counterpart — we can't reliably re-find the line we appended across shells,
/// so the profile edit is left in place there.
#[cfg(windows)]
pub fn remove_dir_from_user_path(dir: &Path) -> Result<bool, String> {
    use std::process::Command;

    let escaped = dir.display().to_string().replace('\'', "''");
    // `-ne` is case-insensitive in PowerShell, matching NTFS path semantics, so
    // a differently-cased stored entry still matches; splitting on ';' and
    // dropping empties also tidies any stray separators while we're here.
    let script = format!(
        "$b='{escaped}'; \
         $p=[Environment]::GetEnvironmentVariable('Path','User'); \
         if (-not $p) {{ 'absent' }} else {{ \
             $parts = $p -split ';' | Where-Object {{ $_ -ne '' -and $_ -ne $b }}; \
             $new = $parts -join ';'; \
             if ($new -ne $p) {{ \
                 [Environment]::SetEnvironmentVariable('Path', $new, 'User'); 'removed' \
             }} else {{ 'absent' }} \
         }}"
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
    Ok(String::from_utf8_lossy(&out.stdout).trim() == "removed")
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

    #[test]
    fn path_entry_matches_real_list_entries() {
        let bin = Path::new("/home/u/.local/bin");
        // The two lines we ourselves write.
        assert!(profile_has_path_entry(
            "export PATH=\"/home/u/.local/bin:$PATH\"\n",
            bin
        ));
        assert!(profile_has_path_entry(
            "fish_add_path /home/u/.local/bin\n",
            bin
        ));
        // In the middle of a list, both neighbours are separators.
        assert!(profile_has_path_entry(
            "export PATH=\"/opt/x:/home/u/.local/bin:/usr/bin\"\n",
            bin
        ));
        // Single-quoted, and as the last component (end-of-line boundary).
        assert!(profile_has_path_entry(
            "export PATH='/home/u/.local/bin'",
            bin
        ));
        // Path equality normalises a trailing slash away.
        assert!(profile_has_path_entry(
            "export PATH=\"/home/u/.local/bin/:$PATH\"",
            bin
        ));
    }

    #[test]
    fn path_entry_rejects_substring_lookalikes() {
        let bin = Path::new("/home/u/.local/bin");
        // Longer dir that merely shares the prefix.
        assert!(!profile_has_path_entry(
            "export PATH=\"/home/u/.local/bin-old:$PATH\"\n",
            bin
        ));
        assert!(!profile_has_path_entry(
            "export PATH=\"/home/u/.local/binutils:$PATH\"\n",
            bin
        ));
        // A subdir of our bin, not the bin itself.
        assert!(!profile_has_path_entry(
            "export PATH=\"/home/u/.local/bin/extra:$PATH\"\n",
            bin
        ));
        // A bare mention in a comment must not suppress the edit.
        assert!(!profile_has_path_entry(
            "# remember to add /home/u/.local/bin someday\n",
            bin
        ));
        assert!(!profile_has_path_entry("", bin));
    }
}
