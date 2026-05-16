//! Filesystem-level link maintenance for a freshly-extracted vdir.
//!
//! `link_all_executables` is the entry point: it walks the vdir, creates a
//! `bin_dir` link per executable, honors a package's UNPIN_META alias list,
//! and (since the orphan-cleanup fix) wipes leftover links from prior versions
//! the new manifest no longer declares.
//!
//! Helpers (`walk_files`, `is_executable`, `ensure_executable`, etc.) and the
//! path-building functions (`bin_dir`, `data_dir`, `repo_dir`) live in the
//! parent module and come in via `super::`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use indicatif::MultiProgress;

use crate::aliases::{self, AliasMode};
use crate::platform;

use super::prompt::{PromptResult, prompt_yes_no_with_skip};
use super::spec::{CATALOG_OWNER, Spec};
use super::{bin_dir, data_dir, repo_dir};

pub fn walk_files(root: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_dir() {
            walk_files(&path, out)?;
        } else if ft.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Walk a vdir for files that might become PATH entries: top-level files
/// (a single-binary release that puts the binary at the root) and anything
/// inside `bin/` (the canonical location for catalog packages). Skips
/// `share/`, `lib/`, `etc/`, `libexec/` and any other subtree shipped by a
/// runtime-data tarball — those are full of scripts (`.pl`, `.awk`, `.sh`)
/// with +x set that we have no business promoting into the user's PATH.
/// vim's `share/vim/runtime/tools/*.pl` is the concrete case that motivated
/// this restriction.
pub fn walk_binary_candidates(vdir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if let Ok(entries) = fs::read_dir(vdir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                out.push(entry.path());
            }
        }
    }
    let bin = vdir.join("bin");
    if bin.is_dir() {
        walk_files(&bin, out)?;
    }
    Ok(())
}

pub fn is_executable(p: &Path) -> bool {
    platform::is_executable(p)
}

pub fn ensure_executable(p: &Path) -> Result<(), String> {
    platform::ensure_executable(p)
}

/// Strip trailing target-triple markers from a binary filename. Useful when
/// projects ship `tool-x86_64-linux-musl` and we want the link to be `tool`.
/// On Windows the `.exe` suffix is stripped first.
fn short_binary_name(name: &str) -> &str {
    #[cfg(windows)]
    let name = name.strip_suffix(".exe").unwrap_or(name);
    const MARKERS: &[&str] = &[
        "-x86_64", "_x86_64", "-amd64", "_amd64", "-aarch64", "_aarch64", "-arm64", "_arm64",
        "-i686", "_i686", "-i386", "_i386", "-linux", "_linux", "-darwin", "_darwin", "-apple",
        "-windows", "_windows", "-win64", "_win64", "-win32", "_win32", "-mingw", "_mingw",
        "-msvc", "_msvc", "-pc-", "-musl", "-gnu",
    ];
    let mut earliest: Option<usize> = None;
    for m in MARKERS {
        if let Some(i) = name.find(m) {
            earliest = Some(earliest.map_or(i, |e| e.min(i)));
        }
    }
    match earliest {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

fn link_binary(
    multi: &MultiProgress,
    target: &Path,
    link: &Path,
    assume_yes: bool,
) -> Result<bool, String> {
    let parent = link.parent().ok_or("link has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;

    if link.exists() || fs::symlink_metadata(link).is_ok() {
        let managed = platform::read_link(link)
            .map(|t| t.starts_with(data_dir()))
            .unwrap_or(false);
        if !managed && !assume_yes {
            let q = format!(
                "{} already exists and was not installed by unpin. Overwrite?",
                link.display()
            );
            let overwrite = match prompt_yes_no_with_skip(multi, &q) {
                PromptResult::Got(true) => true,
                PromptResult::Got(false) | PromptResult::Skip => false,
            };
            if !overwrite {
                let _ = multi.println(format!(
                    "Skipped {}",
                    link.file_name().unwrap_or_default().to_string_lossy()
                ));
                return Ok(false);
            }
        }
        let _ = fs::remove_file(link);
    }
    platform::create_link(target, link)
        .map_err(|e| format!("link {} -> {}: {e}", link.display(), target.display()))?;
    Ok(true)
}

/// Outcome of `link_all_executables`. Primary names go into the install
/// summary line; alias names get a separate `aliases:` line; notes ride a
/// `note:` line (e.g. when aliases were declared but skipped — non-catalog
/// source, `--no-aliases`, etc).
#[derive(Default)]
pub struct LinkSummary {
    pub primary: Vec<String>,
    pub aliases: Vec<String>,
    pub notes: Vec<String>,
}

pub fn link_all_executables(
    multi: &MultiProgress,
    spec: &Spec,
    vdir: &Path,
    assume_yes: bool,
    alias_mode: AliasMode,
) -> Result<LinkSummary, String> {
    let mut files = Vec::new();
    walk_binary_candidates(vdir, &mut files)
        .map_err(|e| format!("walk {}: {e}", vdir.display()))?;

    let mut executables: Vec<PathBuf> =
        files.iter().filter(|p| is_executable(p)).cloned().collect();
    // If nothing has +x set (rare; some archives lose modes), promote any file
    // matching spec.name so the user still gets a working symlink.
    if executables.is_empty()
        && let Some(p) = files
            .iter()
            .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(&spec.name))
    {
        ensure_executable(p)?;
        executables.push(p.clone());
    }

    let bin = bin_dir();
    let rdir = repo_dir(&spec.owner, &spec.name);

    // Snapshot of unpin-managed links currently pointing anywhere into this
    // package's repo dir. After linking the new version we use this to wipe
    // entries the new version no longer declares — e.g. an alias `lzma` that
    // v1 had and v2 dropped would otherwise keep pointing at v1's binary
    // (and also keep v1's vdir alive past `prune`).
    //
    // On Windows alias hardlinks aren't introspectable by `read_link`; they
    // get a separate cleanup pass below keyed on the binary's UNPIN_META.
    let existing_managed: Vec<PathBuf> = match fs::read_dir(&bin) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                let target = platform::read_link(&p)?;
                target.starts_with(&rdir).then_some(p)
            })
            .collect(),
        Err(_) => Vec::new(),
    };

    let mut summary = LinkSummary::default();
    let mut refreshed: Vec<PathBuf> = Vec::new();
    for target in &executables {
        let basename = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("non-utf8 binary name")?;
        let short = short_binary_name(basename);
        let link = bin.join(platform::link_filename(short));
        if link_binary(multi, target, &link, assume_yes)? {
            refreshed.push(link.clone());
            summary.primary.push(short.to_owned());
        }

        // Aliases scan + create. We attempt this on every primary executable;
        // most packages have one, but a multi-binary release with two
        // alias-bearing primaries would just contribute both lists. The
        // catalog-only gate is enforced inside `link_aliases_for`.
        let alias_outcome = link_aliases_for(multi, target, spec, alias_mode, assume_yes)?;
        for a in &alias_outcome.linked {
            refreshed.push(bin.join(platform::alias_link_filename(a)));
        }
        // Dedup across primaries: two binaries declaring the same alias
        // name would silently overwrite each other in bin_dir (last write
        // wins), and the summary line would show "aliases: lzma lzma".
        // First-seen wins.
        for a in alias_outcome.linked {
            if !summary.aliases.contains(&a) {
                summary.aliases.push(a);
            }
        }
        if let Some(note) = alias_outcome.note {
            summary.notes.push(note);
        }
    }

    // Orphan cleanup: links that pointed into this repo's vdirs before but
    // weren't re-issued by this run are from a previous version's manifest.
    // Removing them keeps `prune` able to reclaim the older vdir later (an
    // orphan alias would otherwise keep the vdir alive indefinitely).
    let mut orphans = Vec::new();
    for old in &existing_managed {
        if !refreshed.iter().any(|r| r == old) && fs::remove_file(old).is_ok() {
            orphans.push(
                old.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }

    // Windows-only: alias hardlinks have no introspectable target so the
    // `existing_managed` scan above didn't see them. Derive the name set
    // from older vdirs' UNPIN_META blocks and remove any name the new
    // version doesn't declare. `aliases_from_vdir` swallows scan errors —
    // a corrupted older binary is a degraded but safe outcome here.
    #[cfg(windows)]
    {
        if let Ok(entries) = fs::read_dir(&rdir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let is_old_vdir =
                    entry.file_type().map(|t| t.is_dir()).unwrap_or(false) && p != vdir;
                if !is_old_vdir {
                    continue;
                }
                for old_alias in aliases_from_vdir(&p) {
                    if summary.aliases.iter().any(|a| a == &old_alias) {
                        continue;
                    }
                    let link_p = bin.join(platform::alias_link_filename(&old_alias));
                    if fs::remove_file(&link_p).is_ok() {
                        orphans.push(old_alias);
                    }
                }
            }
        }
    }

    if !orphans.is_empty() {
        summary.notes.push(format!(
            "removed {} orphan link(s) from previous version: {}",
            orphans.len(),
            orphans.join(", ")
        ));
    }

    Ok(summary)
}

/// Outcome of attempting to install aliases for a single primary binary.
struct AliasOutcome {
    linked: Vec<String>,
    /// One-line note for the install summary when aliases were declared but
    /// skipped (non-catalog source, `--no-aliases`, user said no at prompt).
    note: Option<String>,
}

fn link_aliases_for(
    multi: &MultiProgress,
    primary: &Path,
    spec: &Spec,
    alias_mode: AliasMode,
    assume_yes: bool,
) -> Result<AliasOutcome, String> {
    let meta = match aliases::read_meta(primary)? {
        None => {
            return Ok(AliasOutcome {
                linked: vec![],
                note: None,
            });
        }
        Some(m) if m.aliases.is_empty() => {
            return Ok(AliasOutcome {
                linked: vec![],
                note: None,
            });
        }
        Some(m) => m,
    };

    // Catalog gate: aliases declared by `<owner>/<repo>` packages are *always*
    // ignored regardless of config or CLI flag. The risk is shadowing of
    // commands like `sudo`/`ssh`/`git` from a publisher whose CI we don't
    // audit; honoring aliases there would silently expand the trust surface.
    if spec.owner != CATALOG_OWNER {
        return Ok(AliasOutcome {
            linked: vec![],
            note: Some(format!(
                "{} alias(es) declared but ignored (non-catalog source)",
                meta.aliases.len()
            )),
        });
    }

    // Mode resolution. AliasMode::Ask prompts once for the whole list — N
    // prompts for an N-alias package would just train Y-mashing.
    let install = match alias_mode {
        AliasMode::No => false,
        AliasMode::Yes => true,
        AliasMode::Ask => {
            let q = format!(
                "Install {} alias(es) for {} ({})?",
                meta.aliases.len(),
                spec.repo(),
                meta.aliases.join(", ")
            );
            match prompt_yes_no_with_skip(multi, &q) {
                PromptResult::Got(true) => true,
                PromptResult::Got(false) | PromptResult::Skip => false,
            }
        }
    };
    if !install {
        return Ok(AliasOutcome {
            linked: vec![],
            note: Some(format!("{} alias(es) skipped", meta.aliases.len())),
        });
    }

    if meta.aliases.len() > aliases::MAX_ALIASES {
        return Err(format!(
            "package declares {} aliases (max {})",
            meta.aliases.len(),
            aliases::MAX_ALIASES
        ));
    }

    // Validate every name BEFORE creating any link. If one is bad we want a
    // clean failure, not half a manifest on disk that the user has to clean
    // up by hand. The validator catches blocklisted names (sudo, ssh, ...),
    // path traversal, Windows reserved names, and length/charset violations.
    for name in &meta.aliases {
        aliases::validate_alias(name)?;
    }

    let bin = bin_dir();
    let mut linked = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for name in &meta.aliases {
        let link_path = bin.join(platform::alias_link_filename(name));
        if link_alias(multi, primary, &link_path, assume_yes)? {
            linked.push(name.clone());
        } else {
            // `link_alias` returned Ok(false): user declined an overwrite
            // prompt. Surface this in the summary so the install line
            // isn't a half-truth ("aliases: foo bar" while baz quietly
            // didn't land).
            skipped.push(name.clone());
        }
    }

    // No sidecar manifest written — the binary itself is the authoritative
    // source for which aliases this version declared. `remove`/`prune`
    // re-scan via `aliases_from_vdir` when they need the list.
    let note = if skipped.is_empty() {
        None
    } else {
        Some(format!(
            "{} alias(es) not installed (existing files): {}",
            skipped.len(),
            skipped.join(", ")
        ))
    };
    Ok(AliasOutcome { linked, note })
}

/// Create an alias link at `link`, prompting on collision the same way
/// `link_binary` does. The actual filesystem op (`platform::create_alias_link`)
/// is symlink on Unix and NTFS hardlink on Windows.
fn link_alias(
    multi: &MultiProgress,
    target: &Path,
    link: &Path,
    assume_yes: bool,
) -> Result<bool, String> {
    let parent = link.parent().ok_or("alias link has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;

    if link.exists() || fs::symlink_metadata(link).is_ok() {
        // `read_link` recognizes our own symlinks (Unix) and `.cmd` wrappers
        // (Windows primary-binary path) but NOT NTFS hardlinks — those have
        // no introspectable target. So on Windows an existing alias hardlink
        // looks "unmanaged" and triggers the prompt. That's the safe call:
        // we'd rather pester than silently overwrite a pre-existing file.
        let managed = platform::read_link(link)
            .map(|t| t.starts_with(data_dir()))
            .unwrap_or(false);
        if !managed && !assume_yes {
            let q = format!(
                "{} already exists and was not installed by unpin. Overwrite (alias)?",
                link.display()
            );
            let overwrite = match prompt_yes_no_with_skip(multi, &q) {
                PromptResult::Got(true) => true,
                PromptResult::Got(false) | PromptResult::Skip => false,
            };
            if !overwrite {
                let _ = multi.println(format!(
                    "Skipped alias {}",
                    link.file_name().unwrap_or_default().to_string_lossy()
                ));
                return Ok(false);
            }
        }
        let _ = fs::remove_file(link);
    }
    platform::create_alias_link(target, link)
        .map_err(|e| format!("alias {} -> {}: {e}", link.display(), target.display()))?;
    Ok(true)
}

/// Scan every executable in `vdir` for an embedded UNPIN_META block and
/// return the union of alias names declared. Windows-only: alias entries
/// in `bin_dir` are NTFS hardlinks with no introspectable target, so the
/// only way to learn their names at cleanup time is to re-derive from the
/// binary itself. On Unix, alias entries are symlinks — `read_link` on
/// `bin_dir` covers them directly without any binary I/O.
///
/// Errors during scan are swallowed: a corrupted/missing binary at cleanup
/// time means we just don't clean up some aliases. That's a degraded but
/// safe outcome (the orphan link in bin_dir is the user's recovery hint).
#[cfg(windows)]
pub fn aliases_from_vdir(vdir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    if walk_files(vdir, &mut files).is_err() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    for f in &files {
        if !is_executable(f) {
            continue;
        }
        if let Ok(Some(meta)) = aliases::read_meta(f) {
            for a in meta.aliases {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    }
    out
}

/// Sweep `bin_dir` for symlinks (or `.cmd` wrappers) whose target lives
/// under `root` but no longer exists on disk. Used by `prune` before AND
/// after orphan-vdir removal: the second call catches alias symlinks that
/// just became dangling when their owning vdir was wiped (Unix-only flow;
/// the Windows hardlink path uses `aliases_from_vdir` instead).
pub fn sweep_dangling_links(bin: &Path, root: &Path) -> usize {
    let mut removed = 0usize;
    if let Ok(entries) = fs::read_dir(bin) {
        for entry in entries.flatten() {
            let path = entry.path();
            let target = match platform::read_link(&path) {
                Some(t) => t,
                None => continue,
            };
            if !target.starts_with(root) {
                continue;
            }
            if fs::metadata(&target).is_err() && fs::remove_file(&path).is_ok() {
                println!("Removed dangling {}", path.display());
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name_strips_target_triple_suffix() {
        assert_eq!(short_binary_name("rg-x86_64-linux-musl"), "rg");
        assert_eq!(short_binary_name("tool_x86_64-linux"), "tool");
        assert_eq!(short_binary_name("fd-aarch64-apple-darwin"), "fd");
    }

    #[test]
    fn short_name_strips_pc_marker() {
        assert_eq!(short_binary_name("rg-x86_64-pc-linux-gnu"), "rg");
    }

    #[test]
    fn short_name_keeps_simple_names() {
        assert_eq!(short_binary_name("rg"), "rg");
        assert_eq!(short_binary_name("jq"), "jq");
    }

    #[test]
    fn short_name_strips_exe_on_windows_first() {
        #[cfg(unix)]
        assert_eq!(short_binary_name("rg.exe"), "rg.exe");
        #[cfg(windows)]
        assert_eq!(short_binary_name("rg.exe"), "rg");
        #[cfg(windows)]
        assert_eq!(short_binary_name("rg-x86_64-pc-windows-gnu.exe"), "rg");
    }

    #[test]
    fn short_name_first_marker_wins() {
        assert_eq!(short_binary_name("rg-linux-amd64"), "rg");
    }

    #[test]
    fn walk_binary_candidates_skips_share_subtree() {
        // Regression test for the linker.rs scope fix. vim's data tarball
        // ships scripts under `share/vim/runtime/tools/*.pl` with +x set —
        // those used to be promoted into PATH because the linker walked the
        // whole vdir recursively. The candidate walk now stops at top-level
        // files and the `bin/` subtree.
        let tmp = tempfile::tempdir().unwrap();
        let v = tmp.path();
        fs::create_dir_all(v.join("bin")).unwrap();
        fs::create_dir_all(v.join("share/vim/runtime/tools")).unwrap();
        fs::create_dir_all(v.join("lib")).unwrap();
        fs::write(v.join("top-binary"), b"x").unwrap();
        fs::write(v.join("bin/inner"), b"x").unwrap();
        fs::write(
            v.join("share/vim/runtime/tools/efm_filter.pl"),
            b"#!/usr/bin/perl\n",
        )
        .unwrap();
        fs::write(v.join("lib/libfoo.so"), b"x").unwrap();

        let mut out = Vec::new();
        walk_binary_candidates(v, &mut out).unwrap();
        let names: Vec<String> = out
            .iter()
            .map(|p| p.strip_prefix(v).unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"top-binary".to_string()), "got: {names:?}");
        assert!(names.contains(&"bin/inner".to_string()), "got: {names:?}");
        assert!(
            !names.iter().any(|n| n.contains("share/")),
            "share/ leaked into candidates: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("lib/")),
            "lib/ leaked into candidates: {names:?}"
        );
    }
}
