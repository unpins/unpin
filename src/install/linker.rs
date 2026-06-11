//! Filesystem-level link maintenance for a freshly-extracted vdir.
//!
//! `link_all_executables` is the entry point: it walks the vdir, creates a
//! `bin_dir` link per executable, honors a package's `unpin/aliases` list,
//! and (since the orphan-cleanup fix) wipes leftover links from prior versions
//! the new manifest no longer declares.
//!
//! Helpers (`walk_files`, `is_executable`, `ensure_executable`, etc.) live in
//! the parent module and come in via `super::`; the on-disk layout (`bin`,
//! `data`, `repo_dir`) arrives as a borrowed [`crate::platform::Paths`].

use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use crate::aliases::{self, AliasMode};
use crate::meta;
use crate::platform::{self, Paths};
use crate::progress::Ui;

use super::prompt::PromptResult;
use super::spec::{CATALOG_OWNER, Spec};

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
///
/// Lone-root fallback: most third-party release tarballs nest everything one
/// level down under a single root directory named after the asset
/// (`ripgrep-<ver>-<triple>/rg`, `fd-<ver>-<triple>/fd`). When the vdir itself
/// yields nothing (no top-level file, no populated `bin/`) and contains
/// exactly one sub-directory, we treat that sub-directory as the effective
/// root and apply the *same* top-level+`bin/` rule to it. Descending only one
/// level and reusing the same rule is deliberate: a `share/` (or `lib/`, …)
/// subtree under that root is still never walked, so the vim regression stays
/// fixed. Catalog packages (bare binary or `bin/` at the root) never hit this
/// branch.
pub fn walk_binary_candidates(vdir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    collect_top_and_bin(vdir, out)?;
    if out.is_empty()
        && let Some(root) = sole_subdir(vdir)
    {
        collect_top_and_bin(&root, out)?;
    }
    // `read_dir` yields filesystem order, which varies across machines, file
    // systems and extraction runs. Sort by full path so the candidate list —
    // and therefore both the intra-package first-seen link winner and `run`'s
    // executable selection — is deterministic and reproducible.
    out.sort();
    Ok(())
}

/// Push `dir`'s top-level files and the contents of its `bin/` subtree into
/// `out` — the core "where a PATH-worthy binary can legitimately live" rule,
/// factored out so the lone-root fallback in [`walk_binary_candidates`] can
/// reuse it verbatim one level down.
fn collect_top_and_bin(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                out.push(entry.path());
            }
        }
    }
    let bin = dir.join("bin");
    if bin.is_dir() {
        walk_files(&bin, out)?;
    }
    Ok(())
}

/// If `dir` contains exactly one entry and that entry is a sub-directory,
/// return its path; otherwise `None`. Any top-level file, zero sub-dirs, or a
/// second entry all disqualify it — we only see through an *unambiguous* lone
/// root directory, never guess which of several entries is "the" package dir.
fn sole_subdir(dir: &Path) -> Option<PathBuf> {
    let mut entries = fs::read_dir(dir).ok()?.flatten();
    let first = entries.next()?;
    if entries.next().is_some() {
        return None; // more than one entry
    }
    first.file_type().ok()?.is_dir().then(|| first.path())
}

pub fn is_executable(p: &Path) -> bool {
    platform::is_executable(p)
}

pub fn ensure_executable(p: &Path) -> Result<(), String> {
    platform::ensure_executable(p)
}

/// Reduce a release binary's on-disk filename to the command name to put on
/// PATH: drop the platform triple, then the release version that the common
/// `<name>-<version>-<arch>-<os>` bare-binary asset convention bakes in.
/// `version` is the release tag (a leading `v` is ignored); pass `""` to skip
/// version stripping.
///
/// `htop-3.4.1-1-x86_64-linux` + version `v3.4.1-1` → `htop`.
fn short_binary_name<'a>(name: &'a str, version: &str) -> &'a str {
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
    let base = match earliest {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    };
    // After the triple is gone the version may still trail (`htop-3.4.1-1`).
    // Strip it only when it's exactly the release tag — no semver guessing, so
    // an unrelated trailing number is left alone.
    let version = version.strip_prefix('v').unwrap_or(version);
    if !version.is_empty()
        && let Some(head) = base.strip_suffix(version)
        && let Some(stripped) = head.strip_suffix(['-', '_'])
        && !stripped.is_empty()
    {
        return stripped;
    }
    base
}

/// Outcome of a single link/alias create attempt. `note`, when set, is a
/// one-line summary message (a cross-package shadow, or a collision the run
/// resolved) — distinct from the bar's transient "Skipped X" line.
struct LinkResult {
    linked: bool,
    note: Option<String>,
}

/// What to do with the bin_dir slot at `link`.
enum SlotDecision {
    /// (Over)write it; `note` records a summary line when this shadows another
    /// package's link.
    Write(Option<String>),
    /// Leave the existing entry; `note` explains why (a collision) or is None
    /// (user declined a foreign-file overwrite — already surfaced on the bar).
    Keep(Option<String>),
}

/// Derive `owner/repo` from a managed-link target under `data` (e.g.
/// `<data>/owner/repo/<tag>/bin/x` → `owner/repo`). `None` if the target
/// doesn't have at least the two leading components.
fn link_owner_repo(data: &Path, target: &Path) -> Option<String> {
    let rel = target.strip_prefix(data).ok()?;
    let mut comps = rel.components();
    let owner = comps.next()?.as_os_str().to_string_lossy().into_owned();
    let repo = comps.next()?.as_os_str().to_string_lossy().into_owned();
    Some(format!("{owner}/{repo}"))
}

/// Classify the existing bin_dir entry at `link` for the package rooted at
/// `rdir`, prompting where the policy calls for it. `claimed` holds links this
/// run already created (so a second binary in the same package can't silently
/// clobber the first). All four cases:
///   - free slot / our own older version → silent (over)write;
///   - already claimed this run → keep the first, note the intra-package dup;
///   - owned by another unpin package → cross-package: `-y`/non-TTY lets the
///     explicit install win (with a shadow note), TTY prompts;
///   - foreign unmanaged file → the long-standing overwrite prompt.
fn classify_slot(
    paths: &Paths,
    ui: &Ui,
    rdir: &Path,
    claimed: &[PathBuf],
    link: &Path,
    assume_yes: bool,
) -> SlotDecision {
    let name = link
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    // Intra-package: an earlier binary in THIS run already took this name.
    // First-seen wins so bin/<name> matches what the summary reported.
    if claimed.iter().any(|c| c == link) {
        return SlotDecision::Keep(Some(format!(
            "`{name}` is provided by more than one binary in this package; kept the first"
        )));
    }

    if !(link.exists() || fs::symlink_metadata(link).is_ok()) {
        return SlotDecision::Write(None);
    }

    match platform::read_link(link) {
        // Our own previous version → normal update overwrite, silent.
        Some(t) if t.starts_with(rdir) => SlotDecision::Write(None),
        // Owned by a different unpin package → cross-package collision.
        Some(t) if t.starts_with(&paths.data) => {
            let owner =
                link_owner_repo(&paths.data, &t).unwrap_or_else(|| "another package".into());
            // The user explicitly asked for THIS package, so `-y` and non-TTY
            // let it win (with a shadow note). Interactive TTY gets to choose.
            if assume_yes || !io::stdin().is_terminal() {
                SlotDecision::Write(Some(format!("replaced {owner}'s `{name}`")))
            } else {
                let q = format!(
                    "{} is provided by {owner}. Replace it with this package?",
                    link.display()
                );
                match ui.prompt_yes_no(&q) {
                    PromptResult::Got(true) => {
                        SlotDecision::Write(Some(format!("replaced {owner}'s `{name}`")))
                    }
                    PromptResult::Got(false) | PromptResult::Skip => SlotDecision::Keep(Some(
                        format!("`{name}` kept from {owner} (use --yes to replace)"),
                    )),
                }
            }
        }
        // Foreign file, or a symlink pointing outside unpin.
        _ => {
            if assume_yes {
                return SlotDecision::Write(None);
            }
            let q = format!(
                "{} already exists and was not installed by unpin. Overwrite?",
                link.display()
            );
            match ui.prompt_yes_no(&q) {
                PromptResult::Got(true) => SlotDecision::Write(None),
                PromptResult::Got(false) | PromptResult::Skip => {
                    ui.println(format!("Skipped {name}"));
                    SlotDecision::Keep(None)
                }
            }
        }
    }
}

fn link_binary(
    paths: &Paths,
    ui: &Ui,
    rdir: &Path,
    claimed: &[PathBuf],
    target: &Path,
    link: &Path,
    assume_yes: bool,
) -> Result<LinkResult, String> {
    let parent = link.parent().ok_or("link has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;

    match classify_slot(paths, ui, rdir, claimed, link, assume_yes) {
        SlotDecision::Keep(note) => Ok(LinkResult {
            linked: false,
            note,
        }),
        SlotDecision::Write(note) => {
            if link.exists() || fs::symlink_metadata(link).is_ok() {
                let _ = fs::remove_file(link);
            }
            platform::create_link(target, link)
                .map_err(|e| format!("link {} -> {}: {e}", link.display(), target.display()))?;
            Ok(LinkResult { linked: true, note })
        }
    }
}

/// Outcome of `link_all_executables`. Primary names ride bare after the verb in
/// the install summary line; alias names get a `with alias(es)` clause; notes
/// trail as parenthesized asides (e.g. when aliases were declared but skipped —
/// non-catalog source, `--no-aliases`, etc). See `install_summary_message`.
#[derive(Default)]
pub struct LinkSummary {
    pub primary: Vec<String>,
    pub aliases: Vec<String>,
    pub notes: Vec<String>,
}

pub fn link_all_executables(
    paths: &Paths,
    ui: &Ui,
    spec: &Spec,
    vdir: &Path,
    assume_yes: bool,
    alias_mode: AliasMode,
) -> Result<LinkSummary, String> {
    // Helper verbs — catalog `unpins/unpin-<verb>` packages — are reached only
    // via `unpin <verb>` and must never land on PATH: installing one keeps it
    // resident (offline/fast) without shadowing an OS command of the same bare
    // name. This is the *only* way a helper is treated differently from any
    // other package. See docs/helper-verbs.md. (Foreign `owner/unpin-*` is a
    // normal program and still links.)
    if spec.owner == CATALOG_OWNER && spec.name.starts_with("unpin-") {
        let verb = spec.name.strip_prefix("unpin-").unwrap_or(&spec.name);
        return Ok(LinkSummary {
            notes: vec![format!(
                "`{}` is a helper verb — kept resident, not linked on PATH (run it with `unpin {verb}`)",
                spec.name
            )],
            ..LinkSummary::default()
        });
    }

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

    let bin = &paths.bin;
    let rdir = paths.repo_dir(&spec.owner, &spec.name);

    // A previous update that ran while a linked program was executing may
    // have renamed its busy link aside (Windows can't delete a running
    // image); reclaim any tombstone whose process has since exited.
    #[cfg(windows)]
    platform::sweep_sidelined(bin);

    // Snapshot of unpin-managed links currently pointing anywhere into this
    // package's repo dir — the old version's link set. We remove all of them
    // up front (below), then create the new set, so an interrupted update can
    // never leave a *mix* of old- and new-version links. That matters because
    // `active_version` reports the version of whichever bin/ entry `read_dir`
    // yields first: a half-repointed package would make it non-deterministic.
    // Anything that survives a crash here is now a subset of one version.
    // (`read_link` introspects Windows hardlinks — primaries and aliases —
    // via name enumeration, so one pass covers both platforms.)
    let existing_managed: Vec<PathBuf> = match fs::read_dir(bin) {
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

    // Sweep the old link set before creating the new one (see above). On a
    // clean run this is equivalent to repointing each link in place — the
    // create loop re-issues every name the new version still declares, so the
    // end state is identical; only the crash-time intermediate state differs.
    // Best-effort: a removal failure (e.g. a racing manual `rm`) is harmless,
    // the create loop overwrites whatever remains.
    for old in &existing_managed {
        let _ = fs::remove_file(old);
    }

    let mut summary = LinkSummary::default();
    // The version dir's name is the release tag — used to peel a baked-in
    // version off bare-binary asset names (`htop-3.4.1-1-...` → `htop`).
    let version = vdir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let mut refreshed: Vec<PathBuf> = Vec::new();
    for target in &executables {
        let basename = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("non-utf8 binary name")?;
        let short = short_binary_name(basename, version);
        let link = bin.join(platform::link_filename(short));
        // `refreshed` doubles as the "claimed this run" set — passing it in
        // lets a second binary detect a name an earlier one already took.
        let r = link_binary(paths, ui, &rdir, &refreshed, target, &link, assume_yes)?;
        if r.linked {
            refreshed.push(link.clone());
            summary.primary.push(short.to_owned());
        }
        if let Some(note) = r.note {
            summary.notes.push(note);
        }

        // Aliases scan + create. We attempt this on every primary executable;
        // most packages have one, but a multi-binary release with two
        // alias-bearing primaries would just contribute both lists. The
        // catalog-only gate is enforced inside `link_aliases_for`.
        let alias_outcome = link_aliases_for(
            paths, ui, &rdir, &refreshed, target, spec, alias_mode, assume_yes,
        )?;
        for a in &alias_outcome.linked {
            refreshed.push(bin.join(platform::alias_link_filename(a)));
        }
        // `classify_slot` already kept first-seen on disk (via `refreshed`),
        // so a name can't appear twice here — no extra dedup needed.
        summary.aliases.extend(alias_outcome.linked);
        summary.notes.extend(alias_outcome.notes);
    }

    // Orphan report: links from the old version that the new one didn't
    // re-issue (e.g. an alias `lzma` that v1 had and v2 dropped). They were
    // already physically removed by the pre-link sweep above — this is just
    // the name diff so the user sees the dropped entry in the summary. Their
    // removal is also what lets `clean` reclaim the older vdir later.
    //
    // The diff against `refreshed` (created this run) can't mis-report a name
    // as removed while a file still sits at its path: an `existing_managed`
    // entry points into *this* rdir, so even if the pre-sweep removal failed,
    // classify_slot reads it as our own version and re-Writes it (→ refreshed)
    // rather than taking a declinable prompt. A foreign file the user might
    // decline never pointed into rdir, so it was never in `existing_managed`.
    // Anything left here is genuinely gone. (A concurrent external swap in the
    // sweep→classify window is the only gap, and InstallLock serializes us.)
    let mut orphans = Vec::new();
    for old in &existing_managed {
        if !refreshed.iter().any(|r| r == old) {
            orphans.push(
                old.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
            );
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
#[derive(Default)]
struct AliasOutcome {
    /// Aliases successfully linked this run.
    linked: Vec<String>,
    /// Zero or more one-line summary notes: aliases declared but skipped
    /// (non-catalog source, `--no-aliases`, existing files) or a name that
    /// collided with another binary/package.
    notes: Vec<String>,
}

// Cohesive call: every argument is needed for one alias-linking pass and
// bundling them into a struct would only move the noise. Allow the count.
#[allow(clippy::too_many_arguments)]
fn link_aliases_for(
    paths: &Paths,
    ui: &Ui,
    rdir: &Path,
    claimed: &[PathBuf],
    primary: &Path,
    spec: &Spec,
    alias_mode: AliasMode,
    assume_yes: bool,
) -> Result<AliasOutcome, String> {
    let declared = match meta::read(primary)? {
        None => return Ok(AliasOutcome::default()),
        Some(m) => m.aliases(),
    };
    if declared.is_empty() {
        return Ok(AliasOutcome::default());
    }

    // Catalog gate: aliases declared by `<owner>/<repo>` packages are *always*
    // ignored regardless of config or CLI flag. The risk is shadowing of
    // commands like `sudo`/`ssh`/`git` from a publisher whose CI we don't
    // audit; honoring aliases there would silently expand the trust surface.
    if spec.owner != CATALOG_OWNER {
        return Ok(AliasOutcome {
            notes: vec![format!(
                "{} alias(es) declared but ignored (non-catalog source)",
                declared.len()
            )],
            ..Default::default()
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
                declared.len(),
                spec.display(),
                declared.join(", ")
            );
            match ui.prompt_yes_no(&q) {
                PromptResult::Got(true) => true,
                PromptResult::Got(false) | PromptResult::Skip => false,
            }
        }
    };
    if !install {
        return Ok(AliasOutcome {
            notes: vec![format!("{} alias(es) skipped", declared.len())],
            ..Default::default()
        });
    }

    if declared.len() > aliases::MAX_ALIASES {
        return Err(format!(
            "package declares {} aliases (max {})",
            declared.len(),
            aliases::MAX_ALIASES
        ));
    }

    // Validate every name BEFORE creating any link. If one is bad we want a
    // clean failure, not half a manifest on disk that the user has to clean
    // up by hand. The validator catches path traversal, Windows reserved
    // names, and length/charset violations (credential names like `sudo` are
    // not refused here — they're confirmed per-name below).
    for name in &declared {
        aliases::validate_alias(name)?;
    }

    let mut linked = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    // Foreign-file declines collapse into one summary line; collision notes
    // (cross-package / intra-package) carry their own per-name text.
    let mut declined: Vec<String> = Vec::new();
    // Names skipped because the user declined the credential/privesc prompt.
    let mut sensitive_declined: Vec<String> = Vec::new();
    for name in &declared {
        // Security gate, independent of `alias_mode`: a name that would shadow
        // `sudo`/`ssh`/`gpg`/... gets an explicit per-name confirmation even
        // under the default `yes`, since silent shadowing of those is how a
        // compromised release would harvest credentials. `--yes` auto-confirms
        // (the user opted into non-interactive); a non-tty prompt returns Skip,
        // which we treat as "don't link" — the safe default.
        if aliases::alias_needs_confirmation(name) && !assume_yes {
            let q =
                format!("Alias `{name}` would shadow the system `{name}` command — install it?");
            match ui.prompt_yes_no(&q) {
                PromptResult::Got(true) => {}
                PromptResult::Got(false) | PromptResult::Skip => {
                    sensitive_declined.push(name.clone());
                    continue;
                }
            }
        }
        let r = link_alias(paths, ui, rdir, claimed, primary, name, assume_yes)?;
        if r.linked {
            linked.push(name.clone());
        } else if r.note.is_none() {
            // Bare Ok(false): user declined a foreign-file overwrite. Surface
            // it so the install line isn't a half-truth ("aliases: foo bar"
            // while baz quietly didn't land).
            declined.push(name.clone());
        }
        if let Some(n) = r.note {
            notes.push(n);
        }
    }
    if !sensitive_declined.is_empty() {
        notes.push(format!(
            "{} sensitive alias(es) skipped (declined): {}",
            sensitive_declined.len(),
            sensitive_declined.join(", ")
        ));
    }

    // No sidecar manifest written — the binary itself is the authoritative
    // source for which aliases this version declared. `uninstall`/`clean`
    // introspect the installed links via `read_link` when they need the list.
    if !declined.is_empty() {
        notes.push(format!(
            "{} alias(es) not installed (existing files): {}",
            declined.len(),
            declined.join(", ")
        ));
    }
    Ok(AliasOutcome { linked, notes })
}

/// Create an alias link at `link`, classifying an existing entry the same way
/// `link_binary` does (intra-package dup, our own version, cross-package, or
/// foreign file). The filesystem op (`platform::create_alias_link`) is a
/// symlink on Unix and an NTFS hardlink on Windows; `read_link` introspects
/// both, so all four classifications work on both platforms.
fn link_alias(
    paths: &Paths,
    ui: &Ui,
    rdir: &Path,
    claimed: &[PathBuf],
    target: &Path,
    name: &str,
    assume_yes: bool,
) -> Result<LinkResult, String> {
    let bin = &paths.bin;
    let link = bin.join(platform::alias_link_filename(name));
    fs::create_dir_all(bin).map_err(|e| format!("mkdir {}: {e}", bin.display()))?;

    match classify_slot(paths, ui, rdir, claimed, &link, assume_yes) {
        SlotDecision::Keep(note) => Ok(LinkResult {
            linked: false,
            note,
        }),
        SlotDecision::Write(note) => {
            // The mutation (slot clear + link) goes through `create_alias_link`,
            // which on Unix routes via cap-std confined to `bin` — `name` can't
            // escape it even though `link` itself was built by a plain join.
            platform::create_alias_link(bin, name, target)
                .map_err(|e| format!("alias {} -> {}: {e}", link.display(), target.display()))?;
            Ok(LinkResult { linked: true, note })
        }
    }
}

/// Sweep `bin_dir` for symlinks whose target lives under `root` but no
/// longer exists on disk. Used by `clean` before AND after orphan-vdir
/// removal: the second call catches alias symlinks that just became dangling
/// when their owning vdir was wiped. On Windows this is naturally a no-op:
/// a hardlink keeps its file alive, so `read_link` either resolves to a
/// data-dir name that exists or returns `None` — nothing ever dangles.
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
    fn link_owner_repo_extracts_two_leading_components() {
        let data = Path::new("/d/unpin");
        assert_eq!(
            link_owner_repo(data, Path::new("/d/unpin/me/tool/v1/bin/x")),
            Some("me/tool".to_string())
        );
        // Fewer than two components under data → None.
        assert_eq!(link_owner_repo(data, Path::new("/d/unpin/me")), None);
        // Target not under data → None.
        assert_eq!(link_owner_repo(data, Path::new("/other/x/y")), None);
    }

    #[cfg(unix)]
    #[test]
    fn classify_slot_covers_the_four_cases() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let paths = Paths {
            data: data.clone(),
            bin: bin.clone(),
            config: tmp.path().join("config"),
        };
        let ui = Ui::Plain;
        let rdir = paths.repo_dir("me", "tool");
        let link = bin.join("x");

        // Create a real binary under <owner>/<repo>/v1/bin and return its path.
        let mk_target = |owner: &str, repo: &str| -> PathBuf {
            let vbin = data.join(owner).join(repo).join("v1").join("bin");
            fs::create_dir_all(&vbin).unwrap();
            let t = vbin.join("x");
            fs::write(&t, b"x").unwrap();
            t
        };

        // 1. Free slot → write.
        assert!(matches!(
            classify_slot(&paths, &ui, &rdir, &[], &link, true),
            SlotDecision::Write(None)
        ));

        // 2. Already claimed this run → keep first, with a note.
        assert!(matches!(
            classify_slot(&paths, &ui, &rdir, std::slice::from_ref(&link), &link, true),
            SlotDecision::Keep(Some(_))
        ));

        // 3. Our own previous version → silent overwrite.
        symlink(mk_target("me", "tool"), &link).unwrap();
        assert!(matches!(
            classify_slot(&paths, &ui, &rdir, &[], &link, true),
            SlotDecision::Write(None)
        ));
        fs::remove_file(&link).unwrap();

        // 4. Another package owns it; -y lets the explicit install win + note.
        symlink(mk_target("them", "other"), &link).unwrap();
        match classify_slot(&paths, &ui, &rdir, &[], &link, true) {
            SlotDecision::Write(Some(n)) => assert!(n.contains("them/other"), "note: {n}"),
            d => panic!(
                "expected cross-package Write(Some), got {:?}",
                matches!(d, SlotDecision::Keep(_))
            ),
        }
        fs::remove_file(&link).unwrap();

        // 5. Foreign file; -y overwrites without a shadow note.
        fs::write(&link, b"foreign").unwrap();
        assert!(matches!(
            classify_slot(&paths, &ui, &rdir, &[], &link, true),
            SlotDecision::Write(None)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn update_sweeps_old_links_and_repoints_to_new_version() {
        // End-to-end update via link_all_executables: install v1 (two binaries
        // foo+bar), then v2 which drops bar. After the v2 run every surviving
        // link must point at v2 (no v1 leftover → active_version stays
        // deterministic), and the dropped `bar` must be gone.

        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let paths = Paths {
            data: data.clone(),
            bin: bin.clone(),
            config: tmp.path().join("config"),
        };
        let ui = Ui::Plain;
        let spec = Spec {
            owner: "me".into(),
            name: "tool".into(),
            version: None,
        };

        // Lay down a version dir with the given executable basenames under
        // <data>/me/tool/<tag>/bin and return the vdir path.
        let mk_vdir = |tag: &str, names: &[&str]| -> PathBuf {
            let vdir = paths.version_dir("me", "tool", tag);
            let vbin = vdir.join("bin");
            fs::create_dir_all(&vbin).unwrap();
            for n in names {
                let p = vbin.join(n);
                fs::write(&p, b"#!/bin/sh\n").unwrap();
                ensure_executable(&p).unwrap();
            }
            vdir
        };

        let v1 = mk_vdir("v1", &["foo", "bar"]);
        link_all_executables(&paths, &ui, &spec, &v1, true, AliasMode::No).unwrap();
        assert!(bin.join("foo").exists() && bin.join("bar").exists());
        assert!(
            platform::read_link(&bin.join("foo"))
                .unwrap()
                .starts_with(&v1)
        );

        let v2 = mk_vdir("v2", &["foo"]);
        let summary = link_all_executables(&paths, &ui, &spec, &v2, true, AliasMode::No).unwrap();

        // foo repointed to v2, no v1 link survives, bar (dropped) removed.
        let foo_target = platform::read_link(&bin.join("foo")).unwrap();
        assert!(
            foo_target.starts_with(&v2),
            "foo still points at: {foo_target:?}"
        );
        assert!(!bin.join("bar").exists(), "dropped bar should be gone");
        assert!(summary.primary.contains(&"foo".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn catalog_helper_verb_is_kept_resident_not_linked() {
        // A catalog `unpins/unpin-<verb>` package installs (the vdir stays) but
        // never lands on PATH — that is the whole "doesn't shadow an OS command
        // of the same bare name" guarantee. A foreign `owner/unpin-*` is a normal
        // program and links. (`search` stands in for a future package-verb; the
        // doc verbs man/readme are builtins and never come through here.)
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let paths = Paths {
            data: tmp.path().join("data"),
            bin: bin.clone(),
            config: tmp.path().join("config"),
        };
        let ui = Ui::Plain;

        let mk_vdir = |owner: &str, name: &str| -> PathBuf {
            let vdir = paths.version_dir(owner, name, "v1");
            let vbin = vdir.join("bin");
            fs::create_dir_all(&vbin).unwrap();
            let p = vbin.join("search");
            fs::write(&p, b"#!/bin/sh\n").unwrap();
            ensure_executable(&p).unwrap();
            vdir
        };

        // Catalog helper verb → no PATH link, an explanatory note instead.
        let verb = Spec {
            owner: CATALOG_OWNER.into(),
            name: "unpin-search".into(),
            version: None,
        };
        let vdir = mk_vdir(CATALOG_OWNER, "unpin-search");
        let summary = link_all_executables(&paths, &ui, &verb, &vdir, true, AliasMode::No).unwrap();
        assert!(
            !bin.join("search").exists(),
            "helper verb must not link on PATH"
        );
        assert!(summary.primary.is_empty());
        assert_eq!(summary.notes.len(), 1);
        assert!(
            summary.notes[0].contains("helper verb") && summary.notes[0].contains("unpin search"),
            "note: {}",
            summary.notes[0]
        );

        // Same `unpin-`prefixed name under a foreign owner is a normal program.
        let foreign = Spec {
            owner: "someone".into(),
            name: "unpin-search".into(),
            version: None,
        };
        let fvdir = mk_vdir("someone", "unpin-search");
        link_all_executables(&paths, &ui, &foreign, &fvdir, true, AliasMode::No).unwrap();
        assert!(
            bin.join("search").exists(),
            "foreign unpin-* should link normally"
        );
    }

    #[cfg(unix)]
    #[test]
    fn aliases_gate_credential_names_behind_confirmation() {
        use std::io::Write as _;

        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let paths = Paths {
            data,
            bin: bin.clone(),
            config: tmp.path().join("config"),
        };
        let spec = Spec {
            owner: CATALOG_OWNER.into(),
            name: "tool".into(),
            version: None,
        };
        let rdir = paths.repo_dir(CATALOG_OWNER, "tool");

        // A primary binary carrying an embedded `unpin/aliases` listing one
        // credential name (gated) and one ordinary applet (ungated).
        let vbin = paths.version_dir(CATALOG_OWNER, "tool", "v1").join("bin");
        fs::create_dir_all(&vbin).unwrap();
        let primary = vbin.join("tool");
        let mut bytes = b"\x7fELF not-really-an-elf ".to_vec();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zw.start_file("unpin/aliases", opts).unwrap();
            zw.write_all(b"sudo\nxzcat\n").unwrap();
            bytes.extend_from_slice(&zw.finish().unwrap().into_inner());
        }
        fs::write(&primary, &bytes).unwrap();
        ensure_executable(&primary).unwrap();
        assert_eq!(
            meta::read(&primary).unwrap().unwrap().aliases(),
            vec!["sudo".to_string(), "xzcat".to_string()]
        );

        // `--yes` auto-confirms the gate: both names link.
        let out = link_aliases_for(
            &paths,
            &Ui::Plain,
            &rdir,
            &[],
            &primary,
            &spec,
            AliasMode::Yes,
            true,
        )
        .unwrap();
        assert!(out.linked.contains(&"sudo".to_string()));
        assert!(out.linked.contains(&"xzcat".to_string()));
        assert!(bin.join("sudo").exists() && bin.join("xzcat").exists());

        fs::remove_file(bin.join("sudo")).unwrap();
        fs::remove_file(bin.join("xzcat")).unwrap();

        // Without `--yes` and with no tty, the credential prompt resolves to
        // Skip: `sudo` is withheld, the ordinary `xzcat` still links.
        let out = link_aliases_for(
            &paths,
            &Ui::Plain,
            &rdir,
            &[],
            &primary,
            &spec,
            AliasMode::Yes,
            false,
        )
        .unwrap();
        assert!(
            !out.linked.contains(&"sudo".to_string()),
            "sudo must be gated behind confirmation"
        );
        assert!(out.linked.contains(&"xzcat".to_string()));
        assert!(!bin.join("sudo").exists(), "sudo link must not be created");
        assert!(bin.join("xzcat").exists());
    }

    #[test]
    fn short_name_strips_target_triple_suffix() {
        assert_eq!(short_binary_name("rg-x86_64-linux-musl", ""), "rg");
        assert_eq!(short_binary_name("tool_x86_64-linux", ""), "tool");
        assert_eq!(short_binary_name("fd-aarch64-apple-darwin", ""), "fd");
    }

    #[test]
    fn short_name_strips_pc_marker() {
        assert_eq!(short_binary_name("rg-x86_64-pc-linux-gnu", ""), "rg");
    }

    #[test]
    fn short_name_keeps_simple_names() {
        assert_eq!(short_binary_name("rg", ""), "rg");
        assert_eq!(short_binary_name("jq", ""), "jq");
    }

    #[test]
    fn short_name_strips_exe_on_windows_first() {
        #[cfg(unix)]
        assert_eq!(short_binary_name("rg.exe", ""), "rg.exe");
        #[cfg(windows)]
        assert_eq!(short_binary_name("rg.exe", ""), "rg");
        #[cfg(windows)]
        assert_eq!(short_binary_name("rg-x86_64-pc-windows-gnu.exe", ""), "rg");
    }

    #[test]
    fn short_name_first_marker_wins() {
        assert_eq!(short_binary_name("rg-linux-amd64", ""), "rg");
    }

    #[test]
    fn short_name_strips_release_version_after_triple() {
        // Bare-binary assets bake the version in: <name>-<version>-<arch>-<os>.
        assert_eq!(
            short_binary_name("htop-3.4.1-1-x86_64-linux", "v3.4.1-1"),
            "htop"
        );
        // The leading `v` on the tag is optional.
        assert_eq!(
            short_binary_name("htop-3.4.1-1-x86_64-linux", "3.4.1-1"),
            "htop"
        );
        // Only the exact tag is stripped — an unrelated trailing number stays.
        assert_eq!(
            short_binary_name("tool-1.2-x86_64-linux", "9.9"),
            "tool-1.2"
        );
        // No version embedded (tarball ships `bin/htop`) → unchanged.
        assert_eq!(short_binary_name("htop", "3.4.1-1"), "htop");
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

    #[test]
    fn walk_binary_candidates_returns_sorted_paths() {
        // The candidate list feeds both the intra-package first-seen link
        // winner and `run`'s executable pick — it must not depend on the
        // filesystem's read_dir order. Create files in non-sorted name order
        // and assert the output comes back sorted by full path.
        let tmp = tempfile::tempdir().unwrap();
        let v = tmp.path();
        fs::create_dir_all(v.join("bin")).unwrap();
        for name in ["zebra", "alpha", "mike"] {
            fs::write(v.join(name), b"x").unwrap();
        }
        for name in ["yak", "bravo"] {
            fs::write(v.join("bin").join(name), b"x").unwrap();
        }

        let mut out = Vec::new();
        walk_binary_candidates(v, &mut out).unwrap();
        let mut expected = out.clone();
        expected.sort();
        assert_eq!(out, expected, "candidate list is not sorted: {out:?}");
    }

    /// Relative candidate names (slash-normalized) for assertions.
    fn candidate_names(vdir: &Path, out: &[PathBuf]) -> Vec<String> {
        out.iter()
            .map(|p| {
                p.strip_prefix(vdir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn walk_descends_into_lone_root_dir() {
        // The third-party tarball layout (ripgrep/fd/eza/…): everything nested
        // under a single root directory named after the asset. With no
        // top-level file and no bin/, the walk must see through that lone root
        // and surface the binary — the bug this fixes left it empty.
        let tmp = tempfile::tempdir().unwrap();
        let v = tmp.path();
        let root = v.join("ripgrep-15.1.0-x86_64-unknown-linux-musl");
        fs::create_dir_all(root.join("complete")).unwrap();
        fs::write(root.join("rg"), b"x").unwrap();
        fs::write(root.join("README.md"), b"x").unwrap();
        fs::write(root.join("complete/_rg"), b"x").unwrap(); // a subtree, off-limits

        let mut out = Vec::new();
        walk_binary_candidates(v, &mut out).unwrap();
        let names = candidate_names(v, &out);
        assert!(
            names.iter().any(|n| n.ends_with("/rg")),
            "nested binary not found: {names:?}"
        );
        // A subtree *under* the lone root stays off-limits (same rule, one
        // level down) — `complete/_rg` must never become a PATH candidate.
        assert!(
            !names.iter().any(|n| n.contains("complete")),
            "subtree under lone root leaked: {names:?}"
        );
    }

    #[test]
    fn walk_lone_root_still_excludes_share_subtree() {
        // The vim regression must hold one level down too: a lone root holding
        // bin/ + share/ exposes the bin/ binary but never the +x scripts under
        // share/ (the original `efm_filter.pl` case).
        let tmp = tempfile::tempdir().unwrap();
        let v = tmp.path();
        let root = v.join("vim-9.2.0-x86_64-linux");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("share/vim/runtime/tools")).unwrap();
        fs::write(root.join("bin/vim"), b"x").unwrap();
        fs::write(
            root.join("share/vim/runtime/tools/efm_filter.pl"),
            b"#!/usr/bin/perl\n",
        )
        .unwrap();

        let mut out = Vec::new();
        walk_binary_candidates(v, &mut out).unwrap();
        let names = candidate_names(v, &out);
        assert!(
            names.iter().any(|n| n.ends_with("bin/vim")),
            "bin/ binary under lone root not found: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("share")),
            "share/ subtree leaked from under lone root: {names:?}"
        );
    }

    #[test]
    fn walk_does_not_descend_when_a_top_level_file_exists() {
        // A top-level file already makes the vdir a valid candidate source, so
        // the lone-root fallback must NOT fire and start fishing in a sibling
        // directory.
        let tmp = tempfile::tempdir().unwrap();
        let v = tmp.path();
        fs::write(v.join("rg"), b"x").unwrap();
        fs::create_dir_all(v.join("extras")).unwrap();
        fs::write(v.join("extras/helper"), b"x").unwrap();

        let mut out = Vec::new();
        walk_binary_candidates(v, &mut out).unwrap();
        assert_eq!(candidate_names(v, &out), vec!["rg".to_string()]);
    }

    #[test]
    fn walk_does_not_descend_with_multiple_subdirs() {
        // Two sub-dirs and no top-level file is ambiguous; refuse to guess
        // which one is "the" package root rather than promote the wrong binary.
        let tmp = tempfile::tempdir().unwrap();
        let v = tmp.path();
        fs::create_dir_all(v.join("a")).unwrap();
        fs::create_dir_all(v.join("b")).unwrap();
        fs::write(v.join("a/x"), b"x").unwrap();

        let mut out = Vec::new();
        walk_binary_candidates(v, &mut out).unwrap();
        assert!(
            out.is_empty(),
            "must not descend into ambiguous layout: {out:?}"
        );
    }

    #[test]
    fn sole_subdir_only_matches_a_single_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let v = tmp.path();
        assert!(sole_subdir(v).is_none(), "empty dir → None");
        fs::create_dir_all(v.join("root")).unwrap();
        assert_eq!(sole_subdir(v), Some(v.join("root")), "one sub-dir → Some");
        // A second top-level entry (even a file) disqualifies it.
        fs::write(v.join("LICENSE"), b"x").unwrap();
        assert!(sole_subdir(v).is_none(), "dir + file → None");
    }
}
