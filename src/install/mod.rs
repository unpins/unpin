use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use crate::ctx::Ctx;
use crate::github::{self, ByteSink, Release};
use crate::platform::{self, Paths};
use crate::progress::{self, Ui};

mod asset;
mod job;
mod linker;
mod pipeline;
pub(crate) mod prompt;
mod spec;

use asset::pick_asset;
use job::{PipelineMode, PipelineRequest};
#[cfg(windows)]
use linker::aliases_from_vdir;
use linker::{
    ensure_executable, is_executable, link_all_executables, sweep_dangling_links,
    walk_binary_candidates,
};
pub use pipeline::InstallOptions;
use pipeline::{do_extract, finalize_primary_row, preflight_extract, run_pipeline_v2};
use prompt::{PromptResult, plain_pick};
use spec::validate_path_component;
pub use spec::{Spec, parse_spec};

/// Sibling-staging dirs created by the extract pipeline (`<tag>.part`)
/// live alongside real version dirs in `repo_dir/`. Reads that enumerate
/// installed versions for the user (list/info/prune/remove) need to skip
/// them — otherwise a half-finished extract or a SIGKILL'd run shows up
/// as a phantom version named e.g. `v0.1.0.part`. The string check has
/// to match what `pipeline::part_dir_for` produces (just appends `.part`).
fn is_part_dir_name(name: &str) -> bool {
    name.ends_with(".part")
}

/// Keep the first occurrence of each `same`-class in `items`, preserving
/// input order. Shared by every multi-arg subcommand (install/update/info/
/// remove) so they handle `cmd foo foo` (or `cmd tree unpins/tree`)
/// uniformly: the pipeline runs once per unique target instead of racing
/// on the same vdir or printing the same info block twice.
///
/// Linear `O(N²)` scan: argv lengths stay in the single digits in
/// practice, and avoiding a `Hash`/`Eq` bound lets callers compare by
/// whatever projection is natural (parsed `Spec`, resolved
/// `(owner, repo)`, raw string).
/// Dedup a list, keeping the first occurrence and preserving order, emitting a
/// stderr note for each dropped duplicate — so a user who named the same target
/// twice, or two ways (e.g. `tree` and `unpins/tree`), isn't left wondering why
/// one arg vanished. `same` decides equality; `label` renders an item for the
/// message. All the argv-consuming commands (install/remove/update/info) route
/// their dedup through here so the collapse is never silent.
fn dedup_keep_first_noting<T>(
    items: Vec<T>,
    mut same: impl FnMut(&T, &T) -> bool,
    label: impl Fn(&T) -> String,
) -> Vec<T> {
    let mut out: Vec<T> = Vec::with_capacity(items.len());
    for it in items {
        if let Some(kept) = out.iter().find(|prev| same(prev, &it)) {
            let (dup, kept) = (label(&it), label(kept));
            // When both render identically (exact-string dup) the "same as"
            // clause would be noise; only show it when the two args differ.
            if dup == kept {
                eprintln!("note: ignoring duplicate '{dup}'");
            } else {
                eprintln!("note: ignoring duplicate '{dup}' (same as '{kept}')");
            }
        } else {
            out.push(it);
        }
    }
    out
}

/// Search the data dir for a repo matching `name`. Accepts "owner/repo" or a
/// bare repo name (searches all owners; ambiguous match is an error).
fn resolve_installed(paths: &Paths, name: &str) -> Result<Option<(String, String)>, String> {
    if let Some((owner, repo)) = name.split_once('/') {
        if !owner.is_empty() && !repo.is_empty() && !repo.contains('/') {
            return Ok(if paths.repo_dir(owner, repo).is_dir() {
                Some((owner.to_owned(), repo.to_owned()))
            } else {
                None
            });
        }
        return Err(format!("invalid name: `{name}`"));
    }
    let root = &paths.data;
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    let mut found: Option<(String, String)> = None;
    for owner_entry in entries.flatten() {
        if !owner_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let owner = owner_entry.file_name().to_string_lossy().into_owned();
        let owner_path = owner_entry.path();
        let repos = match fs::read_dir(&owner_path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for repo_entry in repos.flatten() {
            if !repo_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let repo = repo_entry.file_name().to_string_lossy().into_owned();
            if repo != name {
                continue;
            }
            if found.is_some() {
                return Err(format!("ambiguous name `{name}` (matches multiple owners)"));
            }
            found = Some((owner.clone(), repo));
        }
    }
    Ok(found)
}

/// Return the version of `owner/name` currently linked from `bin_dir`, or
/// `None` if no link points into this repo's data dir. "Active" == "in PATH".
///
/// Earlier versions had a lex-max fallback when no link was found, but lex
/// ordering trips on common tags (`v1.10.0` < `v1.9.0`), giving wrong answers
/// in `info` ("Active: v1.9.0" when nothing is linked) and `update` (wrong
/// "from" in the `from -> to` line). Returning `None` is honest and the
/// pipeline handles it fine: `preflight_resolve` sees the cached vdir and
/// skips the download, so `update` just re-links without re-downloading.
///
/// This returns the version of the *first* matching bin/ link in `read_dir`
/// order, which is only well-defined because all of a package's links always
/// point at a single version: `link_all_executables` sweeps the old link set
/// before creating the new one, so even an interrupted update leaves a subset
/// of one version, never a mix. Don't reintroduce in-place repointing without
/// also making this resolve a dominant version.
pub(super) fn active_version(paths: &Paths, owner: &str, name: &str) -> Option<String> {
    let rdir = paths.repo_dir(owner, name);
    let bins = fs::read_dir(&paths.bin).ok()?;
    for entry in bins.flatten() {
        if let Some(target) = platform::read_link(&entry.path())
            && let Ok(rel) = target.strip_prefix(&rdir)
            && let Some(first) = rel.components().next()
        {
            let v = first.as_os_str().to_string_lossy().into_owned();
            if paths.version_dir(owner, name, &v).is_dir() {
                return Some(v);
            }
        }
    }
    None
}

/// Resolve an installed package name (`owner/repo` or bare) to the binary
/// paths of its active version, primary first (file stem == repo). `unpin man`
/// uses this to find the binary carrying the embedded `unpin/man/*` pages.
pub(crate) fn installed_binaries(
    paths: &Paths,
    name: &str,
) -> Result<Vec<std::path::PathBuf>, String> {
    let (owner, repo) =
        resolve_installed(paths, name)?.ok_or_else(|| format!("`{name}` is not installed"))?;
    let version = active_version(paths, &owner, &repo)
        .ok_or_else(|| format!("`{name}` has no linked version (try `unpin install {name}`)"))?;
    let vdir = paths.version_dir(&owner, &repo, &version);
    let mut cands = Vec::new();
    linker::walk_binary_candidates(&vdir, &mut cands)
        .map_err(|e| format!("scan {}: {e}", vdir.display()))?;
    // The man blob lives in the primary binary; sort name-match first so the
    // reader hits it before any helper binaries.
    cands.sort_by_key(|p| {
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_owned();
        (stem != repo, stem)
    });
    Ok(cands)
}

pub(super) fn prompt_yes_no(question: &str) -> bool {
    if !io::stdin().is_terminal() {
        return false;
    }
    eprint!("{question} [y/N] ");
    io::stderr().flush().ok();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim_start().chars().next(), Some('y' | 'Y'))
}

/// Cross-process advisory lock at `<repo_dir>/.unpin.lock`. Wraps
/// [`platform::InstallLock`] to integrate with the sigint cleanup hook —
/// holding this guard guarantees the lock file is removed on normal Drop,
/// process panic, *and* SIGINT (ctrl-c).
///
/// Hold this for the smallest window that fully covers the destructive
/// operation: pipeline.rs holds one from preflight through linking; prune
/// and uninstall_one each grab one for the duration of their `remove_dir_all`
/// pass. Reads (info, list) deliberately skip the lock — they tolerate the
/// occasional racy result instead of paying for serialization.
///
/// The underlying primitive is `File::try_lock` (stable since Rust 1.89),
/// not a sentinel-file dance: the kernel owns the lock state and releases
/// it on fd close, including SIGKILL/panic-abort/power-loss. The sentinel
/// file path is still cosmetic so a user finding `.unpin.lock` knows what
/// it is.
pub(super) struct RepoLock {
    inner: platform::InstallLock,
}

impl RepoLock {
    pub(super) fn acquire(repo_dir: &Path) -> Result<Self, String> {
        let inner = platform::acquire_install_lock(repo_dir)?;
        crate::sigint::push_cleanup(inner.path());
        Ok(Self { inner })
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        crate::sigint::pop_cleanup(self.inner.path());
        // platform::InstallLock::drop runs next and removes the file.
    }
}

pub(super) fn fetch_release(ctx: &Ctx, spec: &Spec) -> Result<Release, String> {
    let repo = spec.repo();
    let release = match &spec.version {
        Some(tag) => github::fetch_tag(ctx, &repo, tag)?,
        None => github::fetch_latest(ctx, &repo)?,
    };
    // tag_name is published by the upstream repo and goes straight into a
    // filesystem path via `version_dir`. A malicious release with a tag like
    // `../../tmp/x` would otherwise let the upstream escape `data_dir/`.
    validate_path_component(&release.tag_name, "tag from upstream release")?;
    Ok(release)
}

pub fn install_many(ctx: &Ctx, opts: &InstallOptions, inputs: &[String]) -> Result<(), String> {
    let parsed: Vec<(String, Spec)> = inputs
        .iter()
        .map(|s| parse_spec(s).map(|sp| (s.clone(), sp)))
        .collect::<Result<_, _>>()?;
    // Dedup by parsed Spec so `install tree unpins/tree` collapses — both
    // normalize to the same target and a parallel run would otherwise race
    // on the same vdir. The noting variant tells the user when an arg was
    // folded in, so the collapse isn't silent.
    let specs = dedup_keep_first_noting(parsed, |a, b| a.1 == b.1, |(label, _)| label.clone());
    // Same `(owner, name)` with different `version` survives the Spec
    // equality dedup but can't all install — bin/ symlinks point to a
    // single version. Resolve to one entry per repo (prompt or `--yes`
    // takes the last). Done before any pipeline work so no bar UX has
    // to deal with the conflict.
    let specs = resolve_argv_version_collisions(specs, opts.assume_yes)?;
    let requests: Vec<PipelineRequest> = specs
        .into_iter()
        .map(|(label, spec)| PipelineRequest { label, spec })
        .collect();
    run_pipeline_v2(ctx, opts, PipelineMode::Install, requests, Vec::new())
}

/// When argv specifies the same `owner/repo` multiple times with different
/// `@version` tags, the bin-dir symlink layout can only point to one of
/// them. Group by `(owner, name)`; for each group of 2+ entries, either
/// prompt the user to pick one (TTY) or — under `--yes` — keep the last
/// entry in input order, matching the user contract "instala o último".
///
/// Honors the same "prompt nunca falha" contract as the rest of the
/// pipeline: invalid input retries, `s` (or EOF / non-TTY) skips the whole
/// colliding group as non-fatal. No live bars are active at this point, so the
/// prompt goes straight to the plain picker.
fn resolve_argv_version_collisions(
    parsed: Vec<(String, Spec)>,
    assume_yes: bool,
) -> Result<Vec<(String, Spec)>, String> {
    // Group indices by (owner, name). Small N — linear scan is fine.
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, (_, spec)) in parsed.iter().enumerate() {
        let pos = groups.iter().position(|g| {
            let head = &parsed[g[0]].1;
            head.owner == spec.owner && head.name == spec.name
        });
        match pos {
            Some(p) => groups[p].push(i),
            None => groups.push(vec![i]),
        }
    }
    let mut keep = vec![true; parsed.len()];
    for group in &groups {
        if group.len() < 2 {
            continue;
        }
        let head = &parsed[group[0]].1;
        let owner = &head.owner;
        let name = &head.name;
        let winner: Option<usize> = if assume_yes {
            let chosen = *group.last().unwrap();
            eprintln!(
                "warning: {owner}/{name} specified with {} different versions; installing {} (last specified)",
                group.len(),
                parsed[chosen].0
            );
            Some(chosen)
        } else {
            let header = format!(
                "{owner}/{name} specified with {} different versions:",
                group.len()
            );
            let items: Vec<String> = group.iter().map(|&i| parsed[i].0.clone()).collect();
            match plain_pick(&header, &items) {
                PromptResult::Got(n) => Some(group[n]),
                // Skip drops the entire conflicting group from the run.
                // Non-fatal: other packages in the argv list keep going.
                PromptResult::Skip => None,
            }
        };
        for &i in group {
            if Some(i) != winner {
                keep[i] = false;
            }
        }
    }
    Ok(parsed
        .into_iter()
        .enumerate()
        .filter_map(|(i, x)| keep[i].then_some(x))
        .collect())
}

pub fn list(paths: &Paths) -> Result<(), String> {
    let root = &paths.data;
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => {
            println!("No packages installed");
            return Ok(());
        }
    };
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for owner_entry in entries.flatten() {
        if !owner_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let owner = owner_entry.file_name().to_string_lossy().into_owned();
        let repos = match fs::read_dir(owner_entry.path()) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for repo_entry in repos.flatten() {
            if !repo_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let repo = repo_entry.file_name().to_string_lossy().into_owned();
            let versions = match fs::read_dir(repo_entry.path()) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for ver_entry in versions.flatten() {
                if !ver_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let v = ver_entry.file_name().to_string_lossy().into_owned();
                if is_part_dir_name(&v) {
                    continue;
                }
                rows.push((owner.clone(), repo.clone(), v));
            }
        }
    }
    if rows.is_empty() {
        println!("No packages installed");
        return Ok(());
    }
    rows.sort();

    let linked_targets: Vec<PathBuf> = fs::read_dir(&paths.bin)
        .map(|it| {
            it.flatten()
                .filter_map(|e| platform::read_link(&e.path()))
                .collect()
        })
        .unwrap_or_default();

    let repo_w = rows
        .iter()
        .map(|(o, r, _)| o.len() + 1 + r.len())
        .max()
        .unwrap_or(0);
    let ver_w = rows.iter().map(|(_, _, v)| v.len()).max().unwrap_or(0);
    for (owner, repo, v) in &rows {
        let full = format!("{owner}/{repo}");
        let vdir = paths.version_dir(owner, repo, v);
        let cached = !linked_targets.iter().any(|t| t.starts_with(&vdir));
        let suffix = if cached { "  (cached)" } else { "" };
        println!(
            "{full:<repo_w$}  {v:<ver_w$}{suffix}",
            repo_w = repo_w,
            ver_w = ver_w
        );
    }
    Ok(())
}

/// The package spec for unpin itself. Self-install registers the running
/// binary under this, so `update`/`list`/`uninstall` then treat unpin like any
/// other package. The release tag is always `v` + the crate version, so the
/// locally bootstrapped version dir lines up with what `update` fetches.
pub fn self_spec() -> Spec {
    Spec {
        owner: spec::CATALOG_OWNER.to_owned(),
        name: "unpin".to_owned(),
        version: Some(format!("v{}", env!("CARGO_PKG_VERSION"))),
    }
}

/// Link an already-populated version dir as `spec`'s active version, taking the
/// same repo→links locks the install pipeline uses. The self-install bootstrap
/// calls this after dropping unpin's own binary into `vdir` — there's no
/// download/extract, just the linking half of a normal install. unpin declares
/// no aliases, so alias handling is off.
pub fn link_installed(
    paths: &Paths,
    spec: &Spec,
    vdir: &Path,
    assume_yes: bool,
) -> Result<(), String> {
    let _repo = RepoLock::acquire(&paths.repo_dir(&spec.owner, &spec.name))?;
    let _links = platform::acquire_links_lock(&paths.data, || {})?;
    link_all_executables(
        paths,
        &Ui::Plain,
        spec,
        vdir,
        assume_yes,
        crate::aliases::AliasMode::No,
    )?;
    Ok(())
}

pub fn uninstall_many(paths: &Paths, names: &[String], assume_yes: bool) -> Result<(), String> {
    let targets: Vec<String> = if names.is_empty() {
        let all = installed_repos(paths);
        if all.is_empty() {
            println!("No packages installed");
            return Ok(());
        }
        // unpin self-installs as a managed package, so a bare `uninstall`
        // sweeps it up with everything else — and that's the surprising bit:
        // the command the user is running disappears. Call it out inline and
        // in a dedicated warning so the confirmation isn't a blind "all".
        let me = self_spec();
        let is_self = |o: &str, r: &str| me.owner == o && me.name == r;
        let includes_self = all.iter().any(|(o, r)| is_self(o, r));
        println!(
            "This will uninstall all {} installed package(s):",
            all.len()
        );
        for (owner, repo) in &all {
            let mark = if is_self(owner, repo) {
                "  (unpin itself)"
            } else {
                ""
            };
            println!("  {owner}/{repo}{mark}");
        }
        if includes_self {
            println!("This includes unpin itself — the `unpin` command will be removed.");
        }
        let question = if includes_self {
            "Continue? This will remove unpin itself."
        } else {
            "Continue?"
        };
        if !assume_yes && !prompt_yes_no(question) {
            return Err("aborted".into());
        }
        all.into_iter().map(|(o, r)| format!("{o}/{r}")).collect()
    } else {
        // Raw-string dedup so `uninstall tree tree` doesn't try to remove the
        // package twice (second call would error "not installed" since the
        // first already wiped it — non-fatal but ugly output). Note the
        // dropped dup so the user knows one of their args was folded in.
        dedup_keep_first_noting(names.to_vec(), |a, b| a == b, |s| s.clone())
    };

    let mut failures = 0usize;
    for name in &targets {
        if let Err(e) = uninstall_one(paths, name) {
            eprintln!("unpin: {name}: {e}");
            failures += 1;
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(format!("{failures} uninstall(s) failed"))
    }
}

fn uninstall_one(paths: &Paths, name: &str) -> Result<(), String> {
    let (owner, repo) = resolve_installed(paths, name)?.ok_or("not installed")?;
    let rdir = paths.repo_dir(&owner, &repo);

    // Same lock the install pipeline takes. Without it a concurrent
    // `unpin install` extracting into rdir would race against this
    // `remove_dir_all` and end up either rolled-back-to-empty or
    // confused with ENOENTs mid-tar. RepoLock will be dropped on its
    // own after the function returns; remove_dir_all below wipes the
    // lock file along with the rest of rdir, which is fine — Drop's
    // `fs::remove_file` becomes a silent no-op.
    let _lock = RepoLock::acquire(&rdir)?;

    let mut versions: Vec<String> = fs::read_dir(&rdir)
        .map(|it| {
            it.flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !is_part_dir_name(n))
                .collect()
        })
        .unwrap_or_default();
    versions.sort();

    // Serialize bin_dir mutations against a concurrent install of a *different*
    // package. The repo lock above only covers this package's repo_dir; the
    // link removals below touch the shared bin_dir. Acquired after the repo
    // lock (repo → links order) so it can't deadlock against an install.
    let _links = platform::acquire_links_lock(&paths.data, || {
        eprintln!("Waiting for another unpin process to finish updating links...");
    })?;

    // Windows-only alias cleanup: hardlinks can't be reverse-mapped from
    // `bin_dir`, so we re-derive the alias names by scanning the binary's
    // embedded `unpin/aliases` and unlinking each. On Unix the read_link sweep
    // below catches alias symlinks naturally — no extra I/O needed.
    let bin = &paths.bin;
    #[cfg(windows)]
    {
        let mut alias_names: Vec<String> = Vec::new();
        for v in &versions {
            for n in aliases_from_vdir(&paths.version_dir(&owner, &repo, v)) {
                if !alias_names.contains(&n) {
                    alias_names.push(n);
                }
            }
        }
        for n in &alias_names {
            let p = bin.join(platform::alias_link_filename(n));
            let _ = fs::remove_file(&p);
        }
    }

    if let Ok(entries) = fs::read_dir(bin) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(target) = platform::read_link(&path)
                && target.starts_with(&rdir)
            {
                let _ = fs::remove_file(&path);
            }
        }
    }
    if rdir.exists() {
        // Self-uninstall on Windows: the running unpin.exe lives inside rdir
        // and can't be deleted while executing. The bin links are already gone
        // (above); hand the dir to a detached janitor that wipes it once we
        // exit, and report success now.
        #[cfg(windows)]
        if crate::setup::running_from(&rdir) {
            crate::setup::spawn_dir_janitor(&rdir)?;
            println!("Removed {owner}/{repo} (cleanup finishes after unpin exits)");
            return Ok(());
        }
        fs::remove_dir_all(&rdir).map_err(|e| format!("remove {}: {e}", rdir.display()))?;
    }
    let _ = fs::remove_dir(paths.data.join(&owner));

    if versions.is_empty() {
        println!("Removed {owner}/{repo}");
    } else {
        for v in &versions {
            println!("Removed {owner}/{repo}@{v}");
        }
    }
    Ok(())
}

pub fn update(ctx: &Ctx, opts: &InstallOptions, names: &[String]) -> Result<(), String> {
    let targets: Vec<(String, String)> = if names.is_empty() {
        installed_repos(&ctx.paths)
    } else {
        // Resolve each name to (owner, repo) first, then dedup so
        // `update foo foo` (or `update foo unpins/foo`) collapses to a
        // single pipeline entry instead of racing on the same vdir. Carry the
        // original input arg alongside the resolved target so the dropped-dup
        // note can name what the user actually typed.
        let resolved: Vec<(String, (String, String))> = names
            .iter()
            .map(|n| {
                resolve_installed(&ctx.paths, n)?
                    .ok_or_else(|| format!("not installed: {n}"))
                    .map(|target| (n.clone(), target))
            })
            .collect::<Result<_, _>>()?;
        dedup_keep_first_noting(resolved, |a, b| a.1 == b.1, |(input, _)| input.clone())
            .into_iter()
            .map(|(_, target)| target)
            .collect()
    };

    if targets.is_empty() {
        println!("No packages installed");
        return Ok(());
    }

    // The dispatcher decides "up to date" via PipelineMode::Update — no
    // separate pre-fetch loop here. Every target becomes a request; the
    // per-package bar lifecycle in run_pipeline_v2 emits the "Up to date"
    // / "v1 -> v2" announcement in-place on the bar.
    let requests: Vec<PipelineRequest> = targets
        .into_iter()
        .map(|(owner, repo)| PipelineRequest {
            label: format!("{owner}/{repo}"),
            spec: Spec {
                owner,
                name: repo,
                version: None,
            },
        })
        .collect();
    run_pipeline_v2(ctx, opts, PipelineMode::Update, requests, Vec::new())
}

fn installed_repos(paths: &Paths) -> Vec<(String, String)> {
    let root = &paths.data;
    let mut out = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for owner_entry in entries.flatten() {
        if !owner_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let owner = owner_entry.file_name().to_string_lossy().into_owned();
        let repos = match fs::read_dir(owner_entry.path()) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for repo_entry in repos.flatten() {
            if !repo_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            out.push((
                owner.clone(),
                repo_entry.file_name().to_string_lossy().into_owned(),
            ));
        }
    }
    out
}

pub fn info_many(ctx: &Ctx, inputs: &[String]) -> Result<(), String> {
    // Raw-string dedup so `info tree tree` doesn't print the block twice.
    // We don't normalize ("tree" vs "unpins/tree") here — info() handles
    // both inputs internally and the cost of normalizing just to dedup
    // would be a filesystem read per arg for no real user benefit. Note the
    // dropped dup for consistency with install/remove/update.
    let inputs = dedup_keep_first_noting(inputs.to_vec(), |a, b| a == b, |s| s.clone());
    let mut failures = 0usize;
    for (i, input) in inputs.iter().enumerate() {
        if i > 0 {
            println!();
        }
        if let Err(e) = info(ctx, input) {
            eprintln!("unpin: {input}: {e}");
            failures += 1;
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(format!("{failures} info lookup(s) failed"))
    }
}

fn info(ctx: &Ctx, input: &str) -> Result<(), String> {
    if let Some((owner, repo)) = resolve_installed(&ctx.paths, input)? {
        let rdir = ctx.paths.repo_dir(&owner, &repo);
        let mut versions: Vec<String> = fs::read_dir(&rdir)
            .map_err(|e| format!("read {}: {e}", rdir.display()))?
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !is_part_dir_name(n))
            .collect();
        versions.sort();
        let active = active_version(&ctx.paths, &owner, &repo);

        println!("Repo:     {owner}/{repo}");
        if let Some(v) = &active {
            println!("Active:   {v}");
            println!(
                "Path:     {}",
                ctx.paths.version_dir(&owner, &repo, v).display()
            );
        }
        if versions.len() > 1 || active.is_none() {
            println!("Versions: {}", versions.join(", "));
        }
        println!("Links:");
        let bin = &ctx.paths.bin;
        let mut any = false;
        if let Ok(entries) = fs::read_dir(bin) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(target) = platform::read_link(&path)
                    && target.starts_with(&rdir)
                {
                    println!("  {} -> {}", path.display(), target.display());
                    any = true;
                }
            }
        }
        if !any {
            println!("  None");
        }
        return Ok(());
    }

    let spec = parse_spec(input)?;
    let release = fetch_release(ctx, &spec)?;
    println!("Repo:    {}", spec.repo());
    println!("Version: {} (latest)", release.tag_name);
    if !release.published_at.is_empty() {
        println!(
            "Date:    {}",
            &release.published_at[..release.published_at.len().min(10)]
        );
    }
    println!("Status:  not installed");
    match pick_asset(&release.assets, &spec.name, false, ctx.verbose) {
        Ok(a) => println!("Asset:   {}", a.name),
        Err(e) => println!("Asset:   (unresolved: {e})"),
    }
    Ok(())
}

pub fn prune(paths: &Paths) -> Result<(), String> {
    let mut removed = 0usize;
    let mut skipped: Vec<String> = Vec::new();

    let bin = &paths.bin;
    let root = &paths.data;
    // Phase 1: catch dangling symlinks/wrappers that already existed before
    // this prune run (e.g. user deleted a binary by hand). Must run BEFORE
    // phase 2 — otherwise phase 2's "live links" calculation would treat
    // those dangling pointers as anchors and refuse to remove their vdirs.
    //
    // Hold the shared links lock only for the sweep, then release it before
    // the per-repo loop (which takes repo locks): the global order is
    // repo → links, so we must never still hold links when acquiring a repo
    // lock. The lock keeps a concurrent install's fresh link from being seen
    // mid-write by the sweep.
    {
        let _links = platform::acquire_links_lock(root, || {
            eprintln!("Waiting for another unpin process to finish updating links...");
        })?;
        removed += sweep_dangling_links(bin, root);
    }

    // Orphan version dirs: no live link in bin_dir points into them.
    let linked_targets: Vec<PathBuf> = fs::read_dir(bin)
        .map(|it| {
            it.flatten()
                .filter_map(|e| platform::read_link(&e.path()))
                .collect()
        })
        .unwrap_or_default();

    for (owner, repo) in installed_repos(paths) {
        let rdir = paths.repo_dir(&owner, &repo);
        // Take the lock for this repo before scanning + removing version
        // dirs. Without this prune races with a concurrent `install`/`update`
        // in Phase B: the in-flight vdir exists on disk but has no link in
        // bin_dir yet (linking is Phase C), so the linked_targets check
        // above would classify it as orphan and remove_dir_all would
        // happily nuke the extraction in progress. With the lock, prune
        // either gets exclusive access or skips that repo entirely until
        // the install finishes.
        let _lock = match RepoLock::acquire(&rdir) {
            Ok(l) => l,
            Err(_) => {
                skipped.push(format!("{owner}/{repo}"));
                continue;
            }
        };
        let versions = match fs::read_dir(&rdir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for ver_entry in versions.flatten() {
            if !ver_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let vpath = ver_entry.path();
            let v = ver_entry.file_name().to_string_lossy().into_owned();
            // Stale `.part` from a crashed install (SIGKILL'd between
            // extract and rename). The RepoLock above guarantees no
            // install is currently writing this dir, so the cleanup
            // is safe. We don't gate on `linked_targets` because `.part`
            // dirs are never linked.
            if is_part_dir_name(&v) {
                if fs::remove_dir_all(&vpath).is_ok() {
                    let tag = v.strip_suffix(".part").unwrap_or(&v);
                    println!("Removed stale extraction {owner}/{repo}@{tag}");
                    removed += 1;
                }
                continue;
            }
            if linked_targets.iter().any(|t| t.starts_with(&vpath)) {
                continue;
            }
            // Windows-only: alias entries in bin_dir are NTFS hardlinks
            // (no target to dangle), so removing this vdir leaves them
            // behind unless we re-derive the names here. On Unix the
            // post-loop dangling sweep catches alias symlinks naturally
            // once their targets vanish. We hold the repo lock here, so
            // taking the links lock keeps the repo → links order intact.
            #[cfg(windows)]
            {
                let _links = platform::acquire_links_lock(root, || {
                    eprintln!("Waiting for another unpin process to finish updating links...");
                })?;
                for n in aliases_from_vdir(&vpath) {
                    let p = bin.join(platform::alias_link_filename(&n));
                    if fs::remove_file(&p).is_ok() {
                        println!("Removed alias {}", p.display());
                        removed += 1;
                    }
                }
            }
            if fs::remove_dir_all(&vpath).is_ok() {
                println!("Removed orphan {owner}/{repo}@{v}");
                removed += 1;
            }
        }
        // Clean up now-empty repo and owner dirs.
        let _ = fs::remove_dir(&rdir);
        let _ = fs::remove_dir(paths.data.join(&owner));
    }

    // Phase 3 (Unix-only): orphan-vdir removal above just broke any alias
    // symlinks pointing into those vdirs. Re-sweep so prune cleans in one
    // invocation instead of leaving newly-dangling entries for the next
    // run. On Windows the per-vdir rescan handles this inline.
    #[cfg(not(windows))]
    {
        let _links = platform::acquire_links_lock(root, || {
            eprintln!("Waiting for another unpin process to finish updating links...");
        })?;
        removed += sweep_dangling_links(bin, root);
    }

    if !skipped.is_empty() {
        eprintln!(
            "Skipped {} package(s) with an active install lock: {}",
            skipped.len(),
            skipped.join(", ")
        );
    }
    if removed > 0 {
        println!("Pruned {removed} item(s)");
    } else if skipped.is_empty() {
        println!("Nothing to prune");
    }
    Ok(())
}

/// Returns the child's exit code (0 on success, non-zero on the child's own
/// failure, 128+signal on Unix when the child died from a signal). The caller
/// is expected to map this to its own process exit so destructors at this
/// level still run — calling `std::process::exit` here skipped them.
pub fn run(
    ctx: &Ctx,
    input: &str,
    args: &[String],
    pick: bool,
    assume_yes: bool,
    refresh: bool,
) -> Result<i32, String> {
    let spec = parse_spec(input)?;

    // Cache-first: if a suitable version is already on disk, run it without
    // touching GitHub. `run` is the ephemeral "just execute it" path — keeping
    // up with the latest release is `update`/`install`'s job, not every run's.
    // An explicit `@version` matches that tag; a bare spec uses the most
    // recently fetched version. `--refresh` forces a re-resolve; `--pick` needs
    // the live asset list, so it can't short-circuit here.
    if !refresh
        && !pick
        && let Some(vdir) = cached_run_target(&ctx.paths, &spec)
    {
        // Quiet by default — a cache hit should feel like running any local
        // binary. `-v` still surfaces which version ran, for debugging.
        if ctx.verbose {
            let tag = vdir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            eprintln!("Using {} {} (cached)", spec.repo(), tag);
        }
        return run_binary(&spec, &vdir, args, assume_yes);
    }

    // Status goes to stderr: stdout belongs to the program we're about to
    // exec, and the download bar + prompts already live on stderr. A plain
    // `println!` here would splice "Resolving..." into the child's piped output.
    eprintln!("Resolving {}...", spec.repo());
    let release = fetch_release(ctx, &spec)?;
    // `run` always includes data — bypassing it could leave the binary
    // non-functional (gvim/vim need share/), and `run` is the "just try it"
    // path where surprises are worst. Use `install --no-data` if you need a
    // bare binary on disk.
    //
    // `assume_yes` comes from the `-y` flag. Without it, `preflight_extract`
    // prompts when a release lacks a SHA-256 checksum, and a non-TTY stdin
    // turns the prompt into a refusal — `unpin run owner/repo` in a script
    // won't silently execute unverified code.
    let job = preflight_extract(ctx, spec.clone(), release.clone(), assume_yes, pick, true)?;
    let vdir = job.vdir.clone();
    let needs_download = job.asset.is_some();
    if needs_download {
        // A one-row live block for the single package's download (+ a
        // transient companion row). Cleared on success — the binary runs
        // next, so no leftover line; frozen red on failure.
        let prefix = format!("{} {}", spec.name, release.tag_name);
        let (reporter, handle) = progress::start(vec![prefix.clone()]);
        let ui = Ui::Live(reporter.clone());
        let asset_size = job.asset.as_ref().map(|a| a.size).unwrap_or(0);
        let primary = reporter.start_download(0, prefix, asset_size);
        let companion = job.companion.as_ref().map(|c| {
            let cprefix = format!("{} {} (data)", spec.name, release.tag_name);
            let (cid, csink) = reporter.add_companion(cprefix, c.size);
            (cid, csink as Arc<dyn ByteSink>)
        });
        let sinks = pipeline::DlSinks {
            primary: primary.clone(),
            companion,
        };
        let result = do_extract(ctx, &job, &ui, &sinks);
        finalize_primary_row(&reporter, 0, primary, &result);
        handle.finish();
        result?;
    } else {
        let has_links = fs::read_dir(&ctx.paths.bin)
            .map(|it| {
                it.flatten().any(|e| {
                    platform::read_link(&e.path())
                        .map(|t| t.starts_with(&vdir))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if !has_links {
            // stderr, same reasoning as the "Resolving..." line above.
            eprintln!("Using {} {} (cached)", spec.repo(), release.tag_name);
        }
    }

    // Release the cross-process lock before the child runs. The child might
    // execute for minutes (interactive vim, long-running command), and we
    // don't want a parallel `unpin install` blocked the whole time. The vdir
    // contents are stable from here — the child only reads them.
    drop(job);

    run_binary(&spec, &vdir, args, assume_yes)
}

/// The version dir to run straight from the local cache, or `None` to fall
/// through to a GitHub resolve. An explicit `@version` matches a version dir by
/// tag (tolerating a leading `v` on either side); a bare spec picks the most
/// recently fetched version. A real version dir is always a complete extraction
/// (incomplete ones stay as `.part`), so its presence is enough — `run_binary`
/// does the actual executable selection.
fn cached_run_target(paths: &Paths, spec: &Spec) -> Option<PathBuf> {
    let rdir = paths.repo_dir(&spec.owner, &spec.name);
    let mut versions: Vec<(PathBuf, std::time::SystemTime)> = fs::read_dir(&rdir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter(|e| !is_part_dir_name(&e.file_name().to_string_lossy()))
        .filter_map(|e| {
            let mtime = e.metadata().and_then(|m| m.modified()).ok()?;
            Some((e.path(), mtime))
        })
        .collect();
    if versions.is_empty() {
        return None;
    }
    match &spec.version {
        Some(want) => versions.into_iter().find_map(|(p, _)| {
            let name = p.file_name()?.to_str()?;
            tag_matches(name, want).then_some(p)
        }),
        None => {
            // Most recently fetched — "the last one you got". Avoids version-
            // string sorting, which the rest of the cache does only lexically.
            versions.sort_by_key(|(_, mtime)| *mtime);
            versions.pop().map(|(p, _)| p)
        }
    }
}

/// Whether a version-dir name equals the requested `@version`, ignoring a single
/// leading `v` on either side (so `@3.4.1` matches a `v3.4.1` dir and vice
/// versa).
fn tag_matches(dir_name: &str, want: &str) -> bool {
    fn strip(s: &str) -> &str {
        s.strip_prefix('v').unwrap_or(s)
    }
    dir_name == want || strip(dir_name) == strip(want)
}

/// Pick the executable inside `vdir` and exec it with `args`, returning the
/// child's exit code. Shared by the cache-first short-circuit and the
/// post-download path.
fn run_binary(spec: &Spec, vdir: &Path, args: &[String], assume_yes: bool) -> Result<i32, String> {
    let mut files = Vec::new();
    walk_binary_candidates(vdir, &mut files)
        .map_err(|e| format!("walk {}: {e}", vdir.display()))?;
    let executables: Vec<PathBuf> = files.iter().filter(|p| is_executable(p)).cloned().collect();
    let bin = match executables.len() {
        0 => {
            // No +x file; try to promote one matching spec.name.
            let m = files
                .iter()
                .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(&spec.name))
                .ok_or("no executable in archive")?;
            ensure_executable(m)?;
            m.clone()
        }
        1 => executables.into_iter().next().unwrap(),
        _ => {
            // Multiple executables. Prefer one matching spec.name (the list is
            // sorted, so the first match is deterministic). When none matches,
            // we can't guess which the user wants — show them all and ask.
            match executables
                .iter()
                .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(&spec.name))
            {
                Some(m) => m.clone(),
                None if assume_yes => {
                    // `-y` is non-interactive; we can't ask, and won't pick a
                    // binary the user never chose.
                    return Err(format!(
                        "{} ships {} executables and none is named '{}'; \
                         re-run interactively (without -y) to pick one",
                        spec.repo(),
                        executables.len(),
                        spec.name
                    ));
                }
                None => {
                    let header = format!(
                        "{} ships {} executables, none named '{}':",
                        spec.repo(),
                        executables.len(),
                        spec.name
                    );
                    let items: Vec<String> = executables
                        .iter()
                        .map(|p| {
                            p.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("?")
                                .to_string()
                        })
                        .collect();
                    // No live bars here — the plain picker reads/writes stderr.
                    // Non-TTY (or `-y`) auto-skips, which we turn into a hard
                    // error: `run` won't execute a binary the user never picked.
                    match plain_pick(&header, &items) {
                        PromptResult::Got(n) => executables[n].clone(),
                        PromptResult::Skip => {
                            return Err(format!(
                                "{} ships {} executables and none is named '{}'; \
                                 re-run interactively to pick one",
                                spec.repo(),
                                executables.len(),
                                spec.name
                            ));
                        }
                    }
                }
            }
        }
    };

    // Expose this unpin binary to the launched package via $UNPIN_SELF, so a
    // helper package (e.g. `man`) can shell back to `unpin bundle …` against
    // exactly this binary instead of guessing one off $PATH. Best-effort: if we
    // can't resolve our own path the child just falls back to `unpin` on $PATH.
    let mut cmd = Command::new(&bin);
    cmd.args(args);
    if let Ok(self_exe) = std::env::current_exe() {
        cmd.env("UNPIN_SELF", self_exe);
    }
    let status = cmd
        .status()
        .map_err(|e| format!("exec {}: {e}", bin.display()))?;
    match status.code() {
        Some(code) => Ok(code),
        None => {
            // Unix: child terminated by signal. Mirror shell convention 128+sig
            // so callers (CI, shell scripts) see a non-zero exit. On Windows
            // status.code() is always Some(_), so this branch is Unix-only in
            // practice — fall back to 1 anywhere else.
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                let sig = status.signal().unwrap_or(0);
                Ok(128 + sig)
            }
            #[cfg(not(unix))]
            {
                Ok(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_keep_first_preserves_order_and_removes_later_dups() {
        let v = vec!["a", "b", "a", "c", "b", "d"];
        let out = dedup_keep_first_noting(v, |x, y| x == y, |x| x.to_string());
        assert_eq!(out, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn dedup_keep_first_handles_empty_and_singletons() {
        let empty: Vec<i32> = dedup_keep_first_noting(Vec::new(), |a, b| a == b, |x| x.to_string());
        assert!(empty.is_empty());
        let single = dedup_keep_first_noting(vec![42], |a, b| a == b, |x| x.to_string());
        assert_eq!(single, vec![42]);
    }

    #[test]
    fn dedup_keep_first_compares_via_projection() {
        // Same use case as install_many: dedup by the second tuple field
        // while keeping the first ("label") of the winner intact.
        let v = vec![("first", 1), ("second", 1), ("third", 2)];
        let out = dedup_keep_first_noting(v, |a, b| a.1 == b.1, |x| format!("{x:?}"));
        assert_eq!(out, vec![("first", 1), ("third", 2)]);
    }

    #[test]
    fn is_part_dir_name_matches_only_dot_part_suffix() {
        assert!(is_part_dir_name("v1.0.0.part"));
        assert!(is_part_dir_name(".part"));
        assert!(!is_part_dir_name("v1.0.0"));
        assert!(!is_part_dir_name("part"));
        assert!(!is_part_dir_name("partial"));
    }

    #[test]
    fn tag_matches_tolerates_a_single_leading_v() {
        assert!(tag_matches("v3.4.1", "3.4.1"));
        assert!(tag_matches("3.4.1", "v3.4.1"));
        assert!(tag_matches("v3.4.1", "v3.4.1"));
        assert!(tag_matches("3.4.1", "3.4.1"));
        // No false prefix matches.
        assert!(!tag_matches("v3.4.1", "3.4.2"));
        assert!(!tag_matches("v3.4.10", "3.4.1"));
    }

    fn paths_with_data(tmp: &Path) -> Paths {
        Paths {
            data: tmp.join("data"),
            bin: tmp.join("bin"),
            config: tmp.join("config"),
        }
    }

    #[test]
    fn cached_run_target_none_when_nothing_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_data(tmp.path());
        let (_, spec) = mk("htop", "unpins", "htop", None);
        assert!(cached_run_target(&paths, &spec).is_none());
    }

    #[test]
    fn cached_run_target_explicit_version_matches_with_v_tolerance() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_data(tmp.path());
        let vdir = paths.version_dir("unpins", "htop", "v3.4.0");
        fs::create_dir_all(&vdir).unwrap();

        let (_, want_v) = mk("htop@v3.4.0", "unpins", "htop", Some("v3.4.0"));
        assert_eq!(
            cached_run_target(&paths, &want_v).as_deref(),
            Some(vdir.as_path())
        );
        // Without the leading `v`, still matches the `v`-prefixed dir.
        let (_, want_bare) = mk("htop@3.4.0", "unpins", "htop", Some("3.4.0"));
        assert_eq!(
            cached_run_target(&paths, &want_bare).as_deref(),
            Some(vdir.as_path())
        );
        // A version we don't have on disk → fall through to a GitHub resolve.
        let (_, want_miss) = mk("htop@9.9.9", "unpins", "htop", Some("9.9.9"));
        assert!(cached_run_target(&paths, &want_miss).is_none());
    }

    #[test]
    fn cached_run_target_ignores_part_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_data(tmp.path());
        // Only a half-finished extract on disk → nothing complete to run.
        fs::create_dir_all(paths.repo_dir("unpins", "htop").join("v3.4.0.part")).unwrap();
        let (_, spec) = mk("htop", "unpins", "htop", None);
        assert!(cached_run_target(&paths, &spec).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn cached_run_target_bare_picks_most_recently_fetched() {
        use std::time::{Duration, SystemTime};
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_data(tmp.path());
        let older = paths.version_dir("unpins", "htop", "v3.4.0");
        let newer = paths.version_dir("unpins", "htop", "v3.5.0");
        fs::create_dir_all(&older).unwrap();
        fs::create_dir_all(&newer).unwrap();
        // Force `older`'s mtime back so the ordering is unambiguous regardless
        // of how close together the two dirs were created.
        std::fs::File::open(&older)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(60))
            .unwrap();
        let (_, spec) = mk("htop", "unpins", "htop", None);
        assert_eq!(
            cached_run_target(&paths, &spec).as_deref(),
            Some(newer.as_path())
        );
    }

    fn mk(label: &str, owner: &str, name: &str, version: Option<&str>) -> (String, Spec) {
        (
            label.into(),
            Spec {
                owner: owner.into(),
                name: name.into(),
                version: version.map(|v| v.into()),
            },
        )
    }

    #[test]
    fn argv_collision_no_conflict_returns_unchanged() {
        let input = vec![
            mk("htop", "unpins", "htop", None),
            mk("tree@v2", "unpins", "tree", Some("v2")),
        ];
        let out = resolve_argv_version_collisions(input, true).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, "htop");
        assert_eq!(out[1].0, "tree@v2");
    }

    #[test]
    fn argv_collision_assume_yes_keeps_last_per_repo() {
        // foo/bar specified with v1 and v2; assume_yes keeps the last.
        // Order of unrelated entries is preserved.
        let input = vec![
            mk("alpha", "u", "alpha", None),
            mk("foo/bar@v1", "foo", "bar", Some("v1")),
            mk("zeta", "u", "zeta", None),
            mk("foo/bar@v2", "foo", "bar", Some("v2")),
        ];
        let out = resolve_argv_version_collisions(input, true).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0, "alpha");
        assert_eq!(out[1].0, "zeta");
        assert_eq!(out[2].0, "foo/bar@v2");
    }

    #[test]
    fn argv_collision_non_tty_without_yes_skips_group() {
        // cargo test runs with a piped stdin (non-TTY), so the collision
        // prompt auto-skips per the shared `prompt_pick_with_skip` contract.
        // The whole conflicting group is dropped non-fatally; unrelated
        // entries pass through.
        let input = vec![
            mk("alpha", "u", "alpha", None),
            mk("foo/bar@v1", "foo", "bar", Some("v1")),
            mk("foo/bar@v2", "foo", "bar", Some("v2")),
            mk("zeta", "u", "zeta", None),
        ];
        let out = resolve_argv_version_collisions(input, false).unwrap();
        let labels: Vec<&str> = out.iter().map(|(s, _)| s.as_str()).collect();
        assert_eq!(labels, vec!["alpha", "zeta"]);
    }
}
