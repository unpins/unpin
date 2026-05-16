use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget};

use crate::ctx::Ctx;
use crate::github::{self, Release};
use crate::platform;

mod asset;
mod linker;
mod pipeline;
mod spec;

use asset::pick_asset;
#[cfg(windows)]
use linker::aliases_from_vdir;
use linker::{ensure_executable, is_executable, sweep_dangling_links, walk_files};
pub use pipeline::InstallOptions;
use pipeline::{do_extract, preflight_extract, run_pipeline};
use spec::validate_path_component;
pub use spec::{Spec, parse_spec};

pub(super) fn data_dir() -> PathBuf {
    platform::data_dir()
}

pub(super) fn bin_dir() -> PathBuf {
    platform::bin_dir()
}

pub(super) fn repo_dir(owner: &str, name: &str) -> PathBuf {
    data_dir().join(owner).join(name)
}

pub(super) fn version_dir(owner: &str, name: &str, tag: &str) -> PathBuf {
    repo_dir(owner, name).join(tag)
}

/// Search the data dir for a repo matching `name`. Accepts "owner/repo" or a
/// bare repo name (searches all owners; ambiguous match is an error).
fn resolve_installed(name: &str) -> Result<Option<(String, String)>, String> {
    if let Some((owner, repo)) = name.split_once('/') {
        if !owner.is_empty() && !repo.is_empty() && !repo.contains('/') {
            return Ok(if repo_dir(owner, repo).is_dir() {
                Some((owner.to_owned(), repo.to_owned()))
            } else {
                None
            });
        }
        return Err(format!("invalid name: `{name}`"));
    }
    let root = data_dir();
    let entries = match fs::read_dir(&root) {
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
/// pipeline handles it fine: `preflight_extract` sees the cached vdir and
/// skips the download, so `update` just re-links without re-downloading.
fn active_version(owner: &str, name: &str) -> Option<String> {
    let rdir = repo_dir(owner, name);
    let bins = fs::read_dir(bin_dir()).ok()?;
    for entry in bins.flatten() {
        if let Some(target) = platform::read_link(&entry.path())
            && let Ok(rel) = target.strip_prefix(&rdir)
            && let Some(first) = rel.components().next()
        {
            let v = first.as_os_str().to_string_lossy().into_owned();
            if version_dir(owner, name, &v).is_dir() {
                return Some(v);
            }
        }
    }
    None
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
    // Dedup, preserving first-seen order: two identical args (or two args
    // that normalize to the same spec, e.g. "ripgrep" and "unpins/ripgrep")
    // would otherwise race on the same vdir in the parallel phase. Linear
    // scan is fine — N is the CLI arg count.
    let mut specs: Vec<(String, Spec)> = Vec::with_capacity(parsed.len());
    for (label, spec) in parsed {
        if !specs.iter().any(|(_, s)| s == &spec) {
            specs.push((label, spec));
        }
    }
    run_pipeline(ctx, opts, specs, Vec::new())
}

pub fn list() -> Result<(), String> {
    let root = data_dir();
    let entries = match fs::read_dir(&root) {
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
                rows.push((owner.clone(), repo.clone(), v));
            }
        }
    }
    if rows.is_empty() {
        println!("No packages installed");
        return Ok(());
    }
    rows.sort();

    let linked_targets: Vec<PathBuf> = fs::read_dir(bin_dir())
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
        let vdir = version_dir(owner, repo, v);
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

pub fn remove_many(names: &[String], assume_yes: bool) -> Result<(), String> {
    let targets: Vec<String> = if names.is_empty() {
        let all = installed_repos();
        if all.is_empty() {
            println!("No packages installed");
            return Ok(());
        }
        println!("This will remove all {} installed package(s):", all.len());
        for (owner, repo) in &all {
            println!("  {owner}/{repo}");
        }
        if !assume_yes && !prompt_yes_no("Continue?") {
            return Err("aborted".into());
        }
        all.into_iter().map(|(o, r)| format!("{o}/{r}")).collect()
    } else {
        names.to_vec()
    };

    let mut failures = 0usize;
    for name in &targets {
        if let Err(e) = remove_one(name) {
            eprintln!("unpin: {name}: {e}");
            failures += 1;
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(format!("{failures} remove(s) failed"))
    }
}

fn remove_one(name: &str) -> Result<(), String> {
    let (owner, repo) = resolve_installed(name)?.ok_or("not installed")?;
    let rdir = repo_dir(&owner, &repo);

    let mut versions: Vec<String> = fs::read_dir(&rdir)
        .map(|it| {
            it.flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    versions.sort();

    // Windows-only alias cleanup: hardlinks can't be reverse-mapped from
    // `bin_dir`, so we re-derive the alias names by scanning the binary's
    // UNPIN_META block and unlinking each. On Unix the read_link sweep
    // below catches alias symlinks naturally — no extra I/O needed.
    let bin = bin_dir();
    #[cfg(windows)]
    {
        let mut alias_names: Vec<String> = Vec::new();
        for v in &versions {
            for n in aliases_from_vdir(&version_dir(&owner, &repo, v)) {
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

    if let Ok(entries) = fs::read_dir(&bin) {
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
        fs::remove_dir_all(&rdir).map_err(|e| format!("remove {}: {e}", rdir.display()))?;
    }
    let _ = fs::remove_dir(data_dir().join(&owner));

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
        installed_repos()
    } else {
        // Dedup, preserving first-seen order: `update foo foo` (or
        // `update foo unpins/foo`) would otherwise race on the same vdir.
        let mut out: Vec<(String, String)> = Vec::with_capacity(names.len());
        for n in names {
            let r = resolve_installed(n)?.ok_or_else(|| format!("not installed: {n}"))?;
            if !out.contains(&r) {
                out.push(r);
            }
        }
        out
    };

    if targets.is_empty() {
        println!("No packages installed");
        return Ok(());
    }

    // Resolve which packages actually need an update before kicking off the
    // pipeline — so users see "up to date" lines and `-j` doesn't waste workers
    // on no-ops. Up-to-date / failed resolutions never reach the pipeline.
    let mut errors: Vec<String> = Vec::new();
    let mut specs: Vec<(String, Spec)> = Vec::new();
    for (owner, repo) in &targets {
        let spec = Spec {
            owner: owner.clone(),
            name: repo.clone(),
            version: None,
        };
        let release = match github::fetch_latest(ctx, &spec.repo()) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("unpin: {owner}/{repo}: {e}"));
                continue;
            }
        };
        let current = active_version(owner, repo);
        if current.as_deref() == Some(release.tag_name.as_str()) {
            println!("{owner}/{repo}: up to date ({})", release.tag_name);
            continue;
        }
        let from = current.as_deref().unwrap_or("(none)");
        println!("{owner}/{repo}: {} -> {}", from, release.tag_name);
        specs.push((format!("{owner}/{repo}"), spec));
    }

    run_pipeline(ctx, opts, specs, errors)
}

fn installed_repos() -> Vec<(String, String)> {
    let root = data_dir();
    let mut out = Vec::new();
    let entries = match fs::read_dir(&root) {
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
    if let Some((owner, repo)) = resolve_installed(input)? {
        let rdir = repo_dir(&owner, &repo);
        let mut versions: Vec<String> = fs::read_dir(&rdir)
            .map_err(|e| format!("read {}: {e}", rdir.display()))?
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        versions.sort();
        let active = active_version(&owner, &repo);

        println!("Repo:     {owner}/{repo}");
        if let Some(v) = &active {
            println!("Active:   {v}");
            println!("Path:     {}", version_dir(&owner, &repo, v).display());
        }
        if versions.len() > 1 || active.is_none() {
            println!("Versions: {}", versions.join(", "));
        }
        println!("Links:");
        let bin = bin_dir();
        let mut any = false;
        if let Ok(entries) = fs::read_dir(&bin) {
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

pub fn prune() -> Result<(), String> {
    let mut removed = 0usize;

    let bin = bin_dir();
    let root = data_dir();
    // Phase 1: catch dangling symlinks/wrappers that already existed before
    // this prune run (e.g. user deleted a binary by hand). Must run BEFORE
    // phase 2 — otherwise phase 2's "live links" calculation would treat
    // those dangling pointers as anchors and refuse to remove their vdirs.
    removed += sweep_dangling_links(&bin, &root);

    // Orphan version dirs: no live link in bin_dir points into them.
    let linked_targets: Vec<PathBuf> = fs::read_dir(&bin)
        .map(|it| {
            it.flatten()
                .filter_map(|e| platform::read_link(&e.path()))
                .collect()
        })
        .unwrap_or_default();

    for (owner, repo) in installed_repos() {
        let rdir = repo_dir(&owner, &repo);
        let versions = match fs::read_dir(&rdir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for ver_entry in versions.flatten() {
            if !ver_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let vpath = ver_entry.path();
            if linked_targets.iter().any(|t| t.starts_with(&vpath)) {
                continue;
            }
            // Windows-only: alias entries in bin_dir are NTFS hardlinks
            // (no target to dangle), so removing this vdir leaves them
            // behind unless we re-derive the names here. On Unix the
            // post-loop dangling sweep catches alias symlinks naturally
            // once their targets vanish.
            #[cfg(windows)]
            for n in aliases_from_vdir(&vpath) {
                let p = bin.join(platform::alias_link_filename(&n));
                if fs::remove_file(&p).is_ok() {
                    println!("Removed alias {}", p.display());
                    removed += 1;
                }
            }
            let v = ver_entry.file_name().to_string_lossy().into_owned();
            if fs::remove_dir_all(&vpath).is_ok() {
                println!("Removed orphan {owner}/{repo}@{v}");
                removed += 1;
            }
        }
        // Clean up now-empty repo and owner dirs.
        let _ = fs::remove_dir(&rdir);
        let _ = fs::remove_dir(data_dir().join(&owner));
    }

    // Phase 3 (Unix-only): orphan-vdir removal above just broke any alias
    // symlinks pointing into those vdirs. Re-sweep so prune cleans in one
    // invocation instead of leaving newly-dangling entries for the next
    // run. On Windows the per-vdir rescan handles this inline.
    #[cfg(not(windows))]
    {
        removed += sweep_dangling_links(&bin, &root);
    }

    if removed == 0 {
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
) -> Result<i32, String> {
    let spec = parse_spec(input)?;
    println!("Resolving {}...", spec.repo());
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
        let multi = if io::stderr().is_terminal() {
            MultiProgress::new()
        } else {
            MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
        };
        // multi.add before set_style/set_prefix — see comment in parallel_extract
        // about ghost rows from stderr-direct ticks on freshly-constructed bars.
        let bar = multi.add(ProgressBar::new(0));
        bar.set_style(github::download_progress_style());
        bar.set_prefix(format!("{} {}", spec.name, release.tag_name));
        if let Some(asset) = job.asset.as_ref()
            && asset.size > 0
        {
            bar.set_length(asset.size);
        }
        let cbar = job.companion.as_ref().map(|companion| {
            let cb = multi.add(ProgressBar::new(0));
            cb.set_style(github::download_progress_style());
            cb.set_prefix(format!("{} {} (data)", spec.name, release.tag_name));
            if companion.size > 0 {
                cb.set_length(companion.size);
            }
            cb
        });
        do_extract(ctx, &job, &bar, cbar.as_ref(), &multi)?;
    } else {
        let has_links = fs::read_dir(bin_dir())
            .map(|it| {
                it.flatten().any(|e| {
                    platform::read_link(&e.path())
                        .map(|t| t.starts_with(&vdir))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if !has_links {
            println!("Using {} {} (cached)", spec.repo(), release.tag_name);
        }
    }

    // Release the cross-process lock before the child runs. The child might
    // execute for minutes (interactive vim, long-running command), and we
    // don't want a parallel `unpin install` blocked the whole time. The vdir
    // contents are stable from here — the child only reads them.
    drop(job);

    let mut files = Vec::new();
    walk_files(&vdir, &mut files).map_err(|e| format!("walk {}: {e}", vdir.display()))?;
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
            // Multiple executables: prefer one matching spec.name.
            executables
                .iter()
                .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(&spec.name))
                .cloned()
                .unwrap_or_else(|| executables.into_iter().next().unwrap())
        }
    };

    let status = Command::new(&bin)
        .args(args)
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
