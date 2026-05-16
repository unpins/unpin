use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget};

use crate::aliases::{self, AliasMode};
use crate::archive;
use crate::ctx::Ctx;
use crate::github::{self, Asset, Release};
use crate::platform;

mod spec;

use spec::{CATALOG_OWNER, validate_path_component};
pub use spec::{Spec, parse_spec};

/// Resolved per-invocation policy for one `install`/`update` call. Bundled
/// so the pipeline functions don't carry a five-arg tail of policy flags.
/// `main.rs` builds this from CLI args + config before entering install code.
pub struct InstallOptions {
    pub assume_yes: bool,
    pub jobs: u8,
    pub pick: bool,
    pub include_data: bool,
    pub alias_mode: AliasMode,
}

impl InstallOptions {
    /// Combine CLI overrides with config defaults. `alias_override` comes
    /// from `--aliases`/`--no-aliases`/`--ask-aliases` resolution; `no_data`
    /// from `--no-data`. Caller owns the `ctx` so config lookups happen
    /// here at the boundary rather than scattered in pipeline functions.
    pub fn resolve(
        ctx: &Ctx,
        assume_yes: bool,
        jobs: u8,
        pick: bool,
        no_data: bool,
        alias_override: Option<AliasMode>,
    ) -> Self {
        Self {
            assume_yes,
            jobs,
            pick,
            include_data: !no_data && ctx.cfg.data(),
            alias_mode: alias_override.unwrap_or_else(|| ctx.cfg.aliases()),
        }
    }
}

fn data_dir() -> PathBuf {
    platform::data_dir()
}

fn bin_dir() -> PathBuf {
    platform::bin_dir()
}

fn repo_dir(owner: &str, name: &str) -> PathBuf {
    data_dir().join(owner).join(name)
}

fn version_dir(owner: &str, name: &str, tag: &str) -> PathBuf {
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

/// Classify an asset that should be excluded from the picker. Returns a short
/// human reason, or `None` if the asset is potentially installable.
fn classify_excluded(name_lower: &str) -> Option<&'static str> {
    if platform::other_os_keys()
        .iter()
        .any(|k| name_lower.contains(k))
    {
        return Some("other platform");
    }
    if platform::other_arch_keys()
        .iter()
        .any(|k| name_lower.contains(k))
    {
        return Some("other arch");
    }
    if platform::auxiliary_keys()
        .iter()
        .any(|k| name_lower.contains(k))
    {
        return Some("auxiliary");
    }
    if name_lower.contains(".bsdiff") {
        return Some("unsupported format");
    }
    // Data companion of another release asset: `<pkg>-<tag>-data.tar.zst`. One
    // per release (platform-agnostic runtime data, e.g. vim/share/vim/<ver>).
    // Excluded from the picker — preflight pairs it with the primary by tag.
    if name_lower.ends_with("-data.tar.zst") {
        return Some("data companion");
    }
    if !platform::current_os_keys()
        .iter()
        .any(|k| name_lower.contains(k))
    {
        return Some("no OS tag");
    }
    None
}

pub fn pick_asset<'a>(
    assets: &'a [Asset],
    repo_name: &str,
    force_pick: bool,
    verbose: bool,
) -> Result<&'a Asset, String> {
    let arch_keys = platform::current_arch_keys();

    let mut selectable: Vec<&Asset> = Vec::new();
    let mut ignored: Vec<(&Asset, &'static str)> = Vec::new();
    for a in assets {
        let l = a.name.to_ascii_lowercase();
        match classify_excluded(&l) {
            Some(reason) => ignored.push((a, reason)),
            None => selectable.push(a),
        }
    }

    // Tier 1: linux + explicit arch tag. Tier 2 (fallback): linux only.
    let with_arch: Vec<&Asset> = selectable
        .iter()
        .copied()
        .filter(|a| {
            let l = a.name.to_ascii_lowercase();
            arch_keys.iter().any(|k| l.contains(k))
        })
        .collect();
    let mut candidates = if with_arch.is_empty() {
        selectable.clone()
    } else {
        with_arch
    };

    // Narrow to `<repo>-<arch>` etc. when auto-picking; --pick keeps the
    // full selectable list so the user can choose alternates.
    if !force_pick && candidates.len() > 1 {
        let repo_lower = repo_name.to_ascii_lowercase();
        let narrowed: Vec<&Asset> = candidates
            .iter()
            .copied()
            .filter(|a| {
                let l = a.name.to_ascii_lowercase();
                let Some(rest) = l.strip_prefix(&repo_lower) else {
                    return false;
                };
                let Some(sep) = rest.chars().next() else {
                    return false;
                };
                if !matches!(sep, '-' | '_' | '.') {
                    return false;
                }
                let after_sep = &rest[sep.len_utf8()..];
                arch_keys.iter().any(|k| after_sep.starts_with(k))
            })
            .collect();
        if !narrowed.is_empty() {
            candidates = narrowed;
        }
    }

    if verbose && !ignored.is_empty() {
        let w = ignored.iter().map(|(a, _)| a.name.len()).max().unwrap_or(0);
        eprintln!("Ignored {} assets:", ignored.len());
        for (a, reason) in &ignored {
            eprintln!("  {:<w$}  ({reason})", a.name);
        }
    }

    if candidates.is_empty() {
        return Err(format!(
            "no matching {os} {arch} asset.\nAvailable assets:\n{list}",
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH,
            list = assets
                .iter()
                .map(|a| format!("  {}", a.name))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    if !force_pick && candidates.len() == 1 {
        return Ok(candidates[0]);
    }
    prompt_pick(&candidates)
}

fn prompt_pick<'a>(candidates: &[&'a Asset]) -> Result<&'a Asset, String> {
    let header = if candidates.len() == 1 {
        "Available asset:"
    } else {
        "Available assets:"
    };
    println!("{header}");
    let name_w = candidates.iter().map(|a| a.name.len()).max().unwrap_or(0);
    for (i, a) in candidates.iter().enumerate() {
        // GitHub-reported size on the right; some older API responses elide
        // it (size == 0), so suppress the column for those entries rather
        // than print a misleading "0 B".
        if a.size > 0 {
            println!(
                "  [{}] {:<name_w$}  ({})",
                i + 1,
                a.name,
                indicatif::HumanBytes(a.size),
            );
        } else {
            println!("  [{}] {}", i + 1, a.name);
        }
    }
    print!("Pick [1-{}]: ", candidates.len());
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("stdin: {e}"))?;
    let idx: usize = line
        .trim()
        .parse()
        .map_err(|_| "invalid choice".to_string())?;
    if idx < 1 || idx > candidates.len() {
        return Err("choice out of range".into());
    }
    Ok(candidates[idx - 1])
}

fn prompt_yes_no(question: &str) -> bool {
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

fn walk_files(root: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
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

fn is_executable(p: &Path) -> bool {
    platform::is_executable(p)
}

fn ensure_executable(p: &Path) -> Result<(), String> {
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

fn link_binary(target: &Path, link: &Path, assume_yes: bool) -> Result<bool, String> {
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
            if !prompt_yes_no(&q) {
                eprintln!(
                    "Skipped {}",
                    link.file_name().unwrap_or_default().to_string_lossy()
                );
                return Ok(false);
            }
        }
        let _ = fs::remove_file(link);
    }
    platform::create_link(target, link)
        .map_err(|e| format!("link {} -> {}: {e}", link.display(), target.display()))?;
    Ok(true)
}

fn fetch_release(ctx: &Ctx, spec: &Spec) -> Result<Release, String> {
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

/// Result of the serial preflight: enough to extract+verify in a worker without
/// talking to the user. `None` for `expected_sha256` means user opted to skip
/// verification; `None` for `asset` means the package is already cached.
pub struct ExtractJob {
    pub spec: Spec,
    pub release: Release,
    pub vdir: PathBuf,
    /// `None` → already cached, worker skips the download path entirely.
    pub asset: Option<Asset>,
    pub expected_sha256: Option<String>,
    /// Data tarball companion (e.g. `<pkg>-<tag>-data.tar.zst`) bundled with the
    /// release. Extracted into the same `vdir` after the primary. `None` for
    /// packages without runtime data (the common case).
    pub companion: Option<Asset>,
    pub companion_expected_sha256: Option<String>,
    /// Cross-process lock on the package's `repo_dir`. Held from preflight
    /// (right before the first destructive write) through the end of Phase C
    /// linking. `None` for cached jobs (no write happens, no lock needed).
    /// Field is private so the lock can only be released via Drop.
    _lock: Option<PipelineLock>,
}

/// Local wrapper that pairs an `InstallLock` with sigint cleanup. Acquiring
/// pushes the lock path onto the ctrl-c cleanup list so an interrupted
/// install doesn't leave a stale `.unpin.lock` behind; Drop pops it back
/// off, then `InstallLock::Drop` removes the file.
struct PipelineLock {
    inner: platform::InstallLock,
}

impl PipelineLock {
    /// 1-hour stale-after window: long enough that a slow install on a thin
    /// network doesn't get its lock stolen, short enough that a genuinely
    /// abandoned lock (SIGKILL, power loss) recovers automatically without
    /// requiring the user to find and `rm` the file.
    const STALE_AFTER: Duration = Duration::from_secs(3600);

    fn acquire(repo_dir: &Path) -> Result<Self, String> {
        let inner = platform::acquire_install_lock(repo_dir, Self::STALE_AFTER)?;
        crate::sigint::push_cleanup(inner.path());
        Ok(Self { inner })
    }
}

impl Drop for PipelineLock {
    fn drop(&mut self) {
        crate::sigint::pop_cleanup(self.inner.path());
        // platform::InstallLock::drop runs next and removes the file.
    }
}

/// Find `<pkg>-<tag>-data.tar.zst` in the release's assets. Tries both raw
/// `tag` and `v`-stripped (GitHub releases typically tag as `v9.2.0` but our
/// build emits the data asset using the bare version). Returns `None` for
/// packages that don't ship a runtime tarball.
fn find_companion<'a>(pkg: &str, tag: &str, assets: &'a [Asset]) -> Option<&'a Asset> {
    let pkg_l = pkg.to_ascii_lowercase();
    let tag_l = tag.to_ascii_lowercase();
    let tag_v = tag_l.trim_start_matches('v');
    let candidates = [
        format!("{pkg_l}-{tag_l}-data.tar.zst"),
        format!("{pkg_l}-{tag_v}-data.tar.zst"),
    ];
    assets.iter().find(|a| {
        let n = a.name.to_ascii_lowercase();
        candidates.contains(&n)
    })
}

/// Serial preflight: pick asset, resolve checksum, decide if download is needed.
/// May prompt the user (asset picker, missing-checksum confirmation).
fn preflight_extract(
    ctx: &Ctx,
    spec: Spec,
    release: Release,
    assume_yes: bool,
    pick: bool,
    include_data: bool,
) -> Result<ExtractJob, String> {
    let vdir = version_dir(&spec.owner, &spec.name, &release.tag_name);
    // `--no-data` (or `data = false` in config) suppresses the companion lookup
    // entirely. As a side effect the cache-complete check no longer requires
    // `share/`, so a vdir installed without data won't be re-extracted by a
    // later `--no-data` install/update — and conversely, a vdir installed with
    // `--no-data` will be re-extracted when the user later runs without it.
    let companion_peek = if include_data {
        find_companion(&spec.name, &release.tag_name, &release.assets)
    } else {
        None
    };
    // Cache is complete iff the version dir exists AND, if a companion exists,
    // share/ is present (the companion's payload). Without this, a download
    // interrupted between primary and companion leaves a half-installed vdir
    // that the cache check would happily accept.
    let cache_complete = vdir.is_dir() && (companion_peek.is_none() || vdir.join("share").is_dir());
    if cache_complete && !pick {
        return Ok(ExtractJob {
            spec,
            release,
            vdir,
            asset: None,
            expected_sha256: None,
            companion: None,
            companion_expected_sha256: None,
            _lock: None,
        });
    }
    let asset = pick_asset(&release.assets, &spec.name, pick, ctx.verbose)?.clone();
    // Acquire the cross-process lock *after* any user prompt (asset picker)
    // and *before* the first destructive write. Holding it through the
    // prompt would force a parallel install on the same package to error
    // out while the user is at coffee.
    let lock = PipelineLock::acquire(&repo_dir(&spec.owner, &spec.name))?;
    // --pick (or incomplete cache) on a cached version: wipe before re-extracting.
    if vdir.is_dir() {
        fs::remove_dir_all(&vdir).map_err(|e| format!("remove {}: {e}", vdir.display()))?;
    }
    let expected_sha256 = match find_checksum_url(&release.assets, &asset.name) {
        Some(url) => Some(fetch_expected_sha256(ctx, &url)?),
        None => {
            if !assume_yes
                && !prompt_yes_no("No SHA-256 checksum found. Continue without verification?")
            {
                return Err("aborted: missing checksum".into());
            }
            None
        }
    };
    let companion = if include_data {
        find_companion(&spec.name, &release.tag_name, &release.assets).cloned()
    } else {
        None
    };
    let companion_expected_sha256 = match companion.as_ref() {
        Some(c) => match find_checksum_url(&release.assets, &c.name) {
            Some(url) => Some(fetch_expected_sha256(ctx, &url)?),
            None => {
                if !assume_yes
                    && !prompt_yes_no(
                        "Data companion has no SHA-256 checksum. Continue without verification?",
                    )
                {
                    return Err("aborted: missing companion checksum".into());
                }
                None
            }
        },
        None => None,
    };
    Ok(ExtractJob {
        spec,
        release,
        vdir,
        asset: Some(asset),
        expected_sha256,
        companion,
        companion_expected_sha256,
        _lock: Some(lock),
    })
}

/// Per-download UI handle: which bar to drive, the shared MultiProgress
/// (for serialized `println` so log lines don't interleave with bar
/// renders), and the label/flavor used in messages.
struct ProgressContext<'a> {
    bar: &'a ProgressBar,
    multi: &'a MultiProgress,
    repo: &'a str,
    is_companion: bool,
}

/// Orchestrate one ExtractJob: download+extract primary, and (if present)
/// data companion **concurrently** via `thread::scope`. They write disjoint
/// subtrees of the same vdir (e.g. `bin/` vs `share/`), so there's no
/// contention. Bars must be pre-added to `multi` on the main thread — see
/// the comment in `parallel_extract` for why.
///
/// Per-job cleanup (sigint hook + CleanupGuard) is armed here and only
/// disarmed when *all* tasks succeed; any failure rolls back the vdir.
fn do_extract(
    ctx: &Ctx,
    job: &ExtractJob,
    primary_bar: &ProgressBar,
    companion_bar: Option<&ProgressBar>,
    multi: &MultiProgress,
) -> Result<(), String> {
    let Some(primary_asset) = job.asset.as_ref() else {
        return Ok(()); // cached
    };
    let rdir = repo_dir(&job.spec.owner, &job.spec.name);
    fs::create_dir_all(&rdir).map_err(|e| format!("mkdir {}: {e}", rdir.display()))?;
    crate::sigint::push_cleanup(&job.vdir);
    let mut guard = CleanupGuard::arm(job.vdir.clone());

    let repo = job.spec.repo();
    let primary_ui = ProgressContext {
        bar: primary_bar,
        multi,
        repo: &repo,
        is_companion: false,
    };
    let result = if let (Some(companion), Some(cbar)) = (job.companion.as_ref(), companion_bar) {
        let companion_ui = ProgressContext {
            bar: cbar,
            multi,
            repo: &repo,
            is_companion: true,
        };
        // Run primary + companion in parallel. Each task handles its own bar
        // finalization (clear on Ok, red+abandon on Err) inside
        // `download_extract_verify`, so the UI doesn't wait on the slowest leg
        // before showing failures. The join below propagates the first error;
        // CleanupGuard then wipes the vdir for a clean retry.
        let (r_prim, r_comp) = thread::scope(|s| {
            let h_prim = s.spawn(|| {
                download_extract_verify(
                    ctx,
                    &primary_ui,
                    primary_asset,
                    job.expected_sha256.as_deref(),
                    &job.vdir,
                )
            });
            let h_comp = s.spawn(|| {
                download_extract_verify(
                    ctx,
                    &companion_ui,
                    companion,
                    job.companion_expected_sha256.as_deref(),
                    &job.vdir,
                )
            });
            (h_prim.join().unwrap(), h_comp.join().unwrap())
        });
        r_prim.and(r_comp)
    } else {
        download_extract_verify(
            ctx,
            &primary_ui,
            primary_asset,
            job.expected_sha256.as_deref(),
            &job.vdir,
        )
    };

    if result.is_ok() {
        crate::sigint::pop_cleanup(&job.vdir);
        guard.disarm();
    }
    result
}

/// One download → extract → verify step against a single bar. The caller
/// pre-adds the bar to a shared `MultiProgress`. On success the bar is
/// cleared; on failure it's re-styled red and abandoned so the reason stays
/// visible. The vdir is shared between primary and companion calls — both
/// tar streams write disjoint subtrees, so concurrent invocations are safe.
fn download_extract_verify(
    ctx: &Ctx,
    ui: &ProgressContext,
    asset: &Asset,
    expected_sha256: Option<&str>,
    vdir: &Path,
) -> Result<(), String> {
    let r = (|| -> Result<(), String> {
        if ctx.verbose {
            // multi.println serializes with the bar render loop — avoids
            // interleaving on a TTY. In non-TTY mode (hidden draw target)
            // this is a no-op; api_get URLs from Phase A still print via
            // eprintln, so the user sees what was resolved even when piping.
            let _ = ui
                .multi
                .println(format!("  GET {}", asset.browser_download_url));
        }
        let stream = github::download_stream_into(ctx, &asset.browser_download_url, ui.bar)?;
        // Capture expected length before wrapping. Server Content-Length is
        // authoritative; fall back to `Asset.size` from the API when the CDN
        // omits the header, so truncation still gets caught even on
        // checksum-less releases.
        let content_length = stream
            .content_length()
            .or_else(|| (asset.size > 0).then_some(asset.size));
        let mut hashing = HashingReader::new(stream);
        archive::extract(&asset.name, &mut hashing, vdir)?;
        // Defensive: every extractor today drains its input to EOF, but make
        // the byte count and the hash reflect the whole response regardless
        // of which path was taken — cheap insurance for future formats.
        let _ = io::copy(&mut hashing, &mut io::sink());
        let got_bytes = ui.bar.position();
        let got = hashing.finalize_hex();
        if let Some(expected) = expected_sha256 {
            if !got.eq_ignore_ascii_case(expected) {
                return Err(format!(
                    "checksum mismatch for {}: expected {expected}, got {got}",
                    asset.name
                ));
            }
            let suffix = if ui.is_companion { " (data)" } else { "" };
            let _ = ui.multi.println(format!(
                "  verified {}{suffix}  ({})",
                ui.repo,
                &expected[..16]
            ));
        } else if let Some(total) = content_length
            && got_bytes != total
        {
            // Belt-and-suspenders for releases without a published checksum:
            // a server that closes mid-stream still lets `io::copy` succeed
            // with a short read (EOF != error). The length compare catches
            // the resulting truncated binary that archive::extract didn't.
            return Err(format!(
                "truncated download for {}: read {got_bytes} of {total} bytes",
                asset.name
            ));
        }
        Ok(())
    })();
    match &r {
        Ok(()) => ui.bar.finish_and_clear(),
        Err(e) => {
            ui.bar.set_style(github::download_error_style());
            ui.bar.set_message(e.clone());
            ui.bar.abandon();
        }
    }
    r
}

struct CleanupGuard {
    path: PathBuf,
    armed: bool,
}
impl CleanupGuard {
    fn arm(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: sha2::Sha256,
}
impl<R: io::Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        use sha2::Digest;
        Self {
            inner,
            hasher: sha2::Sha256::new(),
        }
    }
    fn finalize_hex(self) -> String {
        use sha2::Digest;
        let digest = self.hasher.finalize();
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}
impl<R: io::Read> io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use sha2::Digest;
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
    }
}

/// Outcome of `link_all_executables`. Primary names go into the install
/// summary line; alias names get a separate `aliases:` line; notes ride a
/// `note:` line (e.g. when aliases were declared but skipped — non-catalog
/// source, `--no-aliases`, etc).
#[derive(Default)]
struct LinkSummary {
    primary: Vec<String>,
    aliases: Vec<String>,
    notes: Vec<String>,
}

fn link_all_executables(
    spec: &Spec,
    vdir: &Path,
    assume_yes: bool,
    alias_mode: AliasMode,
) -> Result<LinkSummary, String> {
    let mut files = Vec::new();
    walk_files(vdir, &mut files).map_err(|e| format!("walk {}: {e}", vdir.display()))?;

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
        if link_binary(target, &link, assume_yes)? {
            refreshed.push(link.clone());
            summary.primary.push(short.to_owned());
        }

        // Aliases scan + create. We attempt this on every primary executable;
        // most packages have one, but a multi-binary release with two
        // alias-bearing primaries would just contribute both lists. The
        // catalog-only gate is enforced inside `link_aliases_for`.
        let alias_outcome = link_aliases_for(target, spec, alias_mode, assume_yes)?;
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
            prompt_yes_no(&q)
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
        if link_alias(primary, &link_path, assume_yes)? {
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
fn link_alias(target: &Path, link: &Path, assume_yes: bool) -> Result<bool, String> {
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
            if !prompt_yes_no(&q) {
                eprintln!(
                    "Skipped alias {}",
                    link.file_name().unwrap_or_default().to_string_lossy()
                );
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
fn aliases_from_vdir(vdir: &Path) -> Vec<String> {
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
fn sweep_dangling_links(bin: &Path, root: &Path) -> usize {
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

/// Three-phase pipeline shared by `install` and `update`.
/// Phase A is serial (may prompt); Phase B is parallel; Phase C is serial.
///
/// All error messages are collected and printed in a single batch at the very
/// end — interleaving stdout (progress) with stderr (errors) was producing
/// out-of-order output, and Phase B failed bars stay visible in red anyway.
fn run_pipeline(
    ctx: &Ctx,
    opts: &InstallOptions,
    specs: Vec<(String, Spec)>,
    mut errors: Vec<String>,
) -> Result<(), String> {
    if specs.is_empty() {
        if errors.is_empty() {
            return Ok(());
        }
        for err in &errors {
            eprintln!("{err}");
        }
        return Err(format!("{} operation(s) failed", errors.len()));
    }

    let mut prepared: Vec<(String, ExtractJob)> = Vec::new();

    // ---- Phase A: serial preflight (fetch release, pick asset, prompt) ----
    for (label, spec) in specs {
        println!("Resolving {}...", spec.repo());
        let release = match fetch_release(ctx, &spec) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("unpin: {label}: {e}"));
                continue;
            }
        };
        match preflight_extract(
            ctx,
            spec,
            release,
            opts.assume_yes,
            opts.pick,
            opts.include_data,
        ) {
            Ok(job) => prepared.push((label, job)),
            Err(e) => {
                errors.push(format!("unpin: {label}: {e}"));
            }
        }
    }

    // ---- Phase B: parallel download + extract + verify ----
    let n_workers = pick_jobs(opts.jobs, prepared.len());
    let extract_results = parallel_extract(ctx, &prepared, n_workers);

    // ---- Phase C: serial linking + final summary (may prompt to overwrite) ----
    for ((label, job), result) in prepared.iter().zip(extract_results.into_iter()) {
        if let Err(e) = result {
            errors.push(format!("unpin: {label}: {e}"));
            continue;
        }
        match link_all_executables(&job.spec, &job.vdir, opts.assume_yes, opts.alias_mode) {
            Ok(summary) => {
                if summary.primary.is_empty() {
                    println!("Installed {} {}", job.spec.repo(), job.release.tag_name);
                } else {
                    println!(
                        "Installed {} {} ({})",
                        job.spec.repo(),
                        job.release.tag_name,
                        summary.primary.join(", ")
                    );
                }
                if !summary.aliases.is_empty() {
                    println!("  aliases: {}", summary.aliases.join(" "));
                }
                for note in &summary.notes {
                    println!("  note: {note}");
                }
            }
            Err(e) => {
                errors.push(format!("unpin: {label}: {e}"));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        for err in &errors {
            eprintln!("{err}");
        }
        Err(format!("{} operation(s) failed", errors.len()))
    }
}

fn pick_jobs(requested: u8, n_inputs: usize) -> usize {
    let req = if requested == 0 {
        4
    } else {
        requested as usize
    };
    req.min(n_inputs).max(1)
}

/// Run the parallel extract phase. Returns one Result per input, in input order.
///
/// Pre-adds every download bar to the `MultiProgress` on the main thread BEFORE
/// any worker starts. This is required by indicatif: a `ProgressBar` constructed
/// then ticked before being attached to a `MultiProgress` first writes its own
/// stderr lines, which remain in scrollback when the bar is later attached —
/// producing ghost copies. Configure first, tick later.
fn parallel_extract(
    ctx: &Ctx,
    prepared: &[(String, ExtractJob)],
    n_workers: usize,
) -> Vec<Result<(), String>> {
    let is_tty = io::stderr().is_terminal();
    let multi = if is_tty {
        MultiProgress::new()
    } else {
        MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
    };

    let mut results: Vec<Result<(), String>> = (0..prepared.len()).map(|_| Ok(())).collect();

    // Compute per-column widths so all bars share the same name/tag alignment.
    let (name_w, tag_w) = prepared.iter().filter(|(_, j)| j.asset.is_some()).fold(
        (0usize, 0usize),
        |(n, t), (_, j)| {
            (
                n.max(j.spec.name.chars().count()),
                t.max(j.release.tag_name.chars().count()),
            )
        },
    );

    // Pre-add bars for every job that needs a download. Cached jobs get None
    // (no slot, no bars). Jobs with a data companion get *two* bars — both are
    // added here so they ride together below cached-announce lines and so the
    // companion's bar exists when its worker spawns.
    //
    // multi.add MUST happen before set_style/set_prefix — those methods tick
    // the bar, and on a fresh `ProgressBar::new` the draw target is still the
    // default stderr writer. A tick there renders the bar directly to stderr
    // (showing "100%" because length=0/position=0), and that line stays in
    // scrollback when multi.add later swaps the target — producing one ghost
    // row per bar above the live render area.
    let bars: Vec<Option<(ProgressBar, Option<ProgressBar>)>> = prepared
        .iter()
        .map(|(_, job)| {
            let asset = job.asset.as_ref()?;
            let bar = multi.add(ProgressBar::new(0));
            bar.set_style(github::download_progress_style());
            bar.set_prefix(format!(
                "{:<name_w$}  {:<tag_w$}",
                job.spec.name, job.release.tag_name
            ));
            // Seed the bar with Asset.size as a fallback for CDNs that omit
            // Content-Length. download_stream_into prefers the server value
            // when it arrives, so this is purely a hint.
            if asset.size > 0 {
                bar.set_length(asset.size);
            }
            let cbar = job.companion.as_ref().map(|companion| {
                let cb = multi.add(ProgressBar::new(0));
                cb.set_style(github::download_progress_style());
                cb.set_prefix(format!(
                    "{:<name_w$}  {:<tag_w$}  (data)",
                    job.spec.name, job.release.tag_name
                ));
                if companion.size > 0 {
                    cb.set_length(companion.size);
                }
                cb
            });
            Some((bar, cbar))
        })
        .collect();

    // Announce cached jobs. In TTY mode use multi.println so it lands above
    // the bars; in non-TTY just print to stdout (multi is hidden there).
    for (_, job) in prepared {
        if job.asset.is_none() {
            let msg = format!(
                "Using {} {} (cached)",
                job.spec.repo(),
                job.release.tag_name
            );
            if is_tty {
                let _ = multi.println(msg);
            } else {
                println!("{msg}");
            }
        }
    }

    let (work_tx, work_rx) = mpsc::channel::<usize>();
    for (i, (_, job)) in prepared.iter().enumerate() {
        if job.asset.is_some() {
            work_tx.send(i).unwrap();
        }
    }
    drop(work_tx);
    let work_rx = std::sync::Mutex::new(work_rx);

    let (result_tx, result_rx) = mpsc::channel::<(usize, Result<(), String>)>();

    thread::scope(|s| {
        for _ in 0..n_workers {
            let multi_w = multi.clone();
            let result_tx_w = result_tx.clone();
            let work_rx_w = &work_rx;
            let prepared_w = prepared;
            let bars_w = &bars;
            s.spawn(move || {
                loop {
                    let i = match work_rx_w.lock().unwrap().recv() {
                        Ok(i) => i,
                        Err(_) => break,
                    };
                    let (_label, job) = &prepared_w[i];
                    let (bar, cbar) = bars_w[i]
                        .as_ref()
                        .expect("downloadable job has pre-added bars");
                    let result = do_extract(ctx, job, bar, cbar.as_ref(), &multi_w);
                    let _ = result_tx_w.send((i, result));
                }
            });
        }
        drop(result_tx);
        for (i, r) in result_rx {
            results[i] = r;
        }
    });

    results
}

fn find_checksum_url(assets: &[Asset], asset_name: &str) -> Option<String> {
    for suffix in [".sha256", ".sha256sum"] {
        let want = format!("{asset_name}{suffix}");
        if let Some(a) = assets.iter().find(|a| a.name == want) {
            return Some(a.browser_download_url.clone());
        }
    }
    None
}

fn fetch_expected_sha256(ctx: &Ctx, url: &str) -> Result<String, String> {
    let body = github::download(ctx, url)?;
    let text = std::str::from_utf8(&body).map_err(|e| format!("checksum body: {e}"))?;
    parse_sha256(text)
}

/// Extract a SHA-256 digest from a per-asset checksum file. Some projects ship
/// `<hex>  <filename>` (sha256sum format); others wrap the digest in prose
/// (e.g. ripgrep's "SHA256 hash of ...zip:\n<hex>\n"). We look for the first
/// run of >= 64 consecutive ASCII-hex chars — short hex-looking words ("SHA",
/// "of") are what tripped a naive scanner.
fn parse_sha256(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i - start >= 64 {
            return Ok(text[start..start + 64].to_ascii_lowercase());
        }
    }
    Err("malformed checksum file".into())
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
pub fn run(ctx: &Ctx, input: &str, args: &[String], pick: bool) -> Result<i32, String> {
    let spec = parse_spec(input)?;
    println!("Resolving {}...", spec.repo());
    let release = fetch_release(ctx, &spec)?;
    // `run` always includes data — bypassing it could leave the binary
    // non-functional (gvim/vim need share/), and `run` is the "just try it"
    // path where surprises are worst. Use `install --no-data` if you need a
    // bare binary on disk.
    let job = preflight_extract(ctx, spec.clone(), release.clone(), true, pick, true)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- classify_excluded ----

    #[test]
    fn classify_picks_up_other_os_assets() {
        // Test relies on host OS — the function uses platform::other_os_keys.
        #[cfg(target_os = "linux")]
        assert_eq!(
            classify_excluded("tool-darwin-x86_64.tar.gz"),
            Some("other platform")
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            classify_excluded("tool-windows-x86_64.zip"),
            Some("other platform")
        );
    }

    #[test]
    fn classify_filters_other_arch() {
        // On x86_64 we exclude aarch64 binaries.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(
            classify_excluded("tool-linux-aarch64.tar.gz"),
            Some("other arch")
        );
    }

    #[test]
    fn classify_excludes_auxiliary() {
        assert_eq!(
            classify_excluded("rg-14.1.0-linux.tar.gz.sha256"),
            Some("auxiliary")
        );
        assert_eq!(
            classify_excluded("rg-14.1.0-linux.tar.gz.sig"),
            Some("auxiliary")
        );
        assert_eq!(classify_excluded("rg-14.1.0.deb"), Some("auxiliary"));
        assert_eq!(classify_excluded("rg-14.1.0.rpm"), Some("auxiliary"));
        assert_eq!(classify_excluded("rg-14.1.0.appimage"), Some("auxiliary"));
    }

    #[test]
    fn classify_excludes_bsdiff() {
        assert_eq!(
            classify_excluded("update.bsdiff"),
            Some("unsupported format")
        );
    }

    #[test]
    fn classify_accepts_bare_zst_binary() {
        // unpins ships primary binaries as bare zstd (e.g. gvim-9.2-linux.zst).
        // Must not be rejected as "unsupported format" — archive.rs handles it.
        #[cfg(target_os = "linux")]
        assert_eq!(classify_excluded("gvim-9.2.0-x86_64-linux.zst"), None);
        // Windows `.exe.zst` on Linux gets rejected via auxiliary/other-platform keys.
        #[cfg(target_os = "linux")]
        assert!(classify_excluded("gvim-9.2.0-x86_64-windows.exe.zst").is_some());
    }

    #[test]
    fn classify_excludes_data_companion() {
        // <pkg>-<tag>-data.tar.zst is platform-agnostic runtime data, paired
        // with the primary asset in preflight. Not directly installable.
        assert_eq!(
            classify_excluded("gvim-9.2.0-data.tar.zst"),
            Some("data companion")
        );
        assert_eq!(
            classify_excluded("gvim-v9.2.0-data.tar.zst"),
            Some("data companion")
        );
        // Regular .tar.zst is not a companion — only the `-data.tar.zst` suffix.
        assert_ne!(
            classify_excluded("rg-linux.tar.zst"),
            Some("data companion")
        );
    }

    #[test]
    fn find_companion_matches_tagged_data_asset() {
        let assets = vec![
            Asset {
                name: "gvim-9.2.0-x86_64-linux.zst".into(),
                browser_download_url: "u1".into(),
                size: 0,
            },
            Asset {
                name: "gvim-9.2.0-x86_64-windows.exe.zst".into(),
                browser_download_url: "u2".into(),
                size: 0,
            },
            Asset {
                name: "gvim-9.2.0-data.tar.zst".into(),
                browser_download_url: "u3".into(),
                size: 0,
            },
        ];
        let c = find_companion("gvim", "v9.2.0", &assets).unwrap();
        assert_eq!(c.name, "gvim-9.2.0-data.tar.zst");
        // Same release without 'v' prefix in tag still matches the bare-version asset.
        let c2 = find_companion("gvim", "9.2.0", &assets).unwrap();
        assert_eq!(c2.name, "gvim-9.2.0-data.tar.zst");
    }

    #[test]
    fn find_companion_returns_none_when_absent() {
        let assets = vec![Asset {
            name: "tree-2.2.1-x86_64-linux.zst".into(),
            browser_download_url: "u".into(),
            size: 0,
        }];
        assert!(find_companion("tree", "v2.2.1", &assets).is_none());
    }

    #[test]
    fn classify_rejects_asset_with_no_os_tag() {
        // No "linux"/"darwin"/"windows" anywhere — can't tell what platform.
        #[cfg(target_os = "linux")]
        assert_eq!(classify_excluded("tool-generic.tar.gz"), Some("no OS tag"));
    }

    #[test]
    fn classify_accepts_current_os_asset() {
        #[cfg(target_os = "linux")]
        assert_eq!(classify_excluded("rg-14.1.0-x86_64-linux.tar.gz"), None);
        #[cfg(target_os = "macos")]
        assert_eq!(classify_excluded("rg-14.1.0-x86_64-darwin.tar.gz"), None);
    }

    // ---- short_binary_name ----

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
        // On Unix, .exe is preserved (not a special suffix). On Windows it
        // gets stripped before marker scanning. We can only test the Unix path
        // here directly; the cfg(windows) branch is exercised in cross builds.
        #[cfg(unix)]
        assert_eq!(short_binary_name("rg.exe"), "rg.exe");
        #[cfg(windows)]
        assert_eq!(short_binary_name("rg.exe"), "rg");
        #[cfg(windows)]
        assert_eq!(short_binary_name("rg-x86_64-pc-windows-gnu.exe"), "rg");
    }

    #[test]
    fn short_name_first_marker_wins() {
        // Earliest marker position wins, so we don't trim more than intended.
        assert_eq!(short_binary_name("rg-linux-amd64"), "rg");
    }

    // ---- parse_sha256 ----

    #[test]
    fn parse_sha256_accepts_sha256sum_format() {
        let body = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  rg.tar.gz\n";
        let got = parse_sha256(body).unwrap();
        assert_eq!(
            got,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn parse_sha256_handles_ripgrep_prose_format() {
        // This is the format that crashed the Windows install earlier.
        let body = "SHA256 hash of ripgrep-15.1.0-x86_64-pc-windows-gnu.zip:\r\n\
                    9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08\r\n";
        let got = parse_sha256(body).unwrap();
        assert_eq!(
            got,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn parse_sha256_lowercases_uppercase_hex() {
        let body = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        assert_eq!(
            parse_sha256(body).unwrap(),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
    }

    #[test]
    fn parse_sha256_rejects_short_runs() {
        // 63 hex chars — one short of a digest.
        let body = "a".repeat(63);
        assert!(parse_sha256(&body).is_err());
    }

    #[test]
    fn parse_sha256_rejects_empty_and_no_hex() {
        assert!(parse_sha256("").is_err());
        assert!(parse_sha256("no digest here").is_err());
        assert!(parse_sha256("SHA256 hash of foo.zip:").is_err());
    }

    #[test]
    fn parse_sha256_ignores_long_runs_after_first_match() {
        // First valid run wins — no ambiguity.
        let body = "1111111111111111111111111111111111111111111111111111111111111111\n\
                    2222222222222222222222222222222222222222222222222222222222222222";
        assert_eq!(
            parse_sha256(body).unwrap(),
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
    }

    // ---- pick_jobs ----

    #[test]
    fn pick_jobs_defaults_to_min_of_4_and_inputs() {
        assert_eq!(pick_jobs(0, 1), 1);
        assert_eq!(pick_jobs(0, 3), 3);
        assert_eq!(pick_jobs(0, 4), 4);
        assert_eq!(pick_jobs(0, 10), 4);
    }

    #[test]
    fn pick_jobs_honors_explicit_request_capped_by_inputs() {
        assert_eq!(pick_jobs(8, 3), 3);
        assert_eq!(pick_jobs(2, 10), 2);
    }

    #[test]
    fn pick_jobs_never_returns_zero() {
        // Defensive: even with 0 inputs the worker pool is at least 1 (the
        // pool exits immediately on empty channel).
        assert_eq!(pick_jobs(0, 0), 1);
        assert_eq!(pick_jobs(4, 0), 1);
    }
}
