//! Three-phase install/update pipeline (preflight → parallel extract → link).
//!
//! `run_pipeline` is the entry point shared by `install_many` and `update`.
//! `ExtractJob` is the carrier of state between phases — built by the serial
//! preflight, consumed by the parallel workers, and (with its `_lock` field)
//! held alive until linking is complete. Subcommand-side glue (Phase A's
//! "Resolving" loop, Phase C's "Installed" summary) lives here too because
//! it shares all the same types.

use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget};

use crate::aliases::AliasMode;
use crate::archive;
use crate::ctx::Ctx;
use crate::github::{self, Asset, Release};

use super::asset::{fetch_expected_sha256, find_checksum_url, find_companion, pick_asset};
use super::linker::link_all_executables;
use super::spec::Spec;
use super::{RepoLock, fetch_release, prompt_yes_no, repo_dir, version_dir};

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

/// Result of the serial preflight: enough to extract+verify in a worker without
/// talking to the user. `None` for `expected_sha256` means user opted to skip
/// verification; `None` for `asset` means the package is already cached.
pub struct ExtractJob {
    pub spec: Spec,
    pub release: Release,
    /// Final on-disk location after a successful extract. Reads (linking,
    /// `run`'s exec) use this path. Set even for cached jobs.
    pub vdir: PathBuf,
    /// Sibling staging directory (`<vdir>.part`) that holds the partial tree
    /// while extraction is in progress. After all tasks succeed, `do_extract`
    /// renames `extract_dir` → `vdir` atomically. If the process is killed
    /// mid-extract (SIGKILL, OOM, power loss), only `.part` survives and the
    /// cache check `vdir.is_dir()` correctly classifies the package as not
    /// installed. Cached jobs leave this equal to `vdir` and never write.
    pub extract_dir: PathBuf,
    /// `None` → already cached, worker skips the download path entirely.
    pub asset: Option<Asset>,
    pub expected_sha256: Option<String>,
    /// Data tarball companion (e.g. `<pkg>-<tag>-data.tar.zst`) bundled with the
    /// release. Extracted into the same `extract_dir` after the primary.
    /// `None` for packages without runtime data (the common case).
    pub companion: Option<Asset>,
    pub companion_expected_sha256: Option<String>,
    /// Cross-process lock on the package's `repo_dir`. Held from preflight
    /// (right before the first destructive write) through the end of Phase C
    /// linking. `None` for cached jobs (no write happens, no lock needed).
    /// Field is private so the lock can only be released via Drop.
    _lock: Option<RepoLock>,
}

/// Append `.part` to the final component of `vdir`. The result is a sibling
/// path inside the same parent (same NTFS volume / same Unix filesystem), so
/// the trailing `fs::rename` to `vdir` is guaranteed to be cheap and atomic.
fn part_dir_for(vdir: &Path) -> PathBuf {
    let mut name = vdir.file_name().unwrap_or_default().to_os_string();
    name.push(".part");
    vdir.with_file_name(name)
}

/// Serial preflight: pick asset, resolve checksum, decide if download is needed.
/// May prompt the user (asset picker, missing-checksum confirmation).
pub fn preflight_extract(
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
            extract_dir: vdir.clone(),
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
    let lock = RepoLock::acquire(&repo_dir(&spec.owner, &spec.name))?;
    let extract_dir = part_dir_for(&vdir);
    // --pick (or incomplete cache) on a cached version: wipe before re-extracting.
    // Also wipe a leftover `.part` from a previous run that got SIGKILL'd between
    // extract and rename — without this the second attempt would start from a
    // half-populated tree and `archive::extract` would error on the first entry
    // that collides.
    if vdir.is_dir() {
        fs::remove_dir_all(&vdir).map_err(|e| format!("remove {}: {e}", vdir.display()))?;
    }
    if extract_dir.is_dir() {
        fs::remove_dir_all(&extract_dir)
            .map_err(|e| format!("remove {}: {e}", extract_dir.display()))?;
    }
    let expected_sha256 = match find_checksum_url(&release.assets, &asset.name) {
        Some(url) => Some(fetch_expected_sha256(ctx, &url)?),
        None => {
            // No published checksum. `-y` (assume_yes) lets the user opt in
            // explicitly; without it we prompt (TTY) or refuse (non-TTY).
            // Either way, when we proceed we surface a stderr warning — the
            // install/run path otherwise looks identical to a verified one,
            // which would hide the trust gap from the user.
            if assume_yes {
                eprintln!(
                    "warning: no SHA-256 checksum published for {}; downloading without verification",
                    asset.name
                );
            } else if !prompt_yes_no("No SHA-256 checksum found. Continue without verification?") {
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
                if assume_yes {
                    eprintln!(
                        "warning: no SHA-256 checksum published for {} (data); downloading without verification",
                        c.name
                    );
                } else if !prompt_yes_no(
                    "Data companion has no SHA-256 checksum. Continue without verification?",
                ) {
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
        extract_dir,
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
/// subtrees of the same `.part` staging tree (e.g. `bin/` vs `share/`), so
/// there's no contention. Bars must be pre-added to `multi` on the main
/// thread — see the comment in `parallel_extract` for why.
///
/// Per-job cleanup (sigint hook + CleanupGuard) is armed against the
/// `.part` directory and only disarmed once `fs::rename(.part → vdir)`
/// succeeds. A failed extract — or a process-wide ctrl-c — leaves only
/// `.part` on disk, so the next `vdir.is_dir()` cache check correctly
/// classifies the package as not installed.
pub fn do_extract(
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
    crate::sigint::push_cleanup(&job.extract_dir);
    let mut guard = CleanupGuard::arm(job.extract_dir.clone());

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
        // CleanupGuard then wipes the .part dir for a clean retry.
        let (r_prim, r_comp) = thread::scope(|s| {
            let h_prim = s.spawn(|| {
                download_extract_verify(
                    ctx,
                    &primary_ui,
                    primary_asset,
                    job.expected_sha256.as_deref(),
                    &job.extract_dir,
                )
            });
            let h_comp = s.spawn(|| {
                download_extract_verify(
                    ctx,
                    &companion_ui,
                    companion,
                    job.companion_expected_sha256.as_deref(),
                    &job.extract_dir,
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
            &job.extract_dir,
        )
    };

    let result = result.and_then(|()| {
        // Atomic publish step. The two paths are siblings under the same
        // parent dir (same filesystem on every supported OS), so rename is
        // a metadata-only operation — no half-rename window. After this
        // succeeds the package looks installed; before, it doesn't.
        fs::rename(&job.extract_dir, &job.vdir).map_err(|e| {
            format!(
                "rename {} -> {}: {e}",
                job.extract_dir.display(),
                job.vdir.display()
            )
        })
    });
    if result.is_ok() {
        crate::sigint::pop_cleanup(&job.extract_dir);
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

/// Three-phase pipeline shared by `install` and `update`.
/// Phase A is serial (may prompt); Phase B is parallel; Phase C is serial.
///
/// All error messages are collected and printed in a single batch at the very
/// end — interleaving stdout (progress) with stderr (errors) was producing
/// out-of-order output, and Phase B failed bars stay visible in red anyway.
pub fn run_pipeline(
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(pick_jobs(0, 0), 1);
        assert_eq!(pick_jobs(4, 0), 1);
    }

    #[test]
    fn part_dir_is_sibling_of_vdir() {
        // Rename's atomicity guarantee depends on this — the `.part` must
        // live under the same parent dir (same filesystem on every supported
        // platform) so `fs::rename` is metadata-only and uninterruptible.
        let v = PathBuf::from("/data/owner/repo/v1.2.3");
        let p = part_dir_for(&v);
        assert_eq!(p, PathBuf::from("/data/owner/repo/v1.2.3.part"));
        assert_eq!(p.parent(), v.parent());
    }

    #[test]
    fn part_dir_handles_dot_in_tag() {
        // The tag has dots (typical for semver). part_dir_for should append
        // `.part` to the whole file_name, not to the stem.
        let v = PathBuf::from("/data/o/r/14.1.0");
        assert_eq!(part_dir_for(&v).file_name().unwrap(), "14.1.0.part");
    }
}
