//! Unified install/update pipeline (parallel preflight → parallel extract → link).
//!
//! `run_pipeline_v2` is the entry point shared by `install_many` and `update`.
//! `ExtractJob` is the carrier of state between phases — built by the
//! preflight pass, consumed by the extract workers, and (with its `_lock`
//! field) held alive until linking is complete. The dispatcher (main thread)
//! is the only place that prompts and acquires the per-repo lock; the
//! preflight pool stays pure network/compute and the extract pool stays
//! pure I/O.

use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use crate::aliases::AliasMode;
use crate::archive;
use crate::ctx::Ctx;
use crate::github::{self, Asset, ByteSink, Release};
use crate::platform::{self, Paths};
use crate::progress::{self, Reporter, Ui};

use super::asset::{
    ambiguous_assets_error, fetch_expected_sha256, find_checksum_url, find_companion,
    narrow_assets, pick_asset,
};
use super::job::{PipelineMode, PipelineRequest, PrepareOutcome, PromptKind, ResolutionData};
use super::linker::{LinkSummary, link_all_executables};
use super::prompt::PromptResult;
use super::spec::Spec;
use super::{RepoLock, active_version, fetch_release, prompt_yes_no};

/// Resolved per-invocation policy for one `install`/`update` call. Bundled
/// so the pipeline functions don't carry a five-arg tail of policy flags.
/// `main.rs` builds this from CLI args + config before entering install code.
pub struct InstallOptions {
    pub assume_yes: bool,
    /// Worker pool size for parallel preflight + extract. `0` means the
    /// default (4). `run_pipeline_v2` passes this through `pick_jobs` for
    /// both pools, capping at the number of input requests.
    pub jobs: u8,
    pub pick: bool,
    pub include_data: bool,
    pub alias_mode: AliasMode,
    /// Reinstall over a complete cache: bypass the `UpToDate`/`Cached`
    /// short-circuits so the package is re-downloaded and re-extracted.
    pub force: bool,
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
        force: bool,
        alias_override: Option<AliasMode>,
    ) -> Self {
        Self {
            assume_yes,
            jobs,
            pick,
            include_data: !no_data && ctx.cfg.data(),
            alias_mode: alias_override.unwrap_or_else(|| ctx.cfg.aliases()),
            force,
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

/// Which leg of an install the missing-checksum prompt is about. Drives the
/// warning text and the prompt question — primary asset vs. data companion.
enum ChecksumKind {
    Primary,
    Companion,
}

/// Resolve the published SHA-256 for one asset. Fetches the `.sha256` (or
/// `.sha256sum`) sidecar when present; falls back to either a stderr warning
/// (`-y`) or an interactive y/N prompt. Returns `Ok(None)` when the user
/// accepts running without verification.
fn resolve_checksum_for(
    ctx: &Ctx,
    assets: &[Asset],
    asset_name: &str,
    kind: ChecksumKind,
    assume_yes: bool,
) -> Result<Option<String>, String> {
    if let Some(url) = find_checksum_url(assets, asset_name) {
        return Ok(Some(fetch_expected_sha256(ctx, &url)?));
    }
    // No published checksum. `-y` (assume_yes) lets the user opt in
    // explicitly; without it we prompt (TTY) or refuse (non-TTY). Either
    // way, when we proceed we surface a stderr warning — the install/run
    // path otherwise looks identical to a verified one, which would hide
    // the trust gap from the user.
    let (data_tag, question, abort_msg) = match kind {
        ChecksumKind::Primary => (
            "",
            "No SHA-256 checksum found. Continue without verification?",
            "aborted: missing checksum",
        ),
        ChecksumKind::Companion => (
            " (data)",
            "Data companion has no SHA-256 checksum. Continue without verification?",
            "aborted: missing companion checksum",
        ),
    };
    if assume_yes {
        eprintln!(
            "warning: no SHA-256 checksum published for {asset_name}{data_tag}; downloading without verification"
        );
    } else if !prompt_yes_no(question) {
        return Err(abort_msg.into());
    }
    Ok(None)
}

/// Acquire the per-repo lock and tear down any leftover staging from a
/// previous attempt. The lock is held by the returned `RepoLock`; callers
/// place it in `ExtractJob._lock` so it lives through extract + linking.
fn prepare_workspace_dirs(
    paths: &Paths,
    spec: &Spec,
    vdir: &Path,
    extract_dir: &Path,
) -> Result<RepoLock, String> {
    // Acquire the cross-process lock *after* every user prompt (asset picker
    // AND the missing-checksum confirm) and *before* the first destructive
    // write. Holding it through a prompt would force a parallel install on the
    // same package to error out while the user is at coffee.
    let lock = RepoLock::acquire(&paths.repo_dir(&spec.owner, &spec.name))?;
    // --pick (or incomplete cache) on a cached version: wipe before re-extracting.
    // Also wipe a leftover `.part` from a previous run that got SIGKILL'd between
    // extract and rename — without this the second attempt would start from a
    // half-populated tree and `archive::extract` would error on the first entry
    // that collides.
    if vdir.is_dir() {
        fs::remove_dir_all(vdir).map_err(|e| format!("remove {}: {e}", vdir.display()))?;
    }
    if extract_dir.is_dir() {
        fs::remove_dir_all(extract_dir)
            .map_err(|e| format!("remove {}: {e}", extract_dir.display()))?;
    }
    Ok(lock)
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
    let vdir = ctx
        .paths
        .version_dir(&spec.owner, &spec.name, &release.tag_name);
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
    // Resolve checksums (network fetch + the missing-checksum y/n prompt)
    // BEFORE acquiring the repo lock. resolve_checksum_for may block on a
    // prompt; holding the cross-process lock across it would make a parallel
    // install/run on the same package error out while the user is deciding.
    // The asset picker above is likewise pre-lock. Mirrors run_pipeline_v2,
    // which resolves on a worker thread and only locks in finalize_resolution.
    let expected_sha256 = resolve_checksum_for(
        ctx,
        &release.assets,
        &asset.name,
        ChecksumKind::Primary,
        assume_yes,
    )?;
    let companion = if include_data {
        find_companion(&spec.name, &release.tag_name, &release.assets).cloned()
    } else {
        None
    };
    let companion_expected_sha256 = match companion.as_ref() {
        Some(c) => resolve_checksum_for(
            ctx,
            &release.assets,
            &c.name,
            ChecksumKind::Companion,
            assume_yes,
        )?,
        None => None,
    };
    // All prompts are done — now take the lock and clear stale staging, the
    // smallest window that still fully covers the destructive extract.
    let extract_dir = part_dir_for(&vdir);
    let lock = prepare_workspace_dirs(&ctx.paths, &spec, &vdir, &extract_dir)?;
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

/// Shared counters for the two concurrent legs of one extract. `companion`
/// carries the companion row's id (to clear/fail it) alongside its counters.
pub struct DlSinks {
    pub primary: Arc<dyn ByteSink>,
    pub companion: Option<(u64, Arc<dyn ByteSink>)>,
}

/// Join a scoped worker, re-raising its panic *as the original panic* rather
/// than the misleading "called `Result::unwrap()` on an `Err` value: Any { .. }"
/// that a plain `.join().unwrap()` produces. Under `panic = "abort"` (release)
/// a worker panic aborts before we get here; this only shapes the dev/unwind
/// build, but a real bug should surface its true message and location, not a
/// raw `Result::Err` dump.
fn join_or_resume<T>(h: thread::ScopedJoinHandle<'_, T>) -> T {
    h.join().unwrap_or_else(|e| std::panic::resume_unwind(e))
}

/// Orchestrate one ExtractJob: download+extract primary, and (if present)
/// data companion **concurrently** via `thread::scope`. They write disjoint
/// subtrees of the same `.part` staging tree (e.g. `bin/` vs `share/`), so
/// there's no contention.
///
/// The **companion** row is transient and finalized here (cleared on Ok,
/// frozen red on Err) via `ui.finish_companion`. The **primary** row is left
/// in its download state; the caller decides its final glyph (the pipeline
/// morphs it through Linking → Installed; the single-package `run` path calls
/// `Reporter::done_*` / `download_failed`).
///
/// Per-job cleanup (sigint hook + CleanupGuard) is armed against the
/// `.part` directory and only disarmed once `fs::rename(.part → vdir)`
/// succeeds. A failed extract — or a process-wide ctrl-c — leaves only
/// `.part` on disk, so the next `vdir.is_dir()` cache check correctly
/// classifies the package as not installed.
pub fn do_extract(ctx: &Ctx, job: &ExtractJob, ui: &Ui, sinks: &DlSinks) -> Result<(), String> {
    let Some(primary_asset) = job.asset.as_ref() else {
        return Ok(()); // cached
    };
    let rdir = ctx.paths.repo_dir(&job.spec.owner, &job.spec.name);
    fs::create_dir_all(&rdir).map_err(|e| format!("mkdir {}: {e}", rdir.display()))?;
    crate::sigint::push_cleanup(&job.extract_dir);
    let mut guard = CleanupGuard::arm(job.extract_dir.clone());

    let repo = job.spec.repo();
    let result = if let (Some(companion), Some((cid, csink))) =
        (job.companion.as_ref(), sinks.companion.as_ref())
    {
        // Run primary + companion in parallel. They write disjoint subtrees
        // (bin/ vs share/), so there's no contention; the join below
        // propagates the first error. CleanupGuard wipes the .part dir for
        // a clean retry. Each leg gets its own `Ui` clone — the live handle's
        // mpsc sender is `Send` but not `Sync`, so the two scoped threads
        // can't share a borrow of it.
        let (ui_p, ui_c) = (ui.clone(), ui.clone());
        let (r_prim, r_comp) = thread::scope(|s| {
            let h_prim = s.spawn(|| {
                download_extract_verify(
                    ctx,
                    &ui_p,
                    &repo,
                    false,
                    &sinks.primary,
                    primary_asset,
                    job.expected_sha256.as_deref(),
                    &job.extract_dir,
                )
            });
            let h_comp = s.spawn(|| {
                download_extract_verify(
                    ctx,
                    &ui_c,
                    &repo,
                    true,
                    csink,
                    companion,
                    job.companion_expected_sha256.as_deref(),
                    &job.extract_dir,
                )
            });
            (join_or_resume(h_prim), join_or_resume(h_comp))
        });
        // Companion row is transient — clear on success, freeze red on error.
        ui.finish_companion(*cid, r_comp.clone());
        r_prim.and(r_comp)
    } else {
        download_extract_verify(
            ctx,
            ui,
            &repo,
            false,
            &sinks.primary,
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

/// One download → extract → verify step against one [`ByteSink`]. **Row
/// finalization is the caller's responsibility** — this only drives byte
/// progress and returns the result. (`do_extract` finalizes the companion
/// row; the primary row is left for the outer pipeline to morph through
/// Linking → Installed.) The vdir is shared between primary and companion
/// calls — both tar streams write disjoint subtrees, so concurrent
/// invocations are safe.
#[allow(clippy::too_many_arguments)]
fn download_extract_verify(
    ctx: &Ctx,
    ui: &Ui,
    repo: &str,
    is_companion: bool,
    sink: &Arc<dyn ByteSink>,
    asset: &Asset,
    expected_sha256: Option<&str>,
    vdir: &Path,
) -> Result<(), String> {
    if ctx.verbose {
        // ui.log scrolls above the live block. In non-TTY mode the render
        // thread drops it; api_get URLs from Phase A still print via eprintln,
        // so the user sees what was resolved even when piping.
        ui.println(format!("  GET {}", asset.browser_download_url));
    }
    let stream = github::download_stream_into(ctx, &asset.browser_download_url, sink.clone())?;
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
    let got_bytes = sink.loaded();
    let got = hashing.finalize_hex();
    if let Some(expected) = expected_sha256 {
        if !got.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "checksum mismatch for {}: expected {expected}, got {got}",
                asset.name
            ));
        }
        if ctx.verbose {
            // The green ✓ already tells the user the download verified; a
            // standalone line would just be noise above the live block. Keep
            // the digest under -v, paired with the `GET` line above, for
            // anyone debugging *which* checksum was matched.
            let suffix = if is_companion { " (data)" } else { "" };
            ui.println(format!("  verified {repo}{suffix}  ({})", &expected[..16]));
        }
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
}

/// Finalize the single-package `run` download row from its extract result:
/// clear on success (the row vanishes; the binary then runs), or freeze it as
/// a red bar at the failure point on error. The pipeline manages its primary
/// rows directly so they can transition into Linking/Installed instead.
pub(super) fn finalize_primary_row(
    reporter: &Reporter,
    idx: usize,
    bytes: Arc<progress::RowBytes>,
    result: &Result<(), String>,
) {
    match result {
        Ok(()) => reporter.clear(idx),
        Err(e) => reporter.download_failed(idx, bytes, e.clone()),
    }
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

/// Pick the worker pool size for the preflight and extract pools. `0` means
/// the default (4); any explicit value is capped by `n_inputs` (a 16-worker
/// pool with 2 inputs would just leave 14 idle threads). Never returns 0 —
/// `thread::scope` with 0 spawn calls would deadlock on a non-empty channel.
fn pick_jobs(requested: u8, n_inputs: usize) -> usize {
    let req = if requested == 0 {
        4
    } else {
        usize::from(requested)
    };
    req.min(n_inputs).max(1)
}

/// Per-request outcome of the resolution stage. `UpToDate` and `Skipped`
/// finish the bar inline (no extract); `Cached`/`Ready` carry an
/// `ExtractJob` onward — the only difference is `Cached` has `asset: None`
/// so the extract worker short-circuits the download. `Skipped` is the
/// user-driven exit (`s` at a prompt or non-TTY auto-skip) — distinct
/// from `Failed`/`Err` because exit code is not affected.
enum Resolved {
    UpToDate(String),
    Cached(ExtractJob),
    Ready(ExtractJob),
    Skipped(String),
}

/// Unified install/update pipeline. One `MultiProgress` wraps the whole run;
/// every request gets a persistent per-package bar that morphs through
/// states (Queued → Resolving → Downloading → Linking → Installed / Skipped
/// / Failed).
///
/// Two worker pools run concurrently inside one `thread::scope`:
/// - **Preflight pool** (network-bound): fetch release + narrow assets +
///   fetch checksum sidecars for each request. Emits `PrepareOutcome` into
///   `prepared_rx` for the dispatcher.
/// - **Extract pool** (network + CPU): downloads + extracts a resolved
///   `ExtractJob`. Pulled from `extract_rx` as the dispatcher resolves
///   prompts and locks; reports back via `extract_done_rx` for linking.
///
/// The main thread is the dispatcher: it consumes `prepared_rx`, runs any
/// interactive prompts via `multi.suspend()`, acquires the per-repo lock,
/// then either finalizes the bar (up-to-date) or enqueues the job for the
/// extract pool. While the dispatcher is blocked in a prompt, extract
/// workers continue running for already-resolved packages. After the
/// preflight stream closes, the dispatcher drains `extract_done_rx` to
/// perform the link step (still serial; linking can also prompt).
///
/// `mode` controls one decision: under `Update`, a request whose
/// `active_version()` already matches the latest release tag finishes
/// silently as "up to date" and never touches the extract path. Under
/// `Install`, every request that resolves goes all the way through.
///
/// `pre_errors` carries non-fatal failures the caller already collected
/// (e.g. "name not installed" from `update`) so the final aggregated error
/// summary lists everything in one place.
pub fn run_pipeline_v2(
    ctx: &Ctx,
    opts: &InstallOptions,
    mode: PipelineMode,
    requests: Vec<PipelineRequest>,
    mut errors: Vec<String>,
) -> Result<(), String> {
    if requests.is_empty() {
        // No live block ever starts here, so any carried-in errors must be
        // spelled out.
        return finalize_errors(errors, false);
    }

    // One render thread owns the whole live block; every row starts Queued.
    let prefixes: Vec<String> = requests.iter().map(|r| r.label.clone()).collect();
    let (reporter, handle) = progress::start(prefixes);
    let ui = Ui::Live(reporter.clone());

    let n_workers = pick_jobs(opts.jobs, requests.len());

    // Channel topology (see module-level comment):
    //   work_tx -> preflight workers (idx)
    //   prepared_tx -> dispatcher (idx, outcome)
    //   extract_tx -> extract workers (idx, ExtractJob)
    //   extract_done_tx -> dispatcher (idx, ExtractJob, Result)
    let (work_tx, work_rx) = mpsc::channel::<usize>();
    for i in 0..requests.len() {
        work_tx.send(i).expect("work channel send");
    }
    drop(work_tx);
    let work_rx = Arc::new(Mutex::new(work_rx));

    let (prepared_tx, prepared_rx) = mpsc::channel::<(usize, Result<PrepareOutcome, String>)>();
    let (extract_tx, extract_rx) = mpsc::channel::<(usize, ExtractJob)>();
    let extract_rx = Arc::new(Mutex::new(extract_rx));
    let (extract_done_tx, extract_done_rx) =
        mpsc::channel::<(usize, ExtractJob, Result<(), String>)>();

    thread::scope(|s| {
        // ---- Preflight worker pool ----
        for _ in 0..n_workers {
            let work_rx = Arc::clone(&work_rx);
            let prepared_tx = prepared_tx.clone();
            let requests = &requests;
            let reporter = reporter.clone();
            s.spawn(move || {
                loop {
                    let idx = match work_rx.lock().unwrap().recv() {
                        Ok(i) => i,
                        Err(_) => break,
                    };
                    reporter.working(idx, "Resolving release...");
                    let outcome = preflight_resolve(ctx, &requests[idx].spec, mode, opts);
                    let _ = prepared_tx.send((idx, outcome));
                }
            });
        }
        drop(prepared_tx);

        // ---- Extract worker pool ----
        for _ in 0..n_workers {
            let extract_rx = Arc::clone(&extract_rx);
            let extract_done_tx = extract_done_tx.clone();
            let reporter = reporter.clone();
            let ui = ui.clone();
            s.spawn(move || {
                loop {
                    let (idx, job) = match extract_rx.lock().unwrap().recv() {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    // Switch the row to a live download (+ a transient
                    // companion row) and hand the shared counters to the
                    // download. Cached jobs never reach the extract pool.
                    let sinks = if let Some(asset) = job.asset.as_ref() {
                        let prefix = format!("{} {}", job.spec.name, job.release.tag_name);
                        let primary: Arc<dyn ByteSink> =
                            reporter.start_download(idx, prefix, asset.size);
                        let companion = job.companion.as_ref().map(|c| {
                            let cprefix =
                                format!("{} {} (data)", job.spec.name, job.release.tag_name);
                            let (cid, csink) = reporter.add_companion(cprefix, c.size);
                            (cid, csink as Arc<dyn ByteSink>)
                        });
                        DlSinks { primary, companion }
                    } else {
                        DlSinks {
                            primary: Arc::new(github::NoopSink),
                            companion: None,
                        }
                    };
                    let result = do_extract(ctx, &job, &ui, &sinks);
                    let _ = extract_done_tx.send((idx, job, result));
                }
            });
        }
        drop(extract_done_tx);

        // ---- Dispatcher (main thread) ----
        // Phase 1: consume preflight outcomes. May prompt (rendered below the
        // bars). Sends Ready jobs to extract pool; cached jobs link inline;
        // up-to-date / failed packages finalize their rows and skip extract.
        for (idx, outcome) in prepared_rx {
            let request = &requests[idx];
            match outcome {
                Err(e) => {
                    reporter.done_fail(idx, e.clone());
                    errors.push(format!("unpin: {}: {e}", request.label));
                }
                Ok(outcome) => {
                    match finalize_resolution(
                        ctx,
                        &request.spec,
                        outcome,
                        opts,
                        mode,
                        &ui,
                        &reporter,
                        idx,
                    ) {
                        Ok(Resolved::UpToDate(tag)) => {
                            reporter.done_skip(idx, format!("Up to date ({tag})"));
                        }
                        Ok(Resolved::Skipped(reason)) => {
                            // User-driven skip (typed `s` or non-TTY at a
                            // prompt). Non-fatal: row shows ⊘ but the process
                            // exit code is unaffected.
                            reporter.done_skip(idx, format!("Skipped: {reason}"));
                        }
                        Ok(Resolved::Cached(job)) => {
                            // No transient "Using cached" message — link_on_main
                            // immediately morphs the row to "Linking..." and the
                            // intermediate state would just flicker.
                            link_on_main(
                                &ctx.paths,
                                opts,
                                request,
                                &reporter,
                                idx,
                                &ui,
                                job,
                                &mut errors,
                            );
                        }
                        Ok(Resolved::Ready(job)) => {
                            let _ = extract_tx.send((idx, job));
                        }
                        Err(e) => {
                            reporter.done_fail(idx, e.clone());
                            errors.push(format!("unpin: {}: {e}", request.label));
                        }
                    }
                }
            }
        }
        drop(extract_tx);

        // Phase 2: drain extracted jobs and link them (or report extract
        // failure). Extract pool may still be running when we enter this
        // loop; the channel blocks the main thread on whichever job
        // finishes next. Linking is serial because it can itself prompt
        // (overwrite confirmations in linker.rs).
        for (idx, job, result) in extract_done_rx {
            let request = &requests[idx];
            match result {
                Ok(()) => link_on_main(
                    &ctx.paths,
                    opts,
                    request,
                    &reporter,
                    idx,
                    &ui,
                    job,
                    &mut errors,
                ),
                Err(e) => {
                    reporter.done_fail(idx, e.clone());
                    errors.push(format!("unpin: {}: {e}", request.label));
                }
            }
        }
    });

    handle.finish();
    // The live block drew a row per package only on a TTY; there it already
    // showed each failure, so suppress the redundant trailing dump.
    finalize_errors(errors, io::stderr().is_terminal())
}

/// Run the link phase for one job on the main thread. Called both for
/// cached jobs (no extract happened) and for jobs whose extract just
/// completed via the extract pool. Linker prompts (overwrite-link,
/// alias-ask) go through `multi.suspend` so the persistent bars don't
/// tear when the linker reads stdin.
#[allow(clippy::too_many_arguments)]
fn link_on_main(
    paths: &Paths,
    opts: &InstallOptions,
    request: &PipelineRequest,
    reporter: &Reporter,
    idx: usize,
    ui: &Ui,
    job: ExtractJob,
    errors: &mut Vec<String>,
) {
    // Reset the row from the download prefix back to the owner/repo label.
    reporter.set_prefix(idx, request.label.clone());
    reporter.working(idx, "Linking...");
    // Serialize all bin_dir writes across processes. The per-repo lock in
    // job._lock only covers this package's repo_dir; bin_dir is shared, so
    // another `unpin` linking a *different* package would otherwise race here.
    // Acquired after the repo lock (held since preflight) — order is always
    // repo → links — so it can't deadlock against another process.
    let _links = match platform::acquire_links_lock(&paths.data, || {
        ui.println("Waiting for another unpin process to finish updating links...");
    }) {
        Ok(l) => l,
        Err(e) => {
            mark_failed(reporter, idx, &e);
            errors.push(format!("unpin: {}: {e}", request.label));
            return;
        }
    };
    // Capture the currently-linked version BEFORE linking overwrites
    // bin/ symlinks — that's what makes the summary line read
    // "Updated v1 → v2" instead of just "Installed v2" on an upgrade.
    // A fresh install gets `None` here and falls back to "Installed".
    let previous = active_version(paths, &job.spec.owner, &job.spec.name);
    // A fresh download (asset present) whose `.sha256` sidecar was absent ran
    // without integrity verification. Surface that on the row itself — yellow
    // ⚠ "… (unverified)" — instead of a separate warning line.
    let unverified = (job.asset.is_some() && job.expected_sha256.is_none())
        || (job.companion.is_some() && job.companion_expected_sha256.is_none());
    match link_all_executables(
        paths,
        ui,
        &job.spec,
        &job.vdir,
        opts.assume_yes,
        opts.alias_mode,
    ) {
        Ok(summary) => {
            let msg = install_summary_message(
                previous.as_deref(),
                &job.release.tag_name,
                &job.spec.name,
                &summary,
            );
            if unverified {
                reporter.done_warn(idx, format!("{msg} (unverified)"));
            } else {
                reporter.done_ok(idx, msg);
            }
        }
        Err(e) => {
            mark_failed(reporter, idx, &e);
            errors.push(format!("unpin: {}: {e}", request.label));
        }
    }
}

/// Parallel-safe preflight: fetch release, narrow assets, fetch checksum
/// sidecars. Pure network/compute — never prompts, never writes to disk,
/// never acquires a lock. Workers run this concurrently for different
/// requests; the dispatcher serializes any follow-up that requires user
/// input or destructive FS.
fn preflight_resolve(
    ctx: &Ctx,
    spec: &Spec,
    mode: PipelineMode,
    opts: &InstallOptions,
) -> Result<PrepareOutcome, String> {
    let release = fetch_release(ctx, spec)?;

    // Update-mode short-circuit: nothing changed → skip the whole pipeline
    // for this request. Read of bin_dir is pure; safe to call concurrently.
    // `--force` bypasses it so the package is re-extracted even when current.
    if matches!(mode, PipelineMode::Update) && !opts.force {
        let current = active_version(&ctx.paths, &spec.owner, &spec.name);
        if current.as_deref() == Some(release.tag_name.as_str()) {
            return Ok(PrepareOutcome::UpToDate(Box::new(release)));
        }
    }

    let vdir = ctx
        .paths
        .version_dir(&spec.owner, &spec.name, &release.tag_name);
    let companion_peek = if opts.include_data {
        find_companion(&spec.name, &release.tag_name, &release.assets)
    } else {
        None
    };
    let cache_complete = vdir.is_dir() && (companion_peek.is_none() || vdir.join("share").is_dir());
    if cache_complete && !opts.pick && !opts.force {
        return Ok(PrepareOutcome::Cached(Box::new(release)));
    }

    // Narrow the asset list. When --pick or remaining ambiguity, defer to
    // the dispatcher's AssetPicker prompt; otherwise we have a single
    // chosen asset and can fetch its checksum here on the worker thread.
    let candidates_ref = narrow_assets(&release.assets, &spec.name, opts.pick, ctx.verbose)?;
    if opts.pick || candidates_ref.len() > 1 {
        let candidates: Vec<Asset> = candidates_ref.into_iter().cloned().collect();
        let data = ResolutionData {
            release,
            asset: None,
            candidates,
            expected_sha256: None,
            companion: None,
            companion_expected_sha256: None,
            primary_checksum_missing: false,
            companion_checksum_missing: false,
        };
        return Ok(PrepareOutcome::NeedsPrompt(
            PromptKind::AssetPicker,
            Box::new(data),
        ));
    }

    let asset = candidates_ref[0].clone();
    let (expected_sha256, primary_checksum_missing) =
        match find_checksum_url(&release.assets, &asset.name) {
            Some(url) => (Some(fetch_expected_sha256(ctx, &url)?), false),
            None => (None, true),
        };
    let companion = if opts.include_data {
        find_companion(&spec.name, &release.tag_name, &release.assets).cloned()
    } else {
        None
    };
    let (companion_expected_sha256, companion_checksum_missing) = match companion.as_ref() {
        Some(c) => match find_checksum_url(&release.assets, &c.name) {
            Some(url) => (Some(fetch_expected_sha256(ctx, &url)?), false),
            None => (None, true),
        },
        None => (None, false),
    };

    let data = ResolutionData {
        release,
        asset: Some(asset),
        candidates: Vec::new(),
        expected_sha256,
        companion,
        companion_expected_sha256,
        primary_checksum_missing,
        companion_checksum_missing,
    };

    if primary_checksum_missing {
        Ok(PrepareOutcome::NeedsPrompt(
            PromptKind::MissingChecksum,
            Box::new(data),
        ))
    } else if companion_checksum_missing {
        Ok(PrepareOutcome::NeedsPrompt(
            PromptKind::MissingCompanionChecksum,
            Box::new(data),
        ))
    } else {
        Ok(PrepareOutcome::Ready(Box::new(data)))
    }
}

/// Dispatcher-side completion of a single preflight outcome: prompt if
/// needed, acquire the lock when transitioning to a real extract, build the
/// `ExtractJob`. Runs on the main thread (the only place prompts and lock
/// acquisition are allowed).
#[allow(clippy::too_many_arguments)]
fn finalize_resolution(
    ctx: &Ctx,
    spec: &Spec,
    outcome: PrepareOutcome,
    opts: &InstallOptions,
    mode: PipelineMode,
    ui: &Ui,
    reporter: &Reporter,
    idx: usize,
) -> Result<Resolved, String> {
    match outcome {
        PrepareOutcome::UpToDate(release) => Ok(Resolved::UpToDate(release.tag_name)),
        PrepareOutcome::Cached(release) => {
            match check_replace_active(&ctx.paths, spec, &release.tag_name, mode, opts, ui) {
                ReplaceDecision::Proceed => {}
                ReplaceDecision::Skip(reason) => return Ok(Resolved::Skipped(reason)),
            }
            // Cached jobs have no lock — preflight already saw a complete
            // vdir, so the extractor will short-circuit. Lock semantics
            // match the legacy preflight path.
            let vdir = ctx
                .paths
                .version_dir(&spec.owner, &spec.name, &release.tag_name);
            Ok(Resolved::Cached(ExtractJob {
                spec: spec.clone(),
                release: *release,
                extract_dir: vdir.clone(),
                vdir,
                asset: None,
                expected_sha256: None,
                companion: None,
                companion_expected_sha256: None,
                _lock: None,
            }))
        }
        PrepareOutcome::Ready(data) => {
            match check_replace_active(&ctx.paths, spec, &data.release.tag_name, mode, opts, ui) {
                ReplaceDecision::Proceed => {}
                ReplaceDecision::Skip(reason) => return Ok(Resolved::Skipped(reason)),
            }
            reporter.working(idx, "Preparing...");
            let job = into_extract_job(&ctx.paths, spec.clone(), *data)?;
            Ok(Resolved::Ready(job))
        }
        PrepareOutcome::NeedsPrompt(kind, mut data) => {
            reporter.working(idx, "Waiting for input...");
            match kind {
                PromptKind::AssetPicker => {
                    let items: Vec<String> = data
                        .candidates
                        .iter()
                        .map(|a| {
                            if a.size > 0 {
                                format!("{} ({})", a.name, progress::human_bytes(a.size))
                            } else {
                                a.name.clone()
                            }
                        })
                        .collect();
                    let header = if data.candidates.len() == 1 {
                        "Available asset:"
                    } else {
                        "Available assets:"
                    };
                    // Genuine ambiguity (>1 candidate) that we can't prompt for:
                    // fail loudly rather than letting `prompt_pick_with_skip`
                    // return Skip below, which would mark this an exit-0
                    // "skipped" — an explicit `install <repo>` would then look
                    // like it succeeded while installing nothing. An
                    // interactive cancel (Esc/q) still maps to a non-fatal skip.
                    if data.candidates.len() > 1 && !io::stdin().is_terminal() {
                        let names: Vec<String> =
                            data.candidates.iter().map(|a| a.name.clone()).collect();
                        return Err(ambiguous_assets_error(&names));
                    }
                    let chosen_idx = match ui.prompt_pick(header, &items) {
                        PromptResult::Got(i) => i,
                        PromptResult::Skip => {
                            return Ok(Resolved::Skipped("asset picker skipped".into()));
                        }
                    };
                    let chosen = data.candidates[chosen_idx].clone();
                    // Re-fetch checksums for the chosen asset (the parallel
                    // pass deferred this because the asset was unknown).
                    let (expected, primary_missing) =
                        match find_checksum_url(&data.release.assets, &chosen.name) {
                            Some(url) => (Some(fetch_expected_sha256(ctx, &url)?), false),
                            None => (None, true),
                        };
                    data.expected_sha256 = expected;
                    data.primary_checksum_missing = primary_missing;
                    let companion = if opts.include_data {
                        find_companion(&spec.name, &data.release.tag_name, &data.release.assets)
                            .cloned()
                    } else {
                        None
                    };
                    if let Some(c) = companion.as_ref() {
                        match find_checksum_url(&data.release.assets, &c.name) {
                            Some(url) => {
                                data.companion_expected_sha256 =
                                    Some(fetch_expected_sha256(ctx, &url)?);
                            }
                            None => {
                                data.companion_checksum_missing = true;
                            }
                        }
                    }
                    data.companion = companion;
                    data.asset = Some(chosen);
                }
                PromptKind::MissingChecksum | PromptKind::MissingCompanionChecksum => {}
            }

            // Cascade: handle missing-checksum prompts now (possibly fresh
            // from the picker resolution).
            if data.primary_checksum_missing {
                match resolve_missing_checksum_prompt(ui, ChecksumKind::Primary, opts.assume_yes) {
                    PromptResult::Got(true) => {}
                    PromptResult::Got(false) => {
                        return Err("aborted: missing checksum".into());
                    }
                    PromptResult::Skip => {
                        return Ok(Resolved::Skipped("missing checksum skipped".into()));
                    }
                }
                data.primary_checksum_missing = false;
            }
            if data.companion_checksum_missing {
                match resolve_missing_checksum_prompt(ui, ChecksumKind::Companion, opts.assume_yes)
                {
                    PromptResult::Got(true) => {}
                    PromptResult::Got(false) => {
                        return Err("aborted: missing companion checksum".into());
                    }
                    PromptResult::Skip => {
                        return Ok(Resolved::Skipped(
                            "missing companion checksum skipped".into(),
                        ));
                    }
                }
                data.companion_checksum_missing = false;
            }
            match check_replace_active(&ctx.paths, spec, &data.release.tag_name, mode, opts, ui) {
                ReplaceDecision::Proceed => {}
                ReplaceDecision::Skip(reason) => return Ok(Resolved::Skipped(reason)),
            }
            reporter.working(idx, "Preparing...");
            let job = into_extract_job(&ctx.paths, spec.clone(), *data)?;
            Ok(Resolved::Ready(job))
        }
    }
}

/// Whether `check_replace_active` cleared the request to proceed or the
/// user opted to skip it. Skip is distinct from a hard error: the bar gets
/// the yellow ⊘ Skipped style and the exit code is unaffected.
enum ReplaceDecision {
    Proceed,
    Skip(String),
}

/// Prompt before clobbering an existing install with a different version.
/// Fires only under `Install` mode when there's a currently-linked version
/// distinct from the requested tag. Update mode never fires this (the user
/// explicitly asked for the upgrade). `--yes` bypasses the prompt silently
/// — that matches the user contract: "instala o último, sem perguntar".
///
/// Returns `Proceed` to continue, or `Skip(reason)` when the user typed
/// `n`, `s`, or pressed Ctrl-D / piped stdin without `--yes`. Anything
/// short of a clear "yes" is a non-fatal skip — the user explicitly chose
/// not to clobber the existing install.
fn check_replace_active(
    paths: &Paths,
    spec: &Spec,
    requested_tag: &str,
    mode: PipelineMode,
    opts: &InstallOptions,
    ui: &Ui,
) -> ReplaceDecision {
    if mode != PipelineMode::Install || opts.assume_yes {
        return ReplaceDecision::Proceed;
    }
    let current = match active_version(paths, &spec.owner, &spec.name) {
        Some(c) => c,
        None => return ReplaceDecision::Proceed,
    };
    if current == requested_tag {
        return ReplaceDecision::Proceed;
    }
    let question = format!(
        "{}/{} {current} is already installed. Replace with {requested_tag}?",
        spec.owner, spec.name
    );
    match ui.prompt_yes_no(&question) {
        PromptResult::Got(true) => ReplaceDecision::Proceed,
        PromptResult::Got(false) | PromptResult::Skip => ReplaceDecision::Skip(format!(
            "kept {current} (use --yes to replace with {requested_tag})"
        )),
    }
}

/// Convert resolved data into an `ExtractJob`: acquires the per-repo lock
/// and wipes any stale `.part` / vdir. Runs on the main thread so lock
/// acquisition is serialized — no race between parallel preflight workers
/// trying to take the same lock.
fn into_extract_job(paths: &Paths, spec: Spec, data: ResolutionData) -> Result<ExtractJob, String> {
    let vdir = paths.version_dir(&spec.owner, &spec.name, &data.release.tag_name);
    let extract_dir = part_dir_for(&vdir);
    let lock = prepare_workspace_dirs(paths, &spec, &vdir, &extract_dir)?;
    Ok(ExtractJob {
        spec,
        release: data.release,
        vdir,
        extract_dir,
        asset: data.asset,
        expected_sha256: data.expected_sha256,
        companion: data.companion,
        companion_expected_sha256: data.companion_expected_sha256,
        _lock: Some(lock),
    })
}

/// Prompt (or warn under `-y`) when no `.sha256` sidecar exists for an
/// asset. Returns `Got(true)` to continue without verification, `Got(false)`
/// to abort the install with a hard error, or `Skip` (user typed `s` or
/// stdin is non-TTY) to mark the package as skipped — non-fatal.
fn resolve_missing_checksum_prompt(
    ui: &Ui,
    kind: ChecksumKind,
    assume_yes: bool,
) -> PromptResult<bool> {
    if assume_yes {
        // No separate warning line under -y: the missing-checksum fact is
        // folded into the package's final row instead (yellow ⚠
        // "… (unverified)"), so the live block stays one clean line per package.
        return PromptResult::Got(true);
    }
    let question = match kind {
        ChecksumKind::Primary => "No SHA-256 checksum found. Continue without verification?",
        ChecksumKind::Companion => {
            "Data companion has no SHA-256 checksum. Continue without verification?"
        }
    };
    ui.prompt_yes_no(question)
}

/// Compose the trailing "Installed v1.2.3 (binary names); aliases: ...; note: ..."
/// message that sits to the right of the green check-mark. Mirrors the
/// multi-line summary the legacy pipeline printed via `println!`, collapsed
/// onto one line so it fits a single progress row.
///
/// `previous` is whatever `active_version` returned just before linking ran
/// — when it differs from `tag` the verb becomes "Updated prev → tag" so a
/// version bump shows the upgrade direction inline on the bar. Same-tag
/// (cached or replace-active no-op) and fresh installs (`previous == None`)
/// keep reading as "Installed tag".
fn install_summary_message(
    previous: Option<&str>,
    tag: &str,
    name: &str,
    summary: &LinkSummary,
) -> String {
    let verb_phrase = match previous {
        Some(prev) if prev != tag => format!("Updated {prev} → {tag}"),
        _ => format!("Installed {tag}"),
    };
    // The `(binaries)` tail tells the user which commands landed on PATH — worth
    // showing when they differ from the package name (`coreutils` → `ls, cat`),
    // but pure noise when the lone binary *is* the package name (already in the
    // bar's prefix). Drop it in that case.
    let redundant = summary.primary == [name];
    let mut msg = if summary.primary.is_empty() || redundant {
        verb_phrase
    } else {
        format!("{verb_phrase} ({})", summary.primary.join(", "))
    };
    if !summary.aliases.is_empty() {
        msg.push_str(&format!("; aliases: {}", summary.aliases.join(" ")));
    }
    for note in &summary.notes {
        msg.push_str(&format!("; note: {note}"));
    }
    msg
}

/// Mark a per-package row as failed with the given message — the red ✗ state
/// stays on screen so the user sees what went wrong without scrolling back
/// through the final error summary.
fn mark_failed(reporter: &Reporter, idx: usize, msg: &str) {
    reporter.done_fail(idx, msg.to_string());
}

/// Turn the collected per-package failures into the run's exit status.
///
/// `rows_shown` is true when the live progress block was on screen (stderr is a
/// TTY): every failure here was already painted on its own row as a red ✗ with
/// the same message, so re-dumping them would print each one twice (the bug in
/// `a.png`). Only spell the errors out when there was no live block — piped
/// stderr — where the rows were never drawn. Either way `main` prints the
/// returned `Err` as the single "N operation(s) failed" summary line.
fn finalize_errors(errors: Vec<String>, rows_shown: bool) -> Result<(), String> {
    if errors.is_empty() {
        return Ok(());
    }
    if !rows_shown {
        for err in &errors {
            eprintln!("{err}");
        }
    }
    Err(format!("{} operation(s) failed", errors.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_or_resume_reraises_the_original_panic_not_an_err_dump() {
        // A plain `.join().unwrap()` would surface the worker panic as
        // "called `Result::unwrap()` on an `Err` value: Any { .. }". This
        // helper must instead re-raise the *original* payload verbatim.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silence the test-run stderr
        let caught = std::panic::catch_unwind(|| {
            thread::scope(|s| {
                let h = s.spawn(|| -> i32 { panic!("boom-original") });
                join_or_resume(h)
            })
        });
        std::panic::set_hook(prev);
        let payload = caught.expect_err("worker panic should propagate");
        let msg = payload
            .downcast_ref::<&str>()
            .copied()
            .expect("payload is the original &str panic message");
        assert_eq!(msg, "boom-original");
    }

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
