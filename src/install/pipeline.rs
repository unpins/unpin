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

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget};

use crate::aliases::AliasMode;
use crate::archive;
use crate::ctx::Ctx;
use crate::github::{self, Asset, Release};
use crate::platform::{self, Paths};

use super::asset::{
    ambiguous_assets_error, fetch_expected_sha256, find_checksum_url, find_companion,
    narrow_assets, pick_asset,
};
use super::job::{PipelineMode, PipelineRequest, PrepareOutcome, PromptKind, ResolutionData};
use super::linker::{LinkSummary, link_all_executables};
use super::prompt::{PromptResult, prompt_pick_with_skip, prompt_yes_no_with_skip};
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
/// thread (a tick before `multi.add` writes a ghost row to stderr that
/// lingers in scrollback).
///
/// Bar finalization split: the **companion** bar is transient and finalized
/// here (cleared on Ok, red-abandoned on Err) — callers never need to touch
/// it. The **primary** bar is intentionally left in whatever state download
/// finished it (100% with the download style, or stopped mid-progress on
/// error). The caller decides its final state because primary bars in the
/// pipeline persist across phases (Resolving → Downloading → Linking →
/// Installed); the legacy single-package `run` path clears it after this
/// returns via `finalize_primary_bar`.
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
    let rdir = ctx.paths.repo_dir(&job.spec.owner, &job.spec.name);
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
        // Run primary + companion in parallel. They write disjoint subtrees
        // (bin/ vs share/), so there's no contention; the join below
        // propagates the first error. CleanupGuard wipes the .part dir for
        // a clean retry.
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
        // Companion bar is transient — finalize before returning.
        match &r_comp {
            Ok(()) => cbar.finish_and_clear(),
            Err(e) => {
                cbar.set_style(github::download_error_style());
                cbar.set_message(e.clone());
                cbar.abandon();
            }
        }
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
/// pre-adds the bar to a shared `MultiProgress`. **Bar finalization is the
/// caller's responsibility** — this function only drives byte progress and
/// returns the result. (`do_extract` finalizes the companion bar; the
/// primary bar is left for the outer pipeline to morph through Linking →
/// Installed.) The vdir is shared between primary and companion calls —
/// both tar streams write disjoint subtrees, so concurrent invocations
/// are safe.
fn download_extract_verify(
    ctx: &Ctx,
    ui: &ProgressContext,
    asset: &Asset,
    expected_sha256: Option<&str>,
    vdir: &Path,
) -> Result<(), String> {
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
}

/// Apply the legacy "primary bar finalize" policy to one bar based on a
/// completed extract result: clear-on-success, red-abandon-on-error. Used
/// by `mod.rs::run` (the single-package exec path); `run_pipeline_v2`
/// manages the primary bar directly so it can transition into the
/// Linking/Installed state instead of being cleared.
pub(super) fn finalize_primary_bar(bar: &ProgressBar, result: &Result<(), String>) {
    match result {
        Ok(()) => bar.finish_and_clear(),
        Err(e) => {
            bar.set_style(github::download_error_style());
            bar.set_message(e.clone());
            bar.abandon();
        }
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
/// Right-pad `s` with spaces to a display width of at least `w`.
fn pad_to(s: &str, w: usize) -> String {
    let cur = console::measure_text_width(s);
    if cur >= w {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + (w - cur));
    out.push_str(s);
    out.extend(std::iter::repeat_n(' ', w - cur));
    out
}

/// Keeps every bar's `{prefix}` padded to the same display width so the bar
/// column lines up across rows, *without* a hard-coded size. The widest prefix
/// seen so far is the target; the prefix text is variable (`label` while
/// queued, `name tag` while downloading) and is only known incrementally — the
/// pipeline has no resolve barrier — so when a wider prefix arrives we re-pad
/// the bars that are still live and the column self-corrects on the next tick.
/// Bars that already finished keep their last padding (indicatif freezes a
/// finished line); in practice the widest prefix appears during download, well
/// before any bar finishes, so the residual is rare and small.
struct PrefixAligner {
    state: Mutex<AlignState>,
}

struct AlignState {
    width: usize,
    /// Unpadded prefix per bar index; empty string means "not set yet".
    raw: Vec<String>,
}

impl PrefixAligner {
    fn new(n: usize) -> Self {
        PrefixAligner {
            state: Mutex::new(AlignState {
                width: 0,
                raw: vec![String::new(); n],
            }),
        }
    }

    /// Record bar `idx`'s unpadded prefix and apply the shared padding. A new
    /// maximum re-pads the other live bars; otherwise only this bar is touched.
    fn set(&self, bars: &[ProgressBar], idx: usize, raw: String) {
        let mut s = self.state.lock().unwrap();
        let w = console::measure_text_width(&raw);
        s.raw[idx] = raw;
        if w > s.width {
            s.width = w;
            let width = s.width;
            for (i, r) in s.raw.iter().enumerate() {
                if !r.is_empty() {
                    bars[i].set_prefix(pad_to(r, width));
                }
            }
        } else {
            bars[idx].set_prefix(pad_to(&s.raw[idx], s.width));
        }
    }

    /// Current alignment width — for transient bars (the data companion) that
    /// must sit no further left than the primaries but must not widen them.
    fn width(&self) -> usize {
        self.state.lock().unwrap().width
    }
}

pub fn run_pipeline_v2(
    ctx: &Ctx,
    opts: &InstallOptions,
    mode: PipelineMode,
    requests: Vec<PipelineRequest>,
    mut errors: Vec<String>,
) -> Result<(), String> {
    if requests.is_empty() {
        // No bars were created, so any inherited errors must be printed here.
        return finalize_errors(errors, false);
    }

    let is_tty = io::stderr().is_terminal();
    let multi = if is_tty {
        MultiProgress::new()
    } else {
        MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
    };

    // One persistent bar per request. Pre-add on the main thread BEFORE any
    // styling/messaging — a tick before `multi.add` writes a ghost row to
    // stderr that lingers in scrollback.
    let bars: Vec<ProgressBar> = requests
        .iter()
        .map(|_req| {
            let pb = multi.add(ProgressBar::new(0));
            pb.set_style(github::idle_style());
            pb.set_message("Queued");
            // Steady tick so the spinner actually animates during the
            // network-bound resolving/linking phases.
            pb.enable_steady_tick(std::time::Duration::from_millis(100));
            pb
        })
        .collect();

    // Pads every bar's `{prefix}` to a common width so the bar column lines up.
    // Seeded with the labels (known up front); download/link phases re-`set`
    // through it as the prefix changes to `name tag`.
    let aligner = PrefixAligner::new(requests.len());
    for (i, req) in requests.iter().enumerate() {
        aligner.set(&bars, i, req.label.clone());
    }

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
            let bars = &bars;
            let requests = &requests;
            s.spawn(move || {
                loop {
                    let idx = match work_rx.lock().unwrap().recv() {
                        Ok(i) => i,
                        Err(_) => break,
                    };
                    bars[idx].set_message("Resolving release...");
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
            let bars = &bars;
            let aligner = &aligner;
            let multi_ref = &multi;
            s.spawn(move || {
                loop {
                    let (idx, job) = match extract_rx.lock().unwrap().recv() {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    let pb = &bars[idx];
                    // Style the persistent bar for the download phase.
                    if let Some(asset) = job.asset.as_ref() {
                        pb.set_style(github::download_progress_style());
                        aligner.set(
                            bars,
                            idx,
                            format!("{} {}", job.spec.name, job.release.tag_name),
                        );
                        pb.set_position(0);
                        if asset.size > 0 {
                            pb.set_length(asset.size);
                        }
                    }
                    let cbar = job.companion.as_ref().map(|companion| {
                        let cb = multi_ref.add(ProgressBar::new(0));
                        cb.set_style(github::download_progress_style());
                        // Pad to the primaries' width but don't widen them: the
                        // " (data)" suffix already makes this the longest prefix.
                        cb.set_prefix(pad_to(
                            &format!("{} {} (data)", job.spec.name, job.release.tag_name),
                            aligner.width(),
                        ));
                        if companion.size > 0 {
                            cb.set_length(companion.size);
                        }
                        cb
                    });
                    let result = do_extract(ctx, &job, pb, cbar.as_ref(), multi_ref);
                    let _ = extract_done_tx.send((idx, job, result));
                }
            });
        }
        drop(extract_done_tx);

        // ---- Dispatcher (main thread) ----
        // Phase 1: consume preflight outcomes. May prompt (multi.suspend).
        // Sends Ready jobs to extract pool; cached jobs link inline; up-to-
        // date / failed packages finalize their bars and skip extract.
        for (idx, outcome) in prepared_rx {
            let request = &requests[idx];
            let pb = &bars[idx];
            match outcome {
                Err(e) => {
                    mark_failed(pb, &e);
                    errors.push(format!("unpin: {}: {e}", request.label));
                }
                Ok(outcome) => {
                    match finalize_resolution(ctx, &request.spec, outcome, opts, mode, &multi, pb) {
                        Ok(Resolved::UpToDate(tag)) => {
                            pb.set_style(github::done_skip_style());
                            pb.finish_with_message(format!("Up to date ({tag})"));
                        }
                        Ok(Resolved::Skipped(reason)) => {
                            // User-driven skip (typed `s` or non-TTY at a
                            // prompt). Non-fatal: bar shows ⊘ but the
                            // process exit code is unaffected.
                            pb.set_style(github::done_skip_style());
                            pb.finish_with_message(format!("Skipped: {reason}"));
                        }
                        Ok(Resolved::Cached(job)) => {
                            // No transient "Using cached" message — link_on_main
                            // immediately morphs the bar to "Linking..." and the
                            // intermediate state would just flicker.
                            link_on_main(
                                &ctx.paths,
                                opts,
                                request,
                                &LinkUi {
                                    bars: &bars,
                                    idx,
                                    aligner: &aligner,
                                    multi: &multi,
                                },
                                job,
                                &mut errors,
                            );
                        }
                        Ok(Resolved::Ready(job)) => {
                            let _ = extract_tx.send((idx, job));
                        }
                        Err(e) => {
                            mark_failed(pb, &e);
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
            let pb = &bars[idx];
            match result {
                Ok(()) => link_on_main(
                    &ctx.paths,
                    opts,
                    request,
                    &LinkUi {
                        bars: &bars,
                        idx,
                        aligner: &aligner,
                        multi: &multi,
                    },
                    job,
                    &mut errors,
                ),
                Err(e) => {
                    pb.set_style(github::done_fail_style());
                    pb.finish_with_message(e.clone());
                    errors.push(format!("unpin: {}: {e}", request.label));
                }
            }
        }
    });

    finalize_errors(errors, is_tty)
}

/// Per-request UI handles threaded into the link phase: the bar to drive
/// (`bars[idx]`), the shared `aligner` so a `set_prefix` keeps the column
/// aligned, and the `multi` for serialized `println`.
struct LinkUi<'a> {
    bars: &'a [ProgressBar],
    idx: usize,
    aligner: &'a PrefixAligner,
    multi: &'a MultiProgress,
}

/// Run the link phase for one job on the main thread. Called both for
/// cached jobs (no extract happened) and for jobs whose extract just
/// completed via the extract pool. Linker prompts (overwrite-link,
/// alias-ask) go through `multi.suspend` so the persistent bars don't
/// tear when the linker reads stdin.
fn link_on_main(
    paths: &Paths,
    opts: &InstallOptions,
    request: &PipelineRequest,
    ui: &LinkUi,
    job: ExtractJob,
    errors: &mut Vec<String>,
) {
    let pb = &ui.bars[ui.idx];
    let multi = ui.multi;
    pb.set_style(github::idle_style());
    // Back to the label for the final line (kept aligned via the shared width).
    ui.aligner.set(ui.bars, ui.idx, request.label.clone());
    pb.set_message("Linking...");
    // Serialize all bin_dir writes across processes. The per-repo lock in
    // job._lock only covers this package's repo_dir; bin_dir is shared, so
    // another `unpin` linking a *different* package would otherwise race here.
    // Acquired after the repo lock (held since preflight) — order is always
    // repo → links — so it can't deadlock against another process.
    let _links = match platform::acquire_links_lock(&paths.data, || {
        let _ = multi.println("Waiting for another unpin process to finish updating links...");
    }) {
        Ok(l) => l,
        Err(e) => {
            mark_failed(pb, &e);
            errors.push(format!("unpin: {}: {e}", request.label));
            return;
        }
    };
    // Capture the currently-linked version BEFORE linking overwrites
    // bin/ symlinks — that's what makes the summary line read
    // "Updated v1 → v2" instead of just "Installed v2" on an upgrade.
    // A fresh install gets `None` here and falls back to "Installed".
    let previous = active_version(paths, &job.spec.owner, &job.spec.name);
    match link_all_executables(
        paths,
        multi,
        &job.spec,
        &job.vdir,
        opts.assume_yes,
        opts.alias_mode,
    ) {
        Ok(summary) => {
            pb.set_style(github::done_ok_style());
            pb.finish_with_message(install_summary_message(
                previous.as_deref(),
                &job.release.tag_name,
                &summary,
            ));
        }
        Err(e) => {
            mark_failed(pb, &e);
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
fn finalize_resolution(
    ctx: &Ctx,
    spec: &Spec,
    outcome: PrepareOutcome,
    opts: &InstallOptions,
    mode: PipelineMode,
    multi: &MultiProgress,
    pb: &ProgressBar,
) -> Result<Resolved, String> {
    match outcome {
        PrepareOutcome::UpToDate(release) => Ok(Resolved::UpToDate(release.tag_name)),
        PrepareOutcome::Cached(release) => {
            match check_replace_active(&ctx.paths, spec, &release.tag_name, mode, opts, multi) {
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
            match check_replace_active(&ctx.paths, spec, &data.release.tag_name, mode, opts, multi)
            {
                ReplaceDecision::Proceed => {}
                ReplaceDecision::Skip(reason) => return Ok(Resolved::Skipped(reason)),
            }
            pb.set_message("Preparing...");
            let job = into_extract_job(&ctx.paths, spec.clone(), *data)?;
            Ok(Resolved::Ready(job))
        }
        PrepareOutcome::NeedsPrompt(kind, mut data) => {
            pb.set_message("Waiting for input...");
            match kind {
                PromptKind::AssetPicker => {
                    let items: Vec<String> = data
                        .candidates
                        .iter()
                        .map(|a| {
                            if a.size > 0 {
                                format!("{} ({})", a.name, indicatif::HumanBytes(a.size))
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
                    let chosen_idx = match prompt_pick_with_skip(multi, header, &items) {
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
                let asset_name = data
                    .asset
                    .as_ref()
                    .map(|a| a.name.clone())
                    .unwrap_or_default();
                match resolve_missing_checksum_prompt(
                    multi,
                    &asset_name,
                    ChecksumKind::Primary,
                    opts.assume_yes,
                ) {
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
                let cname = data
                    .companion
                    .as_ref()
                    .map(|c| c.name.clone())
                    .unwrap_or_default();
                match resolve_missing_checksum_prompt(
                    multi,
                    &cname,
                    ChecksumKind::Companion,
                    opts.assume_yes,
                ) {
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
            match check_replace_active(&ctx.paths, spec, &data.release.tag_name, mode, opts, multi)
            {
                ReplaceDecision::Proceed => {}
                ReplaceDecision::Skip(reason) => return Ok(Resolved::Skipped(reason)),
            }
            pb.set_message("Preparing...");
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
    multi: &MultiProgress,
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
    match prompt_yes_no_with_skip(multi, &question) {
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
    multi: &MultiProgress,
    asset_name: &str,
    kind: ChecksumKind,
    assume_yes: bool,
) -> PromptResult<bool> {
    let (data_tag, question) = match kind {
        ChecksumKind::Primary => (
            "",
            "No SHA-256 checksum found. Continue without verification?",
        ),
        ChecksumKind::Companion => (
            " (data)",
            "Data companion has no SHA-256 checksum. Continue without verification?",
        ),
    };
    if assume_yes {
        eprintln!(
            "warning: no SHA-256 checksum published for {asset_name}{data_tag}; downloading without verification"
        );
        return PromptResult::Got(true);
    }
    prompt_yes_no_with_skip(multi, question)
}

/// Compose the trailing "Installed v1.2.3 (binary names); aliases: ...; note: ..."
/// message that sits inside the green check-mark bar. Mirrors the multi-line
/// summary the legacy pipeline printed via `println!`, collapsed onto one
/// line so it fits an indicatif bar template.
///
/// `previous` is whatever `active_version` returned just before linking ran
/// — when it differs from `tag` the verb becomes "Updated prev → tag" so a
/// version bump shows the upgrade direction inline on the bar. Same-tag
/// (cached or replace-active no-op) and fresh installs (`previous == None`)
/// keep reading as "Installed tag".
fn install_summary_message(previous: Option<&str>, tag: &str, summary: &LinkSummary) -> String {
    let verb_phrase = match previous {
        Some(prev) if prev != tag => format!("Updated {prev} → {tag}"),
        _ => format!("Installed {tag}"),
    };
    let mut msg = if summary.primary.is_empty() {
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

/// Mark a per-package bar as failed with the given message. Bar is set to
/// the red ✗ style and finished — it stays on screen so the user sees what
/// went wrong without scrolling back through the final error summary.
fn mark_failed(pb: &ProgressBar, msg: &str) {
    pb.set_style(github::done_fail_style());
    pb.finish_with_message(msg.to_string());
}

/// Emit the collected per-package failures and return the aggregate error.
///
/// When the bars were visible (`bars_shown`, i.e. a TTY) each one already
/// finished with its own ✗ line on screen, so re-printing the same
/// `unpin: <pkg>: <err>` here would just duplicate it — only the aggregate is
/// returned. With bars hidden (piped/non-TTY) those lines are the sole record
/// of what failed, so they're printed.
fn finalize_errors(errors: Vec<String>, bars_shown: bool) -> Result<(), String> {
    if errors.is_empty() {
        return Ok(());
    }
    if !bars_shown {
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

    #[test]
    fn pad_to_right_pads_to_width_and_never_truncates() {
        assert_eq!(pad_to("jq", 5), "jq   ");
        assert_eq!(pad_to("htop", 4), "htop"); // exact width: untouched
        assert_eq!(pad_to("findutils", 5), "findutils"); // wider than target: untouched
        assert_eq!(pad_to("", 3), "   ");
    }

    #[test]
    fn prefix_aligner_width_grows_but_never_shrinks() {
        // The shared column tracks the widest prefix seen so far. It must only
        // grow: a later, narrower prefix (e.g. a bar reverting to its label
        // after download) can't pull the already-aligned column back left.
        let bars: Vec<ProgressBar> = (0..3).map(|_| ProgressBar::hidden()).collect();
        let a = PrefixAligner::new(3);
        a.set(&bars, 0, "jq".into());
        assert_eq!(a.width(), 2);
        a.set(&bars, 1, "findutils".into());
        assert_eq!(a.width(), 9);
        a.set(&bars, 2, "htop v3.4.1-1".into());
        assert_eq!(a.width(), 13);
        a.set(&bars, 0, "htop".into()); // narrower than the current max
        assert_eq!(a.width(), 13);
    }
}
