use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget};

use crate::archive;
use crate::github::{self, Asset, Release};
use crate::platform;

#[derive(Clone)]
pub struct Spec {
    pub owner: String,
    pub name: String,
    pub version: Option<String>,
}

impl Spec {
    fn repo(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

pub fn parse_spec(input: &str) -> Result<Spec, String> {
    let (base, version) = match input.split_once('@') {
        Some((b, v)) => (b, Some(v.to_owned())),
        None => (input, None),
    };
    if let Some((owner, name)) = base.split_once('/') {
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return Err(format!("invalid package spec: `{input}`"));
        }
        return Ok(Spec {
            owner: owner.to_owned(),
            name: name.to_owned(),
            version,
        });
    }
    if base.is_empty() {
        return Err("empty package name".into());
    }
    Ok(Spec {
        owner: "unpins".to_owned(),
        name: base.to_owned(),
        version,
    })
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
    if platform::other_os_keys().iter().any(|k| name_lower.contains(k)) {
        return Some("other platform");
    }
    if platform::other_arch_keys().iter().any(|k| name_lower.contains(k)) {
        return Some("other arch");
    }
    if platform::auxiliary_keys().iter().any(|k| name_lower.contains(k)) {
        return Some("auxiliary");
    }
    if name_lower.contains(".bsdiff") {
        return Some("unsupported format");
    }
    // Bare `.zst` (not `.tar.zst`) is single-stream compression; we only handle
    // the tar-zst container.
    if name_lower.ends_with(".zst") && !name_lower.ends_with(".tar.zst") {
        return Some("unsupported format");
    }
    if !platform::current_os_keys().iter().any(|k| name_lower.contains(k)) {
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
    for (i, a) in candidates.iter().enumerate() {
        println!("  [{}] {}", i + 1, a.name);
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

fn fetch_release(spec: &Spec) -> Result<Release, String> {
    let repo = spec.repo();
    match &spec.version {
        Some(tag) => github::fetch_tag(&repo, tag),
        None => github::fetch_latest(&repo),
    }
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
}

/// Serial preflight: pick asset, resolve checksum, decide if download is needed.
/// May prompt the user (asset picker, missing-checksum confirmation).
fn preflight_extract(
    spec: Spec,
    release: Release,
    assume_yes: bool,
    pick: bool,
    verbose: bool,
) -> Result<ExtractJob, String> {
    let vdir = version_dir(&spec.owner, &spec.name, &release.tag_name);
    if vdir.is_dir() && !pick {
        return Ok(ExtractJob {
            spec,
            release,
            vdir,
            asset: None,
            expected_sha256: None,
        });
    }
    let asset = pick_asset(&release.assets, &spec.name, pick, verbose)?.clone();
    // --pick on a cached version: wipe before re-extracting the chosen asset.
    if vdir.is_dir() {
        fs::remove_dir_all(&vdir)
            .map_err(|e| format!("remove {}: {e}", vdir.display()))?;
    }
    let expected_sha256 = match find_checksum_url(&release.assets, &asset.name) {
        Some(url) => Some(fetch_expected_sha256(&url)?),
        None => {
            if !assume_yes
                && !prompt_yes_no("No SHA-256 checksum found. Continue without verification?")
            {
                return Err("aborted: missing checksum".into());
            }
            None
        }
    };
    Ok(ExtractJob {
        spec,
        release,
        vdir,
        asset: Some(asset),
        expected_sha256,
    })
}

/// Worker body: download + extract + verify. The bar must already be
/// registered with `multi` (pre-added on the main thread). Safe to call from a
/// worker thread in `thread::scope`.
///
/// On success the bar is cleared from the terminal. On failure the bar is
/// re-styled red, the reason is set as its message, and it is abandoned —
/// leaving the failure visible above any later output.
fn do_extract(job: &ExtractJob, bar: &ProgressBar, multi: &MultiProgress) -> Result<(), String> {
    let Some(asset) = job.asset.as_ref() else {
        return Ok(()); // cached
    };
    let result = do_extract_inner(job, asset, bar, multi);
    match &result {
        Ok(()) => bar.finish_and_clear(),
        Err(e) => {
            bar.set_style(github::download_error_style());
            bar.set_message(e.clone());
            bar.abandon();
        }
    }
    result
}

fn do_extract_inner(
    job: &ExtractJob,
    asset: &Asset,
    bar: &ProgressBar,
    multi: &MultiProgress,
) -> Result<(), String> {
    let rdir = repo_dir(&job.spec.owner, &job.spec.name);
    fs::create_dir_all(&rdir).map_err(|e| format!("mkdir {}: {e}", rdir.display()))?;

    crate::sigint::push_cleanup(&job.vdir);
    let mut guard = CleanupGuard::arm(job.vdir.clone());

    let stream = github::download_stream_into(&asset.browser_download_url, bar)?;
    let mut hashing = HashingReader::new(stream);
    archive::extract(&asset.name, &mut hashing, &job.vdir)?;
    let got = hashing.finalize_hex();

    if let Some(expected) = job.expected_sha256.as_ref() {
        if !got.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "checksum mismatch for {}: expected {expected}, got {got}",
                asset.name
            ));
        }
        let _ = multi.println(format!(
            "  verified {}  ({})",
            job.spec.repo(),
            &expected[..16]
        ));
    }

    crate::sigint::pop_cleanup(&job.vdir);
    guard.disarm();
    Ok(())
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

fn link_all_executables(spec: &Spec, vdir: &Path, assume_yes: bool) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    walk_files(vdir, &mut files).map_err(|e| format!("walk {}: {e}", vdir.display()))?;

    let mut executables: Vec<PathBuf> = files.iter().filter(|p| is_executable(p)).cloned().collect();
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
    let mut linked = Vec::new();
    for target in &executables {
        let basename = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("non-utf8 binary name")?;
        let short = short_binary_name(basename);
        let link = bin.join(platform::link_filename(short));
        if link_binary(target, &link, assume_yes)? {
            linked.push(short.to_owned());
        }
    }
    Ok(linked)
}

pub fn install_many(
    inputs: &[String],
    assume_yes: bool,
    jobs: u8,
    pick: bool,
    verbose: bool,
) -> Result<(), String> {
    let parsed: Vec<(String, Spec)> = inputs
        .iter()
        .map(|s| parse_spec(s).map(|sp| (s.clone(), sp)))
        .collect::<Result<_, _>>()?;
    // Dedup by (owner, name, version), preserving first-seen order: two
    // identical args (or two args that normalize to the same spec, e.g.
    // "ripgrep" and "unpins/ripgrep") would otherwise race on the same vdir
    // in the parallel phase. Linear scan is fine — N is the CLI arg count.
    let mut specs: Vec<(String, Spec)> = Vec::with_capacity(parsed.len());
    for (label, spec) in parsed {
        let dup = specs.iter().any(|(_, s)| {
            s.owner == spec.owner && s.name == spec.name && s.version == spec.version
        });
        if !dup {
            specs.push((label, spec));
        }
    }
    run_pipeline(specs, assume_yes, jobs, pick, verbose, Vec::new())
}

/// Three-phase pipeline shared by `install` and `update`.
/// Phase A is serial (may prompt); Phase B is parallel; Phase C is serial.
///
/// All error messages are collected and printed in a single batch at the very
/// end — interleaving stdout (progress) with stderr (errors) was producing
/// out-of-order output, and Phase B failed bars stay visible in red anyway.
fn run_pipeline(
    specs: Vec<(String, Spec)>,
    assume_yes: bool,
    jobs: u8,
    pick: bool,
    verbose: bool,
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
        let release = match fetch_release(&spec) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("unpin: {label}: {e}"));
                continue;
            }
        };
        match preflight_extract(spec, release, assume_yes, pick, verbose) {
            Ok(job) => prepared.push((label, job)),
            Err(e) => {
                errors.push(format!("unpin: {label}: {e}"));
            }
        }
    }

    // ---- Phase B: parallel download + extract + verify ----
    let n_workers = pick_jobs(jobs, prepared.len());
    let extract_results = parallel_extract(&prepared, n_workers);

    // ---- Phase C: serial linking + final summary (may prompt to overwrite) ----
    for ((label, job), result) in prepared.iter().zip(extract_results.into_iter()) {
        if let Err(e) = result {
            errors.push(format!("unpin: {label}: {e}"));
            continue;
        }
        match link_all_executables(&job.spec, &job.vdir, assume_yes) {
            Ok(linked) => {
                if linked.is_empty() {
                    println!("Installed {} {}", job.spec.repo(), job.release.tag_name);
                } else {
                    println!(
                        "Installed {} {} ({})",
                        job.spec.repo(),
                        job.release.tag_name,
                        linked.join(", ")
                    );
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
    let req = if requested == 0 { 4 } else { requested as usize };
    req.min(n_inputs).max(1)
}

/// Run the parallel extract phase. Returns one Result per input, in input order.
///
/// Pre-adds every download bar to the `MultiProgress` on the main thread BEFORE
/// any worker starts. This is required by indicatif: a `ProgressBar` constructed
/// then ticked before being attached to a `MultiProgress` first writes its own
/// stderr lines, which remain in scrollback when the bar is later attached —
/// producing ghost copies. Configure first, tick later.
fn parallel_extract(prepared: &[(String, ExtractJob)], n_workers: usize) -> Vec<Result<(), String>> {
    let is_tty = io::stderr().is_terminal();
    let multi = if is_tty {
        MultiProgress::new()
    } else {
        MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
    };

    let mut results: Vec<Result<(), String>> =
        (0..prepared.len()).map(|_| Ok(())).collect();

    // Compute per-column widths so all bars share the same name/tag alignment.
    let (name_w, tag_w) = prepared
        .iter()
        .filter(|(_, j)| j.asset.is_some())
        .fold((0usize, 0usize), |(n, t), (_, j)| {
            (n.max(j.spec.name.chars().count()), t.max(j.release.tag_name.chars().count()))
        });

    // Pre-add a bar for every job that needs a download. Cached jobs get None
    // (no slot, no bar). multi.add MUST happen before set_style/set_prefix —
    // those methods tick the bar, and on a fresh `ProgressBar::new` the draw
    // target is still the default stderr writer. A tick there renders the bar
    // directly to stderr (showing "100%" because length=0/position=0), and
    // that line stays in scrollback when multi.add later swaps the target —
    // producing one ghost row per bar above the live render area.
    let bars: Vec<Option<ProgressBar>> = prepared
        .iter()
        .map(|(_, job)| {
            job.asset.as_ref()?;
            let bar = multi.add(ProgressBar::new(0));
            bar.set_style(github::download_progress_style());
            bar.set_prefix(format!(
                "{:<name_w$}  {:<tag_w$}",
                job.spec.name, job.release.tag_name
            ));
            Some(bar)
        })
        .collect();

    // Announce cached jobs. In TTY mode use multi.println so it lands above
    // the bars; in non-TTY just print to stdout (multi is hidden there).
    for (_, job) in prepared {
        if job.asset.is_none() {
            let msg = format!("Using {} {} (cached)", job.spec.repo(), job.release.tag_name);
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
            s.spawn(move || loop {
                let i = match work_rx_w.lock().unwrap().recv() {
                    Ok(i) => i,
                    Err(_) => break,
                };
                let (_label, job) = &prepared_w[i];
                let bar = bars_w[i].as_ref().expect("downloadable job has a pre-added bar");
                let result = do_extract(job, bar, &multi_w);
                let _ = result_tx_w.send((i, result));
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

fn fetch_expected_sha256(url: &str) -> Result<String, String> {
    let body = github::download(url)?;
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

    let mut last_err: Option<String> = None;
    for name in &targets {
        if let Err(e) = remove_one(name) {
            eprintln!("unpin: {name}: {e}");
            last_err = Some(e);
        }
    }
    match last_err {
        Some(e) => Err(format!("one or more removes failed (last: {e})")),
        None => Ok(()),
    }
}

fn remove_one(name: &str) -> Result<(), String> {
    let (owner, repo) = resolve_installed(name)?
        .ok_or_else(|| format!("not installed: {name}"))?;
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

    if let Ok(entries) = fs::read_dir(bin_dir()) {
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

pub fn update(
    names: &[String],
    assume_yes: bool,
    jobs: u8,
    pick: bool,
    verbose: bool,
) -> Result<(), String> {
    let targets: Vec<(String, String)> = if names.is_empty() {
        installed_repos()
    } else {
        // Dedup, preserving first-seen order: `update foo foo` (or
        // `update foo unpins/foo`) would otherwise race on the same vdir.
        let mut out: Vec<(String, String)> = Vec::with_capacity(names.len());
        for n in names {
            let r = resolve_installed(n)?
                .ok_or_else(|| format!("not installed: {n}"))?;
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
        let release = match github::fetch_latest(&spec.repo()) {
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

    run_pipeline(specs, assume_yes, jobs, pick, verbose, errors)
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

pub fn info_many(inputs: &[String]) -> Result<(), String> {
    let mut last_err: Option<String> = None;
    for (i, input) in inputs.iter().enumerate() {
        if i > 0 {
            println!();
        }
        if let Err(e) = info(input) {
            eprintln!("unpin: {input}: {e}");
            last_err = Some(e);
        }
    }
    match last_err {
        Some(e) => Err(format!("one or more info lookups failed (last: {e})")),
        None => Ok(()),
    }
}

fn info(input: &str) -> Result<(), String> {
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
    let release = fetch_release(&spec)?;
    println!("Repo:    {}", spec.repo());
    println!("Version: {} (latest)", release.tag_name);
    if !release.published_at.is_empty() {
        println!("Date:    {}", &release.published_at[..release.published_at.len().min(10)]);
    }
    println!("Status:  not installed");
    match pick_asset(&release.assets, &spec.name, false, false) {
        Ok(a) => println!("Asset:   {}", a.name),
        Err(e) => println!("Asset:   (unresolved: {e})"),
    }
    Ok(())
}

pub fn prune() -> Result<(), String> {
    let mut removed = 0usize;

    let bin = bin_dir();
    let root = data_dir();
    if let Ok(entries) = fs::read_dir(&bin) {
        for entry in entries.flatten() {
            let path = entry.path();
            let target = match platform::read_link(&path) {
                Some(t) => t,
                None => continue,
            };
            if !target.starts_with(&root) {
                continue;
            }
            if fs::metadata(&target).is_err() && fs::remove_file(&path).is_ok() {
                println!("Removed dangling {}", path.display());
                removed += 1;
            }
        }
    }

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

    if removed == 0 {
        println!("Nothing to prune");
    }
    Ok(())
}

pub fn run(input: &str, args: &[String]) -> Result<(), String> {
    let spec = parse_spec(input)?;
    println!("Resolving {}...", spec.repo());
    let release = fetch_release(&spec)?;
    let was_cached = version_dir(&spec.owner, &spec.name, &release.tag_name).is_dir();
    let job = preflight_extract(spec.clone(), release.clone(), true, false, false)?;
    let vdir = job.vdir.clone();
    if !was_cached {
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
        do_extract(&job, &bar, &multi)?;
    }
    if was_cached {
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
        Some(0) => Ok(()),
        Some(code) => std::process::exit(code),
        None => {
            // Unix: child terminated by signal. Mirror shell convention 128+sig
            // so callers (CI, shell scripts) see a non-zero exit. On Windows
            // status.code() is always Some(_), so this branch is Unix-only in
            // practice — fall back to 1 anywhere else.
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                let sig = status.signal().unwrap_or(0);
                std::process::exit(128 + sig);
            }
            #[cfg(not(unix))]
            {
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_spec ----

    #[test]
    fn parse_spec_owner_repo() {
        let s = parse_spec("BurntSushi/ripgrep").unwrap();
        assert_eq!(s.owner, "BurntSushi");
        assert_eq!(s.name, "ripgrep");
        assert_eq!(s.version, None);
    }

    #[test]
    fn parse_spec_with_version() {
        let s = parse_spec("BurntSushi/ripgrep@14.1.0").unwrap();
        assert_eq!(s.owner, "BurntSushi");
        assert_eq!(s.name, "ripgrep");
        assert_eq!(s.version.as_deref(), Some("14.1.0"));
    }

    #[test]
    fn parse_spec_bare_name_defaults_to_unpins_owner() {
        let s = parse_spec("sgleam").unwrap();
        assert_eq!(s.owner, "unpins");
        assert_eq!(s.name, "sgleam");
        assert_eq!(s.version, None);
    }

    #[test]
    fn parse_spec_bare_name_with_version() {
        let s = parse_spec("sgleam@v0.7.0").unwrap();
        assert_eq!(s.owner, "unpins");
        assert_eq!(s.name, "sgleam");
        assert_eq!(s.version.as_deref(), Some("v0.7.0"));
    }

    #[test]
    fn parse_spec_rejects_empty() {
        assert!(parse_spec("").is_err());
        assert!(parse_spec("@1.0").is_err());
    }

    #[test]
    fn parse_spec_rejects_empty_owner_or_repo() {
        assert!(parse_spec("/repo").is_err());
        assert!(parse_spec("owner/").is_err());
    }

    #[test]
    fn parse_spec_rejects_extra_slashes() {
        // split_once splits on the FIRST '/', so "a/b/c" leaves "b/c" as repo —
        // rejected because repo contains '/'.
        assert!(parse_spec("a/b/c").is_err());
    }

    // ---- classify_excluded ----

    #[test]
    fn classify_picks_up_other_os_assets() {
        // Test relies on host OS — the function uses platform::other_os_keys.
        #[cfg(target_os = "linux")]
        assert_eq!(classify_excluded("tool-darwin-x86_64.tar.gz"), Some("other platform"));
        #[cfg(target_os = "linux")]
        assert_eq!(classify_excluded("tool-windows-x86_64.zip"), Some("other platform"));
    }

    #[test]
    fn classify_filters_other_arch() {
        // On x86_64 we exclude aarch64 binaries.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(classify_excluded("tool-linux-aarch64.tar.gz"), Some("other arch"));
    }

    #[test]
    fn classify_excludes_auxiliary() {
        assert_eq!(classify_excluded("rg-14.1.0-linux.tar.gz.sha256"), Some("auxiliary"));
        assert_eq!(classify_excluded("rg-14.1.0-linux.tar.gz.sig"), Some("auxiliary"));
        assert_eq!(classify_excluded("rg-14.1.0.deb"), Some("auxiliary"));
        assert_eq!(classify_excluded("rg-14.1.0.rpm"), Some("auxiliary"));
        assert_eq!(classify_excluded("rg-14.1.0.appimage"), Some("auxiliary"));
    }

    #[test]
    fn classify_excludes_bsdiff_and_bare_zst() {
        assert_eq!(classify_excluded("update.bsdiff"), Some("unsupported format"));
        assert_eq!(classify_excluded("payload.zst"), Some("unsupported format"));
        // .tar.zst is fine — caught by the OS-key check below, not unsupported.
        assert_ne!(classify_excluded("rg-linux.tar.zst"), Some("unsupported format"));
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
        assert_eq!(got, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    }

    #[test]
    fn parse_sha256_handles_ripgrep_prose_format() {
        // This is the format that crashed the Windows install earlier.
        let body = "SHA256 hash of ripgrep-15.1.0-x86_64-pc-windows-gnu.zip:\r\n\
                    9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08\r\n";
        let got = parse_sha256(body).unwrap();
        assert_eq!(got, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
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
