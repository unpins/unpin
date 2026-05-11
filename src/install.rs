use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget};

use crate::archive;
use crate::github::{self, Asset, Release};

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

pub fn data_dir() -> PathBuf {
    if let Ok(x) = env::var("XDG_DATA_HOME")
        && !x.is_empty()
    {
        return PathBuf::from(x).join("unpin");
    }
    PathBuf::from(env::var("HOME").unwrap_or_default()).join(".local/share/unpin")
}

pub fn bin_dir() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_default()).join(".local/bin")
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

/// Find which version dir holds the binaries currently linked into ~/.local/bin.
/// Returns the tag name. If no linked version found, returns the lexicographic
/// max of the existing version dirs (best-effort).
fn active_version(owner: &str, name: &str) -> Option<String> {
    let rdir = repo_dir(owner, name);
    let mut versions: Vec<String> = fs::read_dir(&rdir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    if versions.is_empty() {
        return None;
    }
    // Try to identify the version linked from bin_dir.
    if let Ok(bins) = fs::read_dir(bin_dir()) {
        for entry in bins.flatten() {
            if let Ok(target) = fs::read_link(entry.path())
                && let Ok(rel) = target.strip_prefix(&rdir)
                && let Some(first) = rel.components().next()
            {
                let v = first.as_os_str().to_string_lossy().into_owned();
                if versions.iter().any(|x| x == &v) {
                    return Some(v);
                }
            }
        }
    }
    versions.sort();
    versions.pop()
}

/// Classify an asset that should be excluded from the picker. Returns a short
/// human reason, or `None` if the asset is potentially installable.
fn classify_excluded(name_lower: &str) -> Option<&'static str> {
    const CROSS_PLATFORM: &[&str] = &[
        "darwin", "macos", "apple", "windows", " win", "win32", "win64",
        "freebsd", "openbsd", "netbsd",
    ];
    const OTHER_ARCH: &[&str] = &["i386", "i686", "armv7", "aarch64", "arm64"];
    const AUXILIARY: &[&str] = &[
        ".deb", ".rpm", ".appimage", ".7z", ".tar.bz2", ".sig", ".sha256",
        ".sha512", ".asc", ".pem", ".gpg", ".sbom", ".msi", ".exe",
    ];
    if CROSS_PLATFORM.iter().any(|k| name_lower.contains(k)) {
        return Some("other platform");
    }
    if OTHER_ARCH.iter().any(|k| name_lower.contains(k)) {
        return Some("other arch");
    }
    if AUXILIARY.iter().any(|k| name_lower.contains(k)) {
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
    if !name_lower.contains("linux") {
        return Some("not linux");
    }
    None
}

pub fn pick_asset<'a>(
    assets: &'a [Asset],
    repo_name: &str,
    force_pick: bool,
    verbose: bool,
) -> Result<&'a Asset, String> {
    let arch_keys = ["x86_64", "amd64", "x64"];

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
            "no matching Linux x86_64 asset.\nAvailable assets:\n{}",
            assets
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
    fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn ensure_executable(p: &Path) -> Result<(), String> {
    if is_executable(p) {
        return Ok(());
    }
    let mut perms = fs::metadata(p)
        .map_err(|e| format!("stat {}: {e}", p.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(p, perms).map_err(|e| format!("chmod {}: {e}", p.display()))
}

/// Strip trailing target-triple markers from a binary filename. Useful when
/// projects ship `tool-x86_64-linux-musl` and we want the link to be `tool`.
fn short_binary_name(name: &str) -> &str {
    const MARKERS: &[&str] = &[
        "-x86_64", "_x86_64", "-amd64", "_amd64", "-aarch64", "_aarch64", "-arm64", "_arm64",
        "-i686", "_i686", "-i386", "_i386", "-linux", "_linux", "-darwin", "_darwin", "-apple",
        "-pc-", "-musl", "-gnu",
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
    let parent = link.parent().ok_or("symlink has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;

    if let Ok(meta) = fs::symlink_metadata(link) {
        let managed = meta.file_type().is_symlink()
            && fs::read_link(link)
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
    symlink(target, link).map_err(|e| {
        format!("symlink {} -> {}: {e}", link.display(), target.display())
    })?;
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

/// Worker body: download + extract + verify. No prompts, no stdout/stderr;
/// progress is reported through the provided `ProgressBar` and `multi`-routed
/// log lines. Safe to call from a worker thread in `thread::scope`.
fn do_extract(job: &ExtractJob, bar: ProgressBar, multi: &MultiProgress) -> Result<(), String> {
    let Some(asset) = job.asset.as_ref() else {
        return Ok(()); // cached
    };

    let rdir = repo_dir(&job.spec.owner, &job.spec.name);
    fs::create_dir_all(&rdir).map_err(|e| format!("mkdir {}: {e}", rdir.display()))?;

    crate::sigint::push_cleanup(&job.vdir);
    let mut guard = CleanupGuard::arm(job.vdir.clone());

    bar.set_prefix(format!("{} {}", job.spec.name, job.release.tag_name));
    let stream = github::download_stream_into(&asset.browser_download_url, bar.clone())?;
    let mut hashing = HashingReader::new(stream);
    archive::extract(&asset.name, &mut hashing, &job.vdir)?;
    let got = hashing.finalize_hex();
    bar.finish_and_clear();

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
        let link = bin.join(short);
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
    let specs: Vec<(String, Spec)> = inputs
        .iter()
        .map(|s| parse_spec(s).map(|sp| (s.clone(), sp)))
        .collect::<Result<_, _>>()?;
    run_pipeline(specs, assume_yes, jobs, pick, verbose)
}

/// Three-phase pipeline shared by `install` and `update`.
/// Phase A is serial (may prompt); Phase B is parallel; Phase C is serial.
fn run_pipeline(
    specs: Vec<(String, Spec)>,
    assume_yes: bool,
    jobs: u8,
    pick: bool,
    verbose: bool,
) -> Result<(), String> {
    if specs.is_empty() {
        return Ok(());
    }

    let mut last_err: Option<String> = None;
    let mut prepared: Vec<(String, ExtractJob)> = Vec::new();

    // ---- Phase A: serial preflight (fetch release, pick asset, prompt) ----
    for (label, spec) in specs {
        println!("Resolving {}...", spec.repo());
        let release = match fetch_release(&spec) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("unpin: {label}: {e}");
                last_err = Some(e);
                continue;
            }
        };
        match preflight_extract(spec, release, assume_yes, pick, verbose) {
            Ok(job) => prepared.push((label, job)),
            Err(e) => {
                eprintln!("unpin: {label}: {e}");
                last_err = Some(e);
            }
        }
    }

    // ---- Phase B: parallel download + extract + verify ----
    let n_workers = pick_jobs(jobs, prepared.len());
    let extract_results = parallel_extract(&prepared, n_workers);

    // ---- Phase C: serial linking + final summary (may prompt to overwrite) ----
    for ((label, job), result) in prepared.iter().zip(extract_results.into_iter()) {
        if let Err(e) = result {
            eprintln!("unpin: {label}: {e}");
            last_err = Some(e);
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
                eprintln!("unpin: {label}: {e}");
                last_err = Some(e);
            }
        }
    }

    match last_err {
        Some(e) => Err(format!("one or more operations failed (last: {e})")),
        None => Ok(()),
    }
}

fn pick_jobs(requested: u8, n_inputs: usize) -> usize {
    let req = if requested == 0 { 4 } else { requested as usize };
    req.min(n_inputs).max(1)
}

/// Run the parallel extract phase. Returns one Result per input, in input order.
/// Spawns N worker threads pulling from a shared work queue. Cached jobs are
/// resolved inline; only ones with `asset: Some(_)` are dispatched to workers.
fn parallel_extract(prepared: &[(String, ExtractJob)], n_workers: usize) -> Vec<Result<(), String>> {
    let multi = if io::stderr().is_terminal() {
        MultiProgress::new()
    } else {
        MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
    };

    let mut results: Vec<Result<(), String>> =
        (0..prepared.len()).map(|_| Ok(())).collect();

    // Feed indices needing real work into a channel; workers pull one at a time.
    // Cached jobs are announced upfront (before any bar exists, so println is safe).
    let (work_tx, work_rx) = mpsc::channel::<usize>();
    for (i, (_, job)) in prepared.iter().enumerate() {
        if job.asset.is_some() {
            work_tx.send(i).unwrap();
        } else {
            println!("Using {} {} (cached)", job.spec.repo(), job.release.tag_name);
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
            s.spawn(move || loop {
                let i = match work_rx_w.lock().unwrap().recv() {
                    Ok(i) => i,
                    Err(_) => break,
                };
                let (_label, job) = &prepared_w[i];
                let bar = multi_w.add(ProgressBar::new(0));
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
    let mut hex = String::with_capacity(64);
    for c in text.chars() {
        if hex.len() == 64 {
            break;
        }
        if c.is_ascii_hexdigit() {
            hex.push(c.to_ascii_lowercase());
        } else if !hex.is_empty() {
            break;
        }
    }
    if hex.len() != 64 {
        return Err("malformed checksum file".into());
    }
    Ok(hex)
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
                .filter_map(|e| fs::read_link(e.path()).ok())
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

pub fn remove_many(names: &[String]) -> Result<(), String> {
    let mut last_err: Option<String> = None;
    for name in names {
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
            if let Ok(target) = fs::read_link(&path)
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
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            let r = resolve_installed(n)?
                .ok_or_else(|| format!("not installed: {n}"))?;
            out.push(r);
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
    let mut last_err: Option<String> = None;
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
                eprintln!("unpin: {}/{}: {e}", owner, repo);
                last_err = Some(e);
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

    if let Err(e) = run_pipeline(specs, assume_yes, jobs, pick, verbose) {
        last_err = Some(e);
    }
    match last_err {
        Some(e) => Err(format!("one or more updates failed (last: {e})")),
        None => Ok(()),
    }
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

pub fn info(input: &str) -> Result<(), String> {
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
                if let Ok(target) = fs::read_link(&path)
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
            let target = match fs::read_link(&path) {
                Ok(t) => t,
                Err(_) => continue,
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

    // Orphan version dirs: no live symlink in bin_dir points into them.
    let linked_targets: Vec<PathBuf> = fs::read_dir(&bin)
        .map(|it| {
            it.flatten()
                .filter_map(|e| fs::read_link(e.path()).ok())
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
        // Single bar, stand-alone (no MultiProgress needed for one job).
        let multi = if io::stderr().is_terminal() {
            MultiProgress::new()
        } else {
            MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
        };
        let bar = multi.add(ProgressBar::new(0));
        do_extract(&job, bar, &multi)?;
    }
    if was_cached {
        let has_links = fs::read_dir(bin_dir())
            .map(|it| {
                it.flatten().any(|e| {
                    fs::read_link(e.path())
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
    if let Some(code) = status.code()
        && code != 0
    {
        std::process::exit(code);
    }
    Ok(())
}
