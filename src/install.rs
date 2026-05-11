use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::archive;
use crate::github::{self, Asset, Release};

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
    if let Ok(x) = env::var("XDG_DATA_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join("unpin");
        }
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
            if let Ok(target) = fs::read_link(entry.path()) {
                if let Ok(rel) = target.strip_prefix(&rdir) {
                    if let Some(first) = rel.components().next() {
                        let v = first.as_os_str().to_string_lossy().into_owned();
                        if versions.iter().any(|x| x == &v) {
                            return Some(v);
                        }
                    }
                }
            }
        }
    }
    versions.sort();
    versions.pop()
}

pub fn pick_asset<'a>(assets: &'a [Asset]) -> Result<&'a Asset, String> {
    let deny = [
        "darwin", "macos", "apple", "windows", " win", "win32", "win64", "freebsd", "openbsd",
        "netbsd", "i386", "i686", "armv7", "aarch64", "arm64", ".deb", ".rpm", ".appimage", ".7z",
        ".tar.bz2", ".sig", ".sha256", ".sha512", ".asc", ".pem", ".gpg", ".sbom",
        ".msi", ".exe",
    ];
    let arch_keys = ["x86_64", "amd64", "x64"];

    let linux_safe = |name: &str| -> bool {
        let l = name.to_ascii_lowercase();
        l.contains("linux") && !deny.iter().any(|k| l.contains(k))
    };

    let mut candidates: Vec<&Asset> = assets
        .iter()
        .filter(|a| {
            if !linux_safe(&a.name) {
                return false;
            }
            let l = a.name.to_ascii_lowercase();
            arch_keys.iter().any(|k| l.contains(k))
        })
        .collect();

    if candidates.is_empty() {
        candidates = assets.iter().filter(|a| linux_safe(&a.name)).collect();
    }

    match candidates.len() {
        0 => Err(format!(
            "no matching Linux x86_64 asset.\nAvailable assets:\n{}",
            assets
                .iter()
                .map(|a| format!("  {}", a.name))
                .collect::<Vec<_>>()
                .join("\n")
        )),
        1 => Ok(candidates[0]),
        _ => prompt_pick(&candidates),
    }
}

fn prompt_pick<'a>(candidates: &[&'a Asset]) -> Result<&'a Asset, String> {
    println!("Multiple matching assets:");
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

/// Download + verify + extract the release's asset into `<data>/<owner>/<repo>/<tag>/`.
/// Returns the absolute version_dir path. Skips network work if already extracted.
fn ensure_extracted(spec: &Spec, release: &Release, assume_yes: bool) -> Result<PathBuf, String> {
    let vdir = version_dir(&spec.owner, &spec.name, &release.tag_name);
    if vdir.is_dir() {
        return Ok(vdir);
    }

    let asset = pick_asset(&release.assets)?;
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

    let rdir = repo_dir(&spec.owner, &spec.name);
    fs::create_dir_all(&rdir).map_err(|e| format!("mkdir {}: {e}", rdir.display()))?;

    // Stream-extract directly into the version dir. The cleanup guard removes
    // the partial dir on any error/panic. Ctrl-C is handled separately by
    // crate::sigint, which also wipes the registered path.
    let _guard = CleanupGuard::arm(vdir.clone());
    crate::sigint::register_cleanup(&vdir);

    println!("Downloading {} ({})...", asset.name, release.tag_name);
    let stream = github::download_stream(&asset.browser_download_url)?;
    let mut hashing = HashingReader::new(stream);
    archive::extract(&asset.name, &mut hashing, &vdir)?;
    let got = hashing.finalize_hex();

    if let Some(expected) = expected_sha256 {
        if !got.eq_ignore_ascii_case(&expected) {
            return Err(format!(
                "checksum mismatch for {}: expected {expected}, got {got}",
                asset.name
            ));
        }
        println!("Verified SHA-256: {expected}");
    }

    crate::sigint::clear_cleanup();
    let mut g = _guard;
    g.disarm();
    Ok(vdir)
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

    let mut executables: Vec<PathBuf> = files.into_iter().filter(|p| is_executable(p)).collect();
    // If nothing has +x set (rare; some archives lose modes), promote any file
    // matching spec.name so the user still gets a working symlink.
    if executables.is_empty() {
        let mut fallback = Vec::new();
        walk_files(vdir, &mut fallback).map_err(|e| format!("walk {}: {e}", vdir.display()))?;
        if let Some(p) = fallback
            .iter()
            .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(&spec.name))
        {
            ensure_executable(p)?;
            executables.push(p.clone());
        }
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

pub fn install_many(inputs: &[String], assume_yes: bool) -> Result<(), String> {
    let mut last_err: Option<String> = None;
    for input in inputs {
        if let Err(e) = install_one(input, assume_yes) {
            eprintln!("unpin: {input}: {e}");
            last_err = Some(e);
        }
    }
    match last_err {
        Some(e) => Err(format!("one or more installs failed (last: {e})")),
        None => Ok(()),
    }
}

fn install_one(input: &str, assume_yes: bool) -> Result<(), String> {
    let spec = parse_spec(input)?;
    do_install(&spec, assume_yes)
}

fn do_install(spec: &Spec, assume_yes: bool) -> Result<(), String> {
    println!("Resolving {}...", spec.repo());
    let release = fetch_release(spec)?;
    let vdir = ensure_extracted(spec, &release, assume_yes)?;
    let linked = link_all_executables(spec, &vdir, assume_yes)?;
    if linked.is_empty() {
        println!("Installed {} {}", spec.repo(), release.tag_name);
    } else {
        println!(
            "Installed {} {} ({})",
            spec.repo(),
            release.tag_name,
            linked.join(", ")
        );
    }
    Ok(())
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
            if let Ok(target) = fs::read_link(&path) {
                if target.starts_with(&rdir) {
                    let _ = fs::remove_file(&path);
                }
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

pub fn update(names: &[String], assume_yes: bool) -> Result<(), String> {
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

    let mut last_err: Option<String> = None;
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
        if let Err(e) = do_install(&spec, assume_yes) {
            eprintln!("unpin: {owner}/{repo}: {e}");
            last_err = Some(e);
        }
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
                if let Ok(target) = fs::read_link(&path) {
                    if target.starts_with(&rdir) {
                        println!("  {} -> {}", path.display(), target.display());
                        any = true;
                    }
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
    match pick_asset(&release.assets) {
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
    let vdir = ensure_extracted(&spec, &release, true)?;
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
    if let Some(code) = status.code() {
        if code != 0 {
            std::process::exit(code);
        }
    }
    Ok(())
}
