use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use nanoserde::{DeJson, SerJson};

use crate::aliases::{self, Alias};
use crate::archive;
use crate::github::{self, Asset, Release};

#[derive(SerJson, DeJson, Default)]
pub struct State {
    #[nserde(default)]
    pub packages: Vec<PackageEntry>,
}

#[derive(SerJson, DeJson, Clone)]
pub struct PackageEntry {
    pub name: String,
    pub repo: String,
    pub tag: String,
    pub asset: String,
    pub binary_paths: Vec<String>,
}

pub struct Spec {
    pub name: String,
    pub repo: String,
    pub alias: Option<&'static Alias>,
    pub version: Option<String>,
}

pub fn parse_spec(input: &str) -> Result<Spec, String> {
    let (base, version) = match input.split_once('@') {
        Some((b, v)) => (b, Some(v.to_owned())),
        None => (input, None),
    };
    if let Some(alias) = aliases::lookup(base) {
        return Ok(Spec {
            name: alias.name.to_owned(),
            repo: alias.repo.to_owned(),
            alias: Some(alias),
            version,
        });
    }
    if let Some((owner, repo)) = base.split_once('/') {
        if !owner.is_empty() && !repo.is_empty() && !repo.contains('/') {
            return Ok(Spec {
                name: repo.to_owned(),
                repo: base.to_owned(),
                alias: None,
                version,
            });
        }
    }
    Err(format!(
        "unknown package `{input}` (use owner/repo or a known alias)"
    ))
}

pub fn data_dir() -> PathBuf {
    if let Ok(x) = env::var("XDG_DATA_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join("ghp");
        }
    }
    PathBuf::from(env::var("HOME").unwrap_or_default())
        .join(".local/share/ghp")
}

pub fn bin_dir() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_default()).join(".local/bin")
}

fn state_path() -> PathBuf {
    data_dir().join("state.json")
}

fn packages_dir() -> PathBuf {
    data_dir().join("packages")
}

pub fn read_state() -> Result<State, String> {
    let p = state_path();
    if !p.exists() {
        return Ok(State::default());
    }
    let s = fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
    DeJson::deserialize_json(&s).map_err(|e| format!("parse {}: {e}", p.display()))
}

pub fn write_state(state: &State) -> Result<(), String> {
    let p = state_path();
    fs::create_dir_all(p.parent().unwrap())
        .map_err(|e| format!("mkdir {}: {e}", p.parent().unwrap().display()))?;
    let tmp = p.with_extension("json.new");
    fs::write(&tmp, state.serialize_json()).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &p).map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), p.display()))
}

pub fn pick_asset<'a>(assets: &'a [Asset], hint: Option<&str>) -> Result<&'a Asset, String> {
    let deny = [
        "darwin", "macos", "apple", "windows", " win", "win32", "win64", "freebsd",
        "openbsd", "netbsd", "i386", "i686", "armv7", "aarch64", "arm64",
        ".deb", ".rpm", ".appimage", ".zip", ".7z", ".tar.bz2", ".tar.zst",
        ".sig", ".sha256", ".sha512", ".asc", ".pem", ".gpg", ".sbom",
        ".msi", ".exe",
    ];
    let arch_keys = ["x86_64", "amd64", "x64"];

    let mut candidates: Vec<&Asset> = assets
        .iter()
        .filter(|a| {
            let l = a.name.to_ascii_lowercase();
            if !l.contains("linux") {
                return false;
            }
            if !arch_keys.iter().any(|k| l.contains(k)) {
                return false;
            }
            // Don't reject windows-style names that share substrings; check carefully.
            if deny.iter().any(|k| l.contains(k)) {
                return false;
            }
            true
        })
        .collect();

    if let Some(h) = hint {
        let hl = h.to_ascii_lowercase();
        let filtered: Vec<&Asset> = candidates
            .iter()
            .copied()
            .filter(|a| a.name.to_ascii_lowercase().contains(&hl))
            .collect();
        if !filtered.is_empty() {
            candidates = filtered;
        }
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

fn find_binaries(version_dir: &Path, spec: &Spec) -> Result<Vec<PathBuf>, String> {
    let mut all = Vec::new();
    walk_files(version_dir, &mut all)
        .map_err(|e| format!("walk {}: {e}", version_dir.display()))?;

    let wanted: Option<&[&'static str]> = spec.alias.map(|a| a.binaries);

    if let Some(names) = wanted {
        let mut found = Vec::with_capacity(names.len());
        for name in names {
            let m = all
                .iter()
                .find(|p| p.file_name().map(|n| n == *name).unwrap_or(false));
            match m {
                Some(p) => {
                    // Ensure executable bit set; if not, set it.
                    if !is_executable(p) {
                        let mut perms = fs::metadata(p)
                            .map_err(|e| format!("stat {}: {e}", p.display()))?
                            .permissions();
                        perms.set_mode(0o755);
                        fs::set_permissions(p, perms)
                            .map_err(|e| format!("chmod {}: {e}", p.display()))?;
                    }
                    found.push(p.clone());
                }
                None => return Err(format!("binary `{name}` not found in archive")),
            }
        }
        Ok(found)
    } else {
        let by_name: Vec<_> = all
            .iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n == spec.name)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        if by_name.len() == 1 {
            return Ok(by_name);
        }
        let executables: Vec<_> = all.iter().filter(|p| is_executable(p)).cloned().collect();
        if executables.len() == 1 {
            return Ok(executables);
        }
        Err(format!(
            "could not unambiguously identify a binary for `{}` (found {} executables). \
             Use an alias entry to specify `binaries`.",
            spec.name,
            executables.len()
        ))
    }
}

fn replace_symlink(target: &Path, link: &Path) -> Result<(), String> {
    let parent = link.parent().ok_or("symlink has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    let tmp_name = link.with_file_name(format!(
        "{}.new",
        link.file_name().unwrap().to_string_lossy()
    ));
    let _ = fs::remove_file(&tmp_name);
    symlink(target, &tmp_name).map_err(|e| {
        format!(
            "symlink {} -> {}: {e}",
            tmp_name.display(),
            target.display()
        )
    })?;
    fs::rename(&tmp_name, link)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp_name.display(), link.display()))
}

fn relative_to(base: &Path, full: &Path) -> Result<PathBuf, String> {
    full.strip_prefix(base)
        .map(|p| p.to_path_buf())
        .map_err(|_| {
            format!(
                "{} is not inside {}",
                full.display(),
                base.display()
            )
        })
}

fn fetch_release(spec: &Spec) -> Result<Release, String> {
    match &spec.version {
        Some(tag) => github::fetch_tag(&spec.repo, tag),
        None => github::fetch_latest(&spec.repo),
    }
}

pub fn install(input: &str) -> Result<(), String> {
    let spec = parse_spec(input)?;
    do_install(&spec)
}

fn do_install(spec: &Spec) -> Result<(), String> {
    println!("Resolving {} ({})...", spec.name, spec.repo);
    let release = fetch_release(spec)?;
    let hint = spec.alias.and_then(|a| a.asset_hint);
    let asset = pick_asset(&release.assets, hint)?;
    println!("Downloading {} ({})...", asset.name, release.tag_name);
    let bytes = github::download(&asset.browser_download_url)?;

    let pkg_root = packages_dir().join(&spec.name);
    fs::create_dir_all(&pkg_root)
        .map_err(|e| format!("mkdir {}: {e}", pkg_root.display()))?;

    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(&pkg_root)
        .map_err(|e| format!("tempdir in {}: {e}", pkg_root.display()))?;

    archive::extract(&asset.name, &bytes, staging.path())?;

    // Find binaries inside staging.
    let bin_paths_abs = find_binaries(staging.path(), spec)?;
    let bin_paths_rel: Vec<PathBuf> = bin_paths_abs
        .iter()
        .map(|p| relative_to(staging.path(), p))
        .collect::<Result<_, _>>()?;

    let version_dir = pkg_root.join(&release.tag_name);
    if version_dir.exists() {
        // Reinstall: nuke the old extraction.
        fs::remove_dir_all(&version_dir)
            .map_err(|e| format!("remove {}: {e}", version_dir.display()))?;
    }

    // Promote staging dir to the version dir (atomic same-fs rename).
    let staging_path = staging.keep();
    fs::rename(&staging_path, &version_dir).map_err(|e| {
        format!(
            "rename {} -> {}: {e}",
            staging_path.display(),
            version_dir.display()
        )
    })?;

    // Swap the `current` symlink (relative target).
    replace_symlink(Path::new(&release.tag_name), &pkg_root.join("current"))?;

    // Symlink each binary into ~/.local/bin/
    let bin_dir = bin_dir();
    let current_dir = pkg_root.join("current");
    let mut bin_names = Vec::with_capacity(bin_paths_rel.len());
    for rel in &bin_paths_rel {
        let target = current_dir.join(rel);
        let link_name = rel.file_name().ok_or("binary path has no file name")?;
        let link = bin_dir.join(link_name);
        replace_symlink(&target, &link)?;
        bin_names.push(link.file_name().unwrap().to_string_lossy().into_owned());
    }

    // Update state.
    let mut state = read_state()?;
    state.packages.retain(|p| p.name != spec.name);
    state.packages.push(PackageEntry {
        name: spec.name.clone(),
        repo: spec.repo.clone(),
        tag: release.tag_name.clone(),
        asset: asset.name.clone(),
        binary_paths: bin_paths_rel
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
    });
    state.packages.sort_by(|a, b| a.name.cmp(&b.name));
    write_state(&state)?;

    println!(
        "Installed {} {} ({} binaries: {})",
        spec.name,
        release.tag_name,
        bin_names.len(),
        bin_names.join(", ")
    );
    Ok(())
}

pub fn list() -> Result<(), String> {
    let state = read_state()?;
    if state.packages.is_empty() {
        println!("(no packages installed)");
        return Ok(());
    }
    let name_w = state.packages.iter().map(|p| p.name.len()).max().unwrap_or(0);
    let tag_w = state.packages.iter().map(|p| p.tag.len()).max().unwrap_or(0);
    for p in &state.packages {
        println!(
            "{:<name_w$}  {:<tag_w$}  {}",
            p.name,
            p.tag,
            p.repo,
            name_w = name_w,
            tag_w = tag_w
        );
    }
    Ok(())
}

pub fn remove(name: &str) -> Result<(), String> {
    let mut state = read_state()?;
    let idx = state
        .packages
        .iter()
        .position(|p| p.name == name)
        .ok_or_else(|| format!("not installed: {name}"))?;
    let entry = state.packages.remove(idx);

    let pkg_root = packages_dir().join(&entry.name);
    let bin_dir = bin_dir();
    for rel in &entry.binary_paths {
        let link_name = Path::new(rel).file_name().unwrap_or_default();
        let link = bin_dir.join(link_name);
        if let Ok(target) = fs::read_link(&link) {
            if target.starts_with(&pkg_root) {
                let _ = fs::remove_file(&link);
            }
        }
    }
    if pkg_root.exists() {
        fs::remove_dir_all(&pkg_root)
            .map_err(|e| format!("remove {}: {e}", pkg_root.display()))?;
    }
    write_state(&state)?;
    println!("Removed {}", name);
    Ok(())
}

pub fn update(names: &[String]) -> Result<(), String> {
    let state = read_state()?;
    let targets: Vec<PackageEntry> = if names.is_empty() {
        state.packages.clone()
    } else {
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            let p = state
                .packages
                .iter()
                .find(|p| &p.name == n)
                .ok_or_else(|| format!("not installed: {n}"))?;
            out.push(p.clone());
        }
        out
    };

    if targets.is_empty() {
        println!("(no packages installed)");
        return Ok(());
    }

    for entry in &targets {
        let alias = aliases::lookup(&entry.name);
        let spec = Spec {
            name: entry.name.clone(),
            repo: entry.repo.clone(),
            alias,
            version: None,
        };
        let release = github::fetch_latest(&spec.repo)?;
        if release.tag_name == entry.tag {
            println!("{}: up to date ({})", entry.name, entry.tag);
            continue;
        }
        println!(
            "{}: {} -> {}",
            entry.name, entry.tag, release.tag_name
        );
        do_install(&spec)?;
    }
    Ok(())
}
