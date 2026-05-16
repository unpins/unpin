use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub fn extract<R: Read>(asset_name: &str, reader: R, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;

    let lower = asset_name.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        let gz = flate2::read::GzDecoder::new(reader);
        unpack_tar(gz, dest)
    } else if lower.ends_with(".tar.xz") {
        let xz = xz2::read::XzDecoder::new(reader);
        unpack_tar(xz, dest)
    } else if lower.ends_with(".tar.zst") {
        let zst = ruzstd::StreamingDecoder::new(reader)
            .map_err(|e| format!("zstd init for {asset_name}: {e}"))?;
        unpack_tar(zst, dest)
    } else if lower.ends_with(".tar") {
        unpack_tar(reader, dest)
    } else if lower.ends_with(".zip") {
        unpack_zip_stream(reader, dest)
    } else if lower.ends_with(".zst") {
        // Single-stream zstd (no tar inside). Asset name minus `.zst` is the
        // binary name. Place under `bin/` so siblings extracted from a `.tar.zst`
        // data companion (which puts files at `share/...`) line up: vim's
        // argv[0]-walk then resolves <exe_dir>/../share/vim/<ver>.
        //
        // `stem` is attacker-controlled (taken verbatim from the GitHub asset
        // name, minus the `.zst`). Routing the write through cap-std's
        // capability-scoped Dir kills any path-traversal attempt at the
        // syscall layer — `openat` with RESOLVE_BENEATH (Linux) or its
        // emulated equivalent refuses to walk `..` or follow symlinks
        // pointing outside the opened dir, even if a future bug let a
        // tainted name reach here. `dest` itself is something we built
        // (`<vdir>.part`), so opening it ambiently is safe.
        let mut zst = ruzstd::StreamingDecoder::new(reader)
            .map_err(|e| format!("zstd init for {asset_name}: {e}"))?;
        let stem = asset_name
            .strip_suffix(".zst")
            .or_else(|| asset_name.strip_suffix(".ZST"))
            .unwrap_or(asset_name);
        let bin_dir = dest.join("bin");
        fs::create_dir_all(&bin_dir).map_err(|e| format!("create {}: {e}", bin_dir.display()))?;
        write_untrusted_name(&bin_dir, stem, &mut zst)?;
        Ok(())
    } else if let Some(suffix) = unsupported_compression_suffix(&lower) {
        // Catch known compression formats we don't implement before the bare-
        // binary fallthrough would silently write the compressed bytes to
        // disk under the asset's name. The user would see "Installed" and
        // then a binary that's actually a tarball.
        Err(format!(
            "unsupported compression `{suffix}` for asset `{asset_name}`"
        ))
    } else {
        // Bare binary: stream directly to a file with the asset's name. On
        // Unix the file is chmod'd +x; on Windows we rely on the `.exe`
        // extension (the file ships with it). asset_name is attacker-
        // controlled — same cap-std treatment as the .zst path.
        let mut r = reader;
        write_untrusted_name(dest, asset_name, &mut r)?;
        Ok(())
    }
}

/// Write `name` inside `dir`, refusing any traversal/escape attempt at the
/// syscall layer. `name` comes from the GitHub release (attacker-controlled);
/// `dir` is one we built ourselves (`<vdir>.part` or `<vdir>.part/bin`).
///
/// Uses `cap_std::fs::Dir::open_ambient_dir` to scope all writes to `dir`.
/// On Linux this routes through `openat2(RESOLVE_BENEATH)`, which refuses
/// to traverse `..` or follow symlinks pointing outside the directory —
/// even if a future code path let a poisoned name reach this function.
/// macOS and Windows are emulated with equivalent guarantees.
///
/// Returns the same error shape as the `fs::File::create` path it replaced,
/// so callers don't need to change error matching.
fn write_untrusted_name<R: Read>(dir: &Path, name: &str, mut reader: R) -> Result<(), String> {
    let capdir = cap_std::fs::Dir::open_ambient_dir(dir, cap_std::ambient_authority())
        .map_err(|e| format!("open {}: {e}", dir.display()))?;
    let mut out = capdir
        .create(name)
        .map_err(|e| format!("create {}/{name}: {e}", dir.display()))?;
    io::copy(&mut reader, &mut out).map_err(|e| format!("write {}/{name}: {e}", dir.display()))?;
    // Chmod via the open file's fd (capability-scoped): even if `name`
    // would have escaped, we already failed at `capdir.create`. Going
    // through the std-path `set_permissions(dir.join(name))` here would
    // be the wrong shape anyway — it'd re-open by path and miss the
    // protection.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = cap_std::fs::Permissions::from_std(fs::Permissions::from_mode(0o755));
        out.set_permissions(perms)
            .map_err(|e| format!("chmod {}/{name}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Return a known compression suffix if `lower_name` ends with one we don't
/// handle. The `auxiliary_keys()` picker filter already drops most of these
/// upstream (`.deb`, `.rpm`, etc.), but a few — like `.gz` alone, or
/// `.tar.bz2` — can slip through if the release names a primary asset that
/// way. Reaching `extract` with such a name means the picker accepted it; we
/// fail loudly here rather than write the compressed bytes as a "binary".
///
/// Longer suffixes are listed first so `.tar.bz2` returns `.tar.bz2`, not
/// `.bz2`.
fn unsupported_compression_suffix(lower_name: &str) -> Option<&'static str> {
    const SUFFIXES: &[&str] = &[
        ".tar.bz2",
        ".tar.lz4",
        ".tar.lzma",
        ".tar.lz",
        ".tar.lzo",
        ".tar.br",
        ".bz2",
        ".lz4",
        ".lzma",
        ".lzo",
        ".br",
        ".gz",
        ".xz",
    ];
    SUFFIXES.iter().copied().find(|s| lower_name.ends_with(s))
}

fn unpack_tar<R: Read>(reader: R, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| format!("mkdir {}: {e}", dest.display()))?;
    let dir = cap_std::fs::Dir::open_ambient_dir(dest, cap_std::ambient_authority())
        .map_err(|e| format!("open {}: {e}", dest.display()))?;

    // We use tar-rs's `entries()` iterator (which handles the binary format,
    // GNU long-path extensions, PAX headers etc.) and route each entry's
    // filesystem effect through cap-std. That way tar-rs still owns format
    // parsing — well-tested ground we don't want to reinvent — but every
    // mutation lands through `openat2(RESOLVE_BENEATH)` (Linux) or its
    // emulation, refusing traversal at the syscall layer. Replaces
    // `archive.unpack(dest)` which used tar-rs's internal canonicalize +
    // starts_with check (TOCTOU-vulnerable in theory).
    //
    // Unsupported entry kinds (char/block device, FIFO, sparse files)
    // are silently skipped: unpins release tarballs don't ship them. We
    // also don't preserve mtimes, uids, or xattrs — none of which matter
    // for installing a CLI binary into PATH.
    //
    // Directory permissions are *deferred* to the end of unpacking and
    // applied deepest-first — mirroring tar-rs's own strategy (alexcrichton/
    // tar-rs#242). Nix-built unpins tarballs ship dirs with mode 0o555
    // (read-only), so if we applied perms inline we'd lose write access
    // to a parent before mkdir-ing its descendants. Files keep inline
    // chmod because each one is a leaf — locking it down can't block any
    // subsequent write.
    #[cfg(unix)]
    let mut dir_modes: Vec<(PathBuf, u32)> = Vec::new();

    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries().map_err(|e| format!("read tar: {e}"))? {
        let mut entry = entry.map_err(|e| format!("read tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("entry path: {e}"))?
            .into_owned();
        // Skip empty/"." entries — some tar writers emit a synthetic
        // root-dir entry that maps to dest itself; create_dir_all("") would
        // be a no-op but is_dir handling later gets confused.
        if path.as_os_str().is_empty() || path == Path::new(".") {
            continue;
        }
        let entry_type = entry.header().entry_type();
        let mode = entry.header().mode().ok();

        match entry_type {
            tar::EntryType::Directory => {
                dir.create_dir_all(&path)
                    .map_err(|e| format!("mkdir {}: {e}", path.display()))?;
                // Defer chmod — see comment above the loop.
                #[cfg(unix)]
                if let Some(m) = mode {
                    dir_modes.push((path, m));
                }
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    dir.create_dir_all(parent)
                        .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
                }
                // set_overwrite(true) equivalent: drop a stale entry first
                // so the create() that follows doesn't trip over an
                // already-symlinked path (mostly a no-op since we extract
                // into a freshly-wiped .part, but cheap insurance for
                // tarballs that intentionally duplicate paths).
                let _ = dir.remove_file(&path);
                let mut out = dir
                    .create(&path)
                    .map_err(|e| format!("create {}: {e}", path.display()))?;
                io::copy(&mut entry, &mut out)
                    .map_err(|e| format!("write {}: {e}", path.display()))?;
                #[cfg(unix)]
                if let Some(m) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = cap_std::fs::Permissions::from_std(fs::Permissions::from_mode(m));
                    out.set_permissions(perms)
                        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
                }
            }
            tar::EntryType::Symlink => {
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    dir.create_dir_all(parent)
                        .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
                }
                let target = entry
                    .link_name()
                    .map_err(|e| format!("symlink target for {}: {e}", path.display()))?
                    .ok_or_else(|| format!("symlink {} has empty target", path.display()))?;
                let _ = dir.remove_file(&path);
                // cap-std refuses creating a symlink that would itself
                // escape, AND refuses following symlinks that point
                // outside on subsequent opens (RESOLVE_BENEATH). So even
                // if a malicious archive ships `evil -> /etc` followed by
                // a write to `evil/passwd`, the write step's
                // dir.create_dir_all("evil") refuses to traverse the
                // outside-pointing symlink. Defense-in-depth holds.
                #[cfg(unix)]
                dir.symlink(&*target, &path)
                    .map_err(|e| format!("symlink {}: {e}", path.display()))?;
                #[cfg(windows)]
                {
                    // Windows distinguishes file vs dir symlinks at creation;
                    // tarballs we extract here are file-targeting in practice.
                    use cap_std::fs::DirExt;
                    dir.symlink_file(&*target, &path)
                        .map_err(|e| format!("symlink {}: {e}", path.display()))?;
                }
            }
            tar::EntryType::Link => {
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    dir.create_dir_all(parent)
                        .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
                }
                let src = entry
                    .link_name()
                    .map_err(|e| format!("hardlink src for {}: {e}", path.display()))?
                    .ok_or_else(|| format!("hardlink {} has empty src", path.display()))?;
                let _ = dir.remove_file(&path);
                dir.hard_link(&*src, &dir, &path)
                    .map_err(|e| format!("hardlink {}: {e}", path.display()))?;
            }
            _ => {
                // Character device, block device, FIFO, GNU sparse, etc.
                // unpins archives don't ship any of these.
            }
        }
    }

    // Now the deferred dir chmods. Deepest-first so that locking a parent
    // to 0o555 can't block an `set_permissions` call on its still-mutable
    // child. Sort by path-bytes descending — same heuristic tar-rs uses
    // for the topological-by-depth ordering.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        dir_modes.sort_by(|a, b| {
            b.0.as_os_str()
                .as_encoded_bytes()
                .cmp(a.0.as_os_str().as_encoded_bytes())
        });
        for (path, m) in dir_modes {
            let perms = cap_std::fs::Permissions::from_std(fs::Permissions::from_mode(m));
            let _ = dir.set_permissions(&path, perms);
        }
    }
    Ok(())
}

fn unpack_zip_stream<R: Read>(reader: R, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| format!("mkdir {}: {e}", dest.display()))?;
    let dir = cap_std::fs::Dir::open_ambient_dir(dest, cap_std::ambient_authority())
        .map_err(|e| format!("open {}: {e}", dest.display()))?;

    // When read_zipfile_from_stream encounters the central directory it has
    // already consumed some bytes from the stream — exactly how many is an
    // internal detail of the zip crate. To recover those bytes we sit a pass-
    // through reader between the network and the zip parser; it keeps a rolling
    // tail of the last `TAIL` bytes that flowed. After the loop ends, we
    // scan the tail (plus whatever's left in the inner stream) for the CD
    // signature `0x02014b50` and parse from there. TAIL is sized generously
    // so the consumed prefix always fits, regardless of crate internals.
    const TAIL: usize = 128;
    let mut filter = CdFilter::new(reader, TAIL);
    // raw_name → relative path map, so we can chmod each file by the same
    // name the CD entry uses. Relative paths are what cap-std works with.
    let mut entries: Vec<(String, PathBuf)> = Vec::new();

    while let Some(mut entry) = zip::read::read_zipfile_from_stream(&mut filter)
        .map_err(|e| format!("read zip entry: {e}"))?
    {
        let raw_name = entry.name().to_owned();
        let rel = match entry.enclosed_name() {
            Some(p) => p,
            None => continue,
        };
        if entry.is_dir() {
            dir.create_dir_all(&rel)
                .map_err(|e| format!("mkdir {}: {e}", rel.display()))?;
            entries.push((raw_name, rel));
            continue;
        }
        if let Some(parent) = rel.parent()
            && !parent.as_os_str().is_empty()
        {
            dir.create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        let mut out = dir
            .create(&rel)
            .map_err(|e| format!("create {}: {e}", rel.display()))?;
        io::copy(&mut entry, &mut out).map_err(|e| format!("write {}: {e}", rel.display()))?;
        entries.push((raw_name, rel));
    }

    // Drain the rest of the stream — this is the remainder of the CD + EOCD.
    let (mut inner, mut cd_buf) = filter.finish();
    inner
        .read_to_end(&mut cd_buf)
        .map_err(|e| format!("read zip central directory: {e}"))?;

    // Locate the first CD entry magic in the recovered buffer. Anything
    // before it was either entry data spillover or the bytes the zip parser
    // already consumed past the signature start.
    const CD_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    let cd_start = cd_buf
        .windows(4)
        .position(|w| w == CD_SIG)
        .unwrap_or(cd_buf.len());
    let modes = parse_central_directory(&cd_buf[cd_start..]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for (name, rel) in &entries {
            let mode = if let Some(&m) = modes.get(name) {
                Some(m)
            } else {
                // Zip made on a non-Unix host doesn't encode permissions. Fall
                // back to detecting ELF/shebang and promoting to 0o755. Reading
                // via `dir.open` keeps the capability scope.
                match dir.open(rel) {
                    Ok(mut f) => {
                        let mut head = [0u8; 4];
                        let n = f.read(&mut head).unwrap_or(0);
                        let is_elf = n >= 4 && &head[..4] == b"\x7fELF";
                        let is_shebang = n >= 2 && &head[..2] == b"#!";
                        if is_elf || is_shebang {
                            Some(0o755)
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            };
            if let Some(m) = mode {
                let perms = cap_std::fs::Permissions::from_std(fs::Permissions::from_mode(m));
                let _ = dir.set_permissions(rel, perms);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (entries, modes); // suppress unused warnings on Windows
    Ok(())
}

/// Pass-through Read that records a rolling tail of the last `max` bytes that
/// flowed through. Used to recover the start of the central directory entry
/// that the streaming zip parser consumed before returning None.
struct CdFilter<R> {
    inner: R,
    tail: Vec<u8>,
    max: usize,
}
impl<R: Read> CdFilter<R> {
    fn new(inner: R, max: usize) -> Self {
        Self {
            inner,
            tail: Vec::with_capacity(max),
            max,
        }
    }
    fn finish(self) -> (R, Vec<u8>) {
        (self.inner, self.tail)
    }
}
impl<R: Read> Read for CdFilter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.tail.extend_from_slice(&buf[..n]);
            let excess = self.tail.len().saturating_sub(self.max);
            if excess > 0 {
                self.tail.drain(..excess);
            }
        }
        Ok(n)
    }
}

/// Parse the central directory bytes and return a `name → unix_mode` map for
/// entries written by Unix-mode zip tools. Returns empty on any structural
/// issue — caller falls back to leaving permissions alone.
fn parse_central_directory(buf: &[u8]) -> std::collections::HashMap<String, u32> {
    const CD_SIG: u32 = 0x0201_4b50;
    let mut out = std::collections::HashMap::new();
    let mut pos = 0;
    while pos + 46 <= buf.len() {
        let sig = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        if sig != CD_SIG {
            break;
        }
        let version_made_by = u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]);
        let host_system = (version_made_by >> 8) as u8; // 3 = Unix
        let name_len = u16::from_le_bytes([buf[pos + 28], buf[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([buf[pos + 30], buf[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([buf[pos + 32], buf[pos + 33]]) as usize;
        let external_attrs =
            u32::from_le_bytes([buf[pos + 38], buf[pos + 39], buf[pos + 40], buf[pos + 41]]);

        let name_start = pos + 46;
        let name_end = name_start + name_len;
        if name_end > buf.len() {
            break;
        }
        if host_system == 3 {
            // Upper 16 bits include the file-type bits (S_IFREG etc.). Mask to
            // the permission bits proper (rwxrwxrwx + setuid/setgid/sticky) so
            // fs::set_permissions doesn't end up clearing perms when only the
            // type bits happen to be set.
            let mode = ((external_attrs >> 16) & 0xFFFF) & 0o7777;
            if mode != 0
                && let Ok(name) = std::str::from_utf8(&buf[name_start..name_end])
            {
                out.insert(name.to_owned(), mode);
            }
        }
        let next = name_end + extra_len + comment_len;
        if next <= pos {
            break;
        }
        pos = next;
    }
    out
}

// Tests check Unix permission bits, so they only run on Unix targets. (The
// production code is portable; we just have no equivalent assertions for
// Windows extraction.)
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn tar_with(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data, mode) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_path(name).unwrap();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_cksum();
            builder.append(&h, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn elf_bytes() -> Vec<u8> {
        // Minimal "ELF" — just the magic + filler. Enough for is_elf detection.
        let mut v = b"\x7fELF".to_vec();
        v.extend_from_slice(b"rest of fake binary contents");
        v
    }

    fn read_file(path: &Path) -> Vec<u8> {
        fs::read(path).unwrap()
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn extract_plain_tar_preserves_perms() {
        let entries: &[(&str, &[u8], u32)] = &[("bin/rg", b"ELF-ish data", 0o755)];
        let tar = tar_with(entries);
        let tmp = tempfile::tempdir().unwrap();
        extract("pkg.tar", &tar[..], tmp.path()).unwrap();
        let p = tmp.path().join("bin/rg");
        assert_eq!(read_file(&p), b"ELF-ish data");
        assert_eq!(mode_of(&p), 0o755);
    }

    #[test]
    fn extract_tar_gz_preserves_perms() {
        let tar = tar_with(&[("hello", b"hi", 0o755)]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        let bytes = gz.finish().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        extract("pkg.tar.gz", &bytes[..], tmp.path()).unwrap();
        let p = tmp.path().join("hello");
        assert_eq!(read_file(&p), b"hi");
        assert_eq!(mode_of(&p), 0o755);
    }

    #[test]
    fn extract_tgz_alias() {
        let tar = tar_with(&[("x", b"x", 0o644)]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        let bytes = gz.finish().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        extract("pkg.tgz", &bytes[..], tmp.path()).unwrap();
        assert_eq!(read_file(&tmp.path().join("x")), b"x");
    }

    #[test]
    fn extract_tar_xz_preserves_perms() {
        let tar = tar_with(&[("only", b"xz body", 0o700)]);
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 6);
        xz.write_all(&tar).unwrap();
        let bytes = xz.finish().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        extract("pkg.tar.xz", &bytes[..], tmp.path()).unwrap();
        let p = tmp.path().join("only");
        assert_eq!(read_file(&p), b"xz body");
        assert_eq!(mode_of(&p), 0o700);
    }

    #[test]
    fn extract_tar_zst_preserves_perms() {
        let tar = tar_with(&[("z", b"zstd body", 0o755)]);
        let bytes = zstd::encode_all(&tar[..], 3).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        extract("pkg.tar.zst", &bytes[..], tmp.path()).unwrap();
        let p = tmp.path().join("z");
        assert_eq!(read_file(&p), b"zstd body");
        assert_eq!(mode_of(&p), 0o755);
    }

    #[test]
    fn extract_zip_preserves_unix_mode_from_central_directory() {
        let mut zw = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o755);
        zw.start_file("tool", opts).unwrap();
        zw.write_all(&elf_bytes()).unwrap();
        let opts644 = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o644);
        zw.start_file("README.md", opts644).unwrap();
        zw.write_all(b"# docs").unwrap();
        let bytes = zw.finish().unwrap().into_inner();

        let tmp = tempfile::tempdir().unwrap();
        extract("pkg.zip", &bytes[..], tmp.path()).unwrap();
        assert_eq!(mode_of(&tmp.path().join("tool")), 0o755);
        assert_eq!(mode_of(&tmp.path().join("README.md")), 0o644);
    }

    #[test]
    fn extract_zip_without_unix_mode_falls_back_to_heuristic() {
        // Build a zip with default (Windows-style) permissions, but file
        // contents that should trip the ELF / shebang heuristic.
        let mut zw = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            // Force a non-Unix host so external_attrs has no unix_mode.
            .last_modified_time(zip::DateTime::default());
        // We can't easily set host = DOS via the public API. Use unix_permissions(0)
        // which makes parse_central_directory skip the entry (mode == 0).
        let opts_zero = opts.unix_permissions(0);
        zw.start_file("native", opts_zero).unwrap();
        zw.write_all(&elf_bytes()).unwrap();
        zw.start_file("script", opts_zero).unwrap();
        zw.write_all(b"#!/bin/sh\necho hi\n").unwrap();
        zw.start_file("notes.txt", opts_zero).unwrap();
        zw.write_all(b"plain text").unwrap();
        let bytes = zw.finish().unwrap().into_inner();

        let tmp = tempfile::tempdir().unwrap();
        extract("pkg.zip", &bytes[..], tmp.path()).unwrap();
        assert_eq!(mode_of(&tmp.path().join("native")), 0o755);
        assert_eq!(mode_of(&tmp.path().join("script")), 0o755);
        assert_ne!(mode_of(&tmp.path().join("notes.txt")), 0o755);
    }

    #[test]
    fn extract_bare_binary_writes_with_755() {
        let bytes = b"raw payload, no archive container";
        let tmp = tempfile::tempdir().unwrap();
        extract("downloaded-binary", &bytes[..], tmp.path()).unwrap();
        let p = tmp.path().join("downloaded-binary");
        assert_eq!(read_file(&p), bytes);
        assert_eq!(mode_of(&p), 0o755);
    }

    #[test]
    fn extract_rejects_unsupported_compression() {
        // .gz alone (not .tar.gz) and .tar.bz2 used to fall through to the
        // bare-binary path, leaving compressed bytes on disk under a name the
        // user thought was the binary. Both should now error explicitly.
        let tmp = tempfile::tempdir().unwrap();
        let err = extract("tool.gz", &b"junk"[..], tmp.path()).unwrap_err();
        assert!(err.contains("unsupported"), "got: {err}");
        let err = extract("tool.tar.bz2", &b"junk"[..], tmp.path()).unwrap_err();
        assert!(err.contains(".tar.bz2"), "got: {err}");
    }

    #[test]
    fn unsupported_suffix_table_prefers_longer_match() {
        // `.tar.bz2` and `.bz2` both match — the longer one (which conveys
        // "we don't do bzip2-compressed tars") should win.
        assert_eq!(
            unsupported_compression_suffix("tool.tar.bz2"),
            Some(".tar.bz2")
        );
    }

    #[test]
    fn extract_bare_zst_decompresses_into_bin_with_755() {
        // Asset like `gvim-9.2-x86_64-linux.zst` should land at `<dest>/bin/gvim-9.2-x86_64-linux`.
        let payload = b"\x7fELFimagine this is a binary";
        let compressed = zstd::encode_all(&payload[..], 3).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        extract("gvim-9.2.0-x86_64-linux.zst", &compressed[..], tmp.path()).unwrap();
        let p = tmp.path().join("bin/gvim-9.2.0-x86_64-linux");
        assert_eq!(read_file(&p), payload);
        assert_eq!(mode_of(&p), 0o755);
    }

    #[test]
    fn extract_bare_binary_refuses_path_traversal_via_asset_name() {
        // A malicious release with `asset_name = "../escape"` used to write
        // outside `dest` (kernel resolves `..` at open(2) time). cap-std's
        // capability-scoped Dir refuses to traverse `..` at the syscall
        // layer, so the write fails before touching the filesystem outside
        // dest.
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("sandbox");
        fs::create_dir_all(&dest).unwrap();
        let err = extract("../escape", &b"evil"[..], &dest).unwrap_err();
        // We don't pin the exact OS error string — cap-std maps RESOLVE_BENEATH
        // refusal to PermissionDenied on Linux, "the path is outside" on
        // emulated targets, etc. What matters is the write failed AND nothing
        // landed at the would-be escape path.
        assert!(err.contains("create"), "got: {err}");
        assert!(
            !parent.path().join("escape").exists(),
            "escape file was created at {}",
            parent.path().join("escape").display()
        );
    }

    #[test]
    fn extract_bare_zst_refuses_traversal_in_stem() {
        // Same protection on the .zst path: a stem like `../escape.zst`
        // strips to `../escape`, which the cap-std Dir for <dest>/bin
        // refuses to resolve.
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("sandbox");
        fs::create_dir_all(&dest).unwrap();
        let compressed = zstd::encode_all(&b"payload"[..], 3).unwrap();
        let err = extract("../escape.zst", &compressed[..], &dest).unwrap_err();
        assert!(err.contains("create"), "got: {err}");
        assert!(
            !parent.path().join("escape").exists(),
            "escape file was created"
        );
    }

    #[test]
    fn extract_tar_refuses_symlink_then_write_through_attack() {
        // Classic tar-bomb: entry A is a symlink `evil -> /tmp/outside`,
        // entry B writes to `evil/file`. Without cap-std the kernel would
        // follow the symlink at open(2) time and write through it. With
        // cap-std's RESOLVE_BENEATH on every dir traversal the second
        // entry's `create_dir_all("evil")` refuses to walk the symlink.
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("sandbox");
        let outside = parent.path().join("outside");
        fs::create_dir_all(&outside).unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        // Entry A: symlink "evil" pointing at /tmp/.../outside (absolute → outside dest)
        let mut h = tar::Header::new_gnu();
        h.set_path("evil").unwrap();
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_link_name(&outside).unwrap();
        h.set_cksum();
        builder.append(&h, std::io::empty()).unwrap();
        // Entry B: regular file "evil/escaped" with malicious content
        let mut h = tar::Header::new_gnu();
        h.set_path("evil/escaped").unwrap();
        let payload = b"got you";
        h.set_size(payload.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        builder.append(&h, &payload[..]).unwrap();
        let tar_bytes = builder.into_inner().unwrap();

        // cap-std refuses at TWO points: it won't create a symlink whose
        // target leaves the dir, and it won't traverse one if creation
        // somehow succeeded. The symlink creation refusal fires first here,
        // so we error on entry A — but either error path is acceptable as
        // long as nothing lands outside.
        let err = extract("pkg.tar", &tar_bytes[..], &dest).unwrap_err();
        assert!(
            err.contains("symlink") || err.contains("create") || err.contains("mkdir"),
            "got: {err}"
        );
        assert!(
            !outside.join("escaped").exists(),
            "wrote through symlink to {}",
            outside.join("escaped").display()
        );
    }

    #[test]
    fn extract_bare_binary_refuses_traversal_via_preexisting_symlink() {
        // Stronger guarantee than the lexical check: even if `dest` somehow
        // already contained a symlink pointing outside (e.g. left by a
        // previous buggy run before .part renames landed), cap-std refuses
        // to follow it. `validate_path_component` alone wouldn't catch
        // this — the asset_name "sneak/file" is lexically clean.
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("sandbox");
        fs::create_dir_all(&dest).unwrap();
        // Plant a symlink inside dest that resolves outside dest:
        let outside = parent.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("sneak")).unwrap();

        let err = extract("sneak/file", &b"evil"[..], &dest).unwrap_err();
        assert!(err.contains("create"), "got: {err}");
        assert!(
            !outside.join("file").exists(),
            "wrote through symlink to {}",
            outside.join("file").display()
        );
    }

    #[test]
    fn cd_filter_keeps_rolling_tail_and_forwards_all_bytes() {
        let data: Vec<u8> = (0u8..200).collect();
        let mut filter = CdFilter::new(&data[..], 64);
        let mut sink = Vec::new();
        io::copy(&mut filter, &mut sink).unwrap();
        assert_eq!(sink, data);
        let (_, tail) = filter.finish();
        assert_eq!(tail.len(), 64);
        assert_eq!(&tail[..], &data[136..]);
    }

    #[test]
    fn parse_central_directory_extracts_unix_mode_from_unix_host() {
        let mut cd = vec![0u8; 46 + 2];
        cd[0..4].copy_from_slice(&0x0201_4b50u32.to_le_bytes());
        // version_made_by: upper byte 3 = Unix
        cd[4..6].copy_from_slice(&((3u16 << 8) | 20).to_le_bytes());
        cd[28..30].copy_from_slice(&2u16.to_le_bytes()); // name_len
        let mode: u32 = 0o755;
        cd[38..42].copy_from_slice(&(mode << 16).to_le_bytes());
        cd[46..48].copy_from_slice(b"rg");
        let modes = parse_central_directory(&cd);
        assert_eq!(modes.get("rg").copied(), Some(0o755));
    }

    #[test]
    fn parse_central_directory_skips_non_unix_host() {
        let mut cd = vec![0u8; 46 + 1];
        cd[0..4].copy_from_slice(&0x0201_4b50u32.to_le_bytes());
        // version_made_by: upper byte 0 = DOS (not Unix)
        cd[4..6].copy_from_slice(&20u16.to_le_bytes());
        cd[28..30].copy_from_slice(&1u16.to_le_bytes());
        cd[38..42].copy_from_slice(&((0o755u32) << 16).to_le_bytes());
        cd[46] = b'x';
        let modes = parse_central_directory(&cd);
        assert!(modes.is_empty());
    }
}
