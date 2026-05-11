use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
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
    } else {
        // Bare binary: stream directly to a file with the asset's name.
        let path = dest.join(asset_name);
        let mut out = fs::File::create(&path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        let mut r = reader;
        io::copy(&mut r, &mut out).map_err(|e| format!("write {}: {e}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
        Ok(())
    }
}

fn unpack_tar<R: Read>(reader: R, dest: &Path) -> Result<(), String> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);
    archive
        .unpack(dest)
        .map_err(|e| format!("unpack tar to {}: {e}", dest.display()))
}

fn unpack_zip_stream<R: Read>(reader: R, dest: &Path) -> Result<(), String> {
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
    // Name → on-disk path map, so we can chmod each file by the same name the
    // CD entry uses without re-deriving safe paths.
    let mut paths: Vec<(String, PathBuf)> = Vec::new();

    while let Some(mut entry) = zip::read::read_zipfile_from_stream(&mut filter)
        .map_err(|e| format!("read zip entry: {e}"))?
    {
        let raw_name = entry.name().to_owned();
        let rel = match entry.enclosed_name() {
            Some(p) => p,
            None => continue,
        };
        let out_path = dest.join(rel);
        if entry.is_dir() {
            fs::create_dir_all(&out_path)
                .map_err(|e| format!("mkdir {}: {e}", out_path.display()))?;
            paths.push((raw_name, out_path));
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        let mut out = fs::File::create(&out_path)
            .map_err(|e| format!("create {}: {e}", out_path.display()))?;
        io::copy(&mut entry, &mut out)
            .map_err(|e| format!("write {}: {e}", out_path.display()))?;
        paths.push((raw_name, out_path));
    }

    // Drain the rest of the stream — this is the remainder of the CD + EOCD.
    let (inner, tail) = filter.finish();
    let mut cd_buf = tail;
    let mut inner = inner;
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
    for (name, path) in &paths {
        if let Some(mode) = modes.get(name) {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(*mode));
        } else {
            // Zip made on a non-Unix host doesn't encode permissions. Fall
            // back to detecting ELF/shebang and promoting to 0o755.
            if let Ok(mut f) = fs::File::open(path) {
                let mut head = [0u8; 4];
                let n = f.read(&mut head).unwrap_or(0);
                let is_elf = n >= 4 && &head[..4] == b"\x7fELF";
                let is_shebang = n >= 2 && &head[..2] == b"#!";
                if is_elf || is_shebang {
                    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
                }
            }
        }
    }
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
        let version_made_by =
            u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]);
        let host_system = (version_made_by >> 8) as u8; // 3 = Unix
        let name_len = u16::from_le_bytes([buf[pos + 28], buf[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([buf[pos + 30], buf[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([buf[pos + 32], buf[pos + 33]]) as usize;
        let external_attrs = u32::from_le_bytes([
            buf[pos + 38],
            buf[pos + 39],
            buf[pos + 40],
            buf[pos + 41],
        ]);

        let name_start = pos + 46;
        let name_end = name_start + name_len;
        if name_end > buf.len() {
            break;
        }
        if host_system == 3 {
            let mode = (external_attrs >> 16) & 0xFFFF;
            if mode != 0 {
                if let Ok(name) = std::str::from_utf8(&buf[name_start..name_end]) {
                    out.insert(name.to_owned(), mode);
                }
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
