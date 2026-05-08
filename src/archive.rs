use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn extract(asset_name: &str, bytes: &[u8], dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;

    let lower = asset_name.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        let mut gz = flate2::read::GzDecoder::new(Cursor::new(bytes));
        let mut tarball = Vec::with_capacity(bytes.len() * 3);
        gz.read_to_end(&mut tarball)
            .map_err(|e| format!("gunzip {asset_name}: {e}"))?;
        unpack_tar(&tarball, dest)
    } else if lower.ends_with(".tar.xz") {
        let mut tarball = Vec::with_capacity(bytes.len() * 4);
        let mut reader = Cursor::new(bytes);
        lzma_rs::xz_decompress(&mut reader, &mut tarball)
            .map_err(|e| format!("xz decompress {asset_name}: {e}"))?;
        unpack_tar(&tarball, dest)
    } else if lower.ends_with(".tar") {
        unpack_tar(bytes, dest)
    } else if lower.ends_with(".zip") {
        unpack_zip(bytes, dest)
    } else {
        // Bare binary.
        let path = dest.join(asset_name);
        fs::write(&path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
        let mut perms = fs::metadata(&path)
            .map_err(|e| format!("stat {}: {e}", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms)
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
        Ok(())
    }
}

fn unpack_tar(bytes: &[u8], dest: &Path) -> Result<(), String> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);
    archive
        .unpack(dest)
        .map_err(|e| format!("unpack tar to {}: {e}", dest.display()))
}

fn unpack_zip(bytes: &[u8], dest: &Path) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| format!("open zip: {e}"))?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("read zip entry {i}: {e}"))?;
        let rel = match entry.enclosed_name() {
            Some(p) => p,
            None => continue,
        };
        let out_path = dest.join(rel);
        if entry.is_dir() {
            fs::create_dir_all(&out_path)
                .map_err(|e| format!("mkdir {}: {e}", out_path.display()))?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        let mut out = fs::File::create(&out_path)
            .map_err(|e| format!("create {}: {e}", out_path.display()))?;
        std::io::copy(&mut entry, &mut out)
            .map_err(|e| format!("write {}: {e}", out_path.display()))?;
        if let Some(mode) = entry.unix_mode() {
            fs::set_permissions(&out_path, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("chmod {}: {e}", out_path.display()))?;
        }
    }
    Ok(())
}
