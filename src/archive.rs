use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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

fn unpack_zip_stream<R: Read>(mut reader: R, dest: &Path) -> Result<(), String> {
    while let Some(mut entry) = zip::read::read_zipfile_from_stream(&mut reader)
        .map_err(|e| format!("read zip entry: {e}"))?
    {
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
        io::copy(&mut entry, &mut out)
            .map_err(|e| format!("write {}: {e}", out_path.display()))?;
    }
    // Streaming zip can't preserve unix_mode (lives in the central directory,
    // not in local headers). Heuristic chmod: any ELF binary or shebang script
    // gets +x.
    fixup_executable_bits(dest)?;
    Ok(())
}

fn fixup_executable_bits(root: &Path) -> Result<(), String> {
    let mut all = Vec::new();
    walk_files(root, &mut all).map_err(|e| format!("walk {}: {e}", root.display()))?;
    for path in &all {
        let mut f = match fs::File::open(path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut head = [0u8; 4];
        let n = f.read(&mut head).unwrap_or(0);
        if n < 2 {
            continue;
        }
        let is_elf = n >= 4 && &head[..4] == b"\x7fELF";
        let is_shebang = &head[..2] == b"#!";
        if is_elf || is_shebang {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
        }
    }
    Ok(())
}

fn walk_files(root: &Path, out: &mut Vec<std::path::PathBuf>) -> io::Result<()> {
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
