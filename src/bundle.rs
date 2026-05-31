//! `unpin bundle` — inspect a binary's embedded metadata *bundle* (its `unpin/*`
//! ZIP entries: aliases, man pages, future kinds).
//!
//! The bundle is the generic container (`docs/embedded-metadata.md`); this is
//! the toolkit over it. Helper packages build on these ops as a **stable**
//! interface — the `man` package (a patched mandoc) runs `bundle list` to pick
//! the right page (and follow `.so` redirects, shown as symlink targets), then
//! `bundle dump` to stream that page's roff into the renderer. So unpin carries
//! no man knowledge, only bundle access; a future `changelog`/`readme` package
//! would read its own `unpin/<kind>/` entries the same way.
//!
//! Just the two primitives a consumer needs: `list` (enumerate) and `dump`
//! (fetch one). Anything aggregate (counts, per-kind rollups) is derivable from
//! `list`, so it's left to the caller rather than baked in here.
//!
//! Reading a foreign binary is fine: this is not a security boundary — the alias
//! trust gate lives in the linker (`install/linker.rs`), not here.
//!
//! **Rule across every op: a missing entry (or no bundle at all) is not an
//! error** — you get nothing back. Only a real failure exits non-zero: PKG not
//! installed, an unreadable binary, or a corrupt/oversized bundle.

use std::io::Write;
use std::path::PathBuf;

use crate::install;
use crate::meta::{self, Meta};
use crate::platform::Paths;

/// Candidate binaries for `pkg`: the running binary for `unpin` itself, else the
/// installed package's binaries (primary first).
fn locate(paths: &Paths, pkg: &str) -> Result<Vec<PathBuf>, String> {
    if pkg == "unpin" {
        let exe = std::env::current_exe()
            .map_err(|e| format!("bundle: cannot locate own binary: {e}"))?;
        Ok(vec![exe])
    } else {
        install::installed_binaries(paths, pkg).map_err(|e| format!("bundle: {e}"))
    }
}

/// Read the bundle of the first candidate binary that carries one. `Ok(None)` =
/// no candidate has any `unpin/*` entries (not an error). A corrupt/oversized
/// bundle on a candidate is a hard error (propagated from `meta::read`).
fn read_bundle(paths: &Paths, pkg: &str) -> Result<Option<Meta>, String> {
    for cand in locate(paths, pkg)? {
        if let Some(m) = meta::read(&cand)? {
            return Ok(Some(m));
        }
    }
    Ok(None)
}

/// `unpin bundle list <PKG>` — one entry per line: `path<TAB>size`, or
/// `path<TAB>-> target` for a symlink (`.so`) entry.
pub fn list(paths: &Paths, pkg: &str) -> Result<(), String> {
    let Some(meta) = read_bundle(paths, pkg)? else {
        return Ok(());
    };
    let mut out = std::io::stdout().lock();
    for e in meta.entries_under("unpin/") {
        writeln!(out, "{}", entry_line(e)).map_err(|er| format!("bundle: write: {er}"))?;
    }
    Ok(())
}

/// One `list` line: `path<TAB>size`, or `path<TAB>-> target` for a symlink
/// (`.so`) entry. This format is part of the stable interface helper packages
/// parse, so it's pinned by a test.
fn entry_line(e: &meta::Entry) -> String {
    if e.is_symlink {
        format!("{}\t-> {}", e.path, String::from_utf8_lossy(&e.data).trim())
    } else {
        format!("{}\t{}", e.path, e.data.len())
    }
}

/// `unpin bundle dump <PKG> <ENTRY>` — write the exact entry's bytes to stdout.
/// Prints nothing (and still succeeds) if the entry, or the whole bundle, is
/// absent. For a symlink entry the bytes are the redirect target.
pub fn dump(paths: &Paths, pkg: &str, entry: &str) -> Result<(), String> {
    let Some(meta) = read_bundle(paths, pkg)? else {
        return Ok(());
    };
    if let Some(e) = meta.entry(entry) {
        std::io::stdout()
            .write_all(&e.data)
            .map_err(|er| format!("bundle: write: {er}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::Entry;

    #[test]
    fn list_line_format() {
        let file = Entry {
            path: "unpin/man/ls.1".into(),
            is_symlink: false,
            data: vec![0u8; 909],
        };
        assert_eq!(entry_line(&file), "unpin/man/ls.1\t909");

        let link = Entry {
            path: "unpin/man/dir.1".into(),
            is_symlink: true,
            data: b"ls.1\n".to_vec(),
        };
        assert_eq!(entry_line(&link), "unpin/man/dir.1\t-> ls.1");
    }
}

