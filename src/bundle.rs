//! `unpin bundle` — inspect a binary's embedded metadata *bundle* (its `unpin/*`
//! ZIP entries: aliases, man pages, future kinds).
//!
//! The bundle is the generic container (`docs/embedded-metadata.md`); this is
//! the toolkit over it, exposed as a **stable** subcommand so a helper-verb
//! *package* can read a binary's `unpin/*` entries without linking unpin: `list`
//! to enumerate (and see `.so` redirects as symlink targets), `dump` to stream
//! one entry's bytes. The builtin doc verbs (`man`, `readme`) read the same
//! entries *in-process* via [`crate::meta`] — they don't shell through here — so
//! this interface now serves future, independent verb-packages (a `search`, say)
//! rather than man/readme. unpin still carries no per-kind knowledge in `bundle`,
//! only generic `unpin/*` access.
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
//! installed, an unreadable binary, or a corrupt/oversized bundle. Of these, "PKG
//! not installed" gets its own exit code ([`EXIT_NOT_INSTALLED`]) so a consumer
//! can tell it apart from a broken read without parsing the stderr text.

use std::io::Write;
use std::path::PathBuf;

use crate::install;
use crate::meta::{self, Meta};
use crate::platform::Paths;

/// Exit code from `list`/`dump` when PKG isn't installed — distinct from the
/// generic failure (1) so a helper-verb *package* can offer a tailored "run
/// `unpin install …`" hint and tell it apart from an unreadable/corrupt bundle.
/// Part of the stable bundle interface. (The builtin `man`/`readme` read the
/// bundle in-process and own this distinction directly, so they don't depend on
/// this code; it's kept for independent verb-packages that shell through here.)
pub const EXIT_NOT_INSTALLED: i32 = 4;

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
///
/// Public to the crate so the builtin doc verbs (`render::man` / `render::readme`)
/// read embedded pages directly, in-process, instead of shelling to `bundle dump`.
pub(crate) fn read_bundle(paths: &Paths, pkg: &str) -> Result<Option<Meta>, String> {
    for cand in locate(paths, pkg)? {
        if let Some(m) = meta::read(&cand)? {
            return Ok(Some(m));
        }
    }
    Ok(None)
}

/// `unpin bundle list <PKG>` — one entry per line: `path<TAB>size`, or
/// `path<TAB>-> target` for a symlink (`.so`) entry.
pub fn list(paths: &Paths, pkg: &str) -> Result<i32, String> {
    if let Some(code) = not_installed(paths, pkg)? {
        return Ok(code);
    }
    let Some(meta) = read_bundle(paths, pkg)? else {
        return Ok(0);
    };
    let mut out = std::io::stdout().lock();
    for e in meta.entries_under("unpin/") {
        writeln!(out, "{}", entry_line(e)).map_err(|er| format!("bundle: write: {er}"))?;
    }
    Ok(0)
}

/// `Some(EXIT_NOT_INSTALLED)` (after printing the diagnostic) if `pkg` isn't an
/// installed package, else `None`. `unpin` itself is always "installed" (read
/// from the running binary), so it's exempt. Kept separate so `list` and `dump`
/// signal it identically.
fn not_installed(paths: &Paths, pkg: &str) -> Result<Option<i32>, String> {
    // A malformed/ambiguous name surfaces as a hard error; prefix it `bundle:`
    // to match every other diagnostic from this op.
    if pkg != "unpin" && !install::is_installed(paths, pkg).map_err(|e| format!("bundle: {e}"))? {
        eprintln!("unpin: bundle: `{pkg}` is not installed");
        return Ok(Some(EXIT_NOT_INSTALLED));
    }
    Ok(None)
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
pub fn dump(paths: &Paths, pkg: &str, entry: &str) -> Result<i32, String> {
    if let Some(code) = not_installed(paths, pkg)? {
        return Ok(code);
    }
    let Some(meta) = read_bundle(paths, pkg)? else {
        return Ok(0);
    };
    if let Some(e) = meta.entry(entry) {
        std::io::stdout()
            .write_all(&e.data)
            .map_err(|er| format!("bundle: write: {er}"))?;
    }
    Ok(0)
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
