//! Read a binary's embedded metadata *bundle* — its `unpin/*` ZIP entries
//! (aliases, man pages, README, future kinds; see `docs/embedded-metadata.md`).
//!
//! The builtin doc verbs (`man`, `readme`) read these entries *in-process* via
//! [`read_bundle`] + [`crate::meta`] — locate the binary carrying the package's
//! `unpin/*` entries, parse it once into a [`Meta`], and link the renderer. No
//! fetch, no subprocess.
//!
//! Reading a foreign binary is fine: this is not a security boundary — the alias
//! trust gate lives in the linker (`install/linker.rs`), not here.

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
///
/// The builtin doc verbs (`render::man` / `render::readme`) read embedded pages
/// through this, in-process.
pub(crate) fn read_bundle(paths: &Paths, pkg: &str) -> Result<Option<Meta>, String> {
    for cand in locate(paths, pkg)? {
        if let Some(m) = meta::read(&cand)? {
            return Ok(Some(m));
        }
    }
    Ok(None)
}
