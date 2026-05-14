//! OS-abstraction layer. Everything POSIX-specific (paths, symlinks, +x bit,
//! asset filtering) routes through here so the rest of the crate stays portable.
//!
//! - Linux/macOS: XDG-ish paths, symlinks for binaries, +x bit for executable.
//! - Windows: `%LOCALAPPDATA%\unpin\` holds `unpin.exe` itself plus the `.cmd`
//!   wrappers (the user adds this single folder to PATH); extracted package
//!   binaries go under `%LOCALAPPDATA%\unpin\packages\`. Wrappers (no admin,
//!   no Developer Mode) replace symlinks; `.exe` extension marks executables.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn data_dir() -> PathBuf {
    #[cfg(unix)]
    {
        if let Ok(x) = env::var("XDG_DATA_HOME")
            && !x.is_empty()
        {
            return PathBuf::from(x).join("unpin");
        }
        PathBuf::from(env::var("HOME").unwrap_or_default()).join(".local/share/unpin")
    }
    #[cfg(windows)]
    {
        PathBuf::from(env::var("LOCALAPPDATA").unwrap_or_default())
            .join("unpin")
            .join("packages")
    }
}

pub fn bin_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(env::var("HOME").unwrap_or_default()).join(".local/bin")
    }
    #[cfg(windows)]
    {
        // Same folder that holds `unpin.exe` itself — the one the user adds to
        // PATH. `.cmd` wrappers live next to it; per-package data goes under
        // the `packages\` subdirectory (see `data_dir`).
        PathBuf::from(env::var("LOCALAPPDATA").unwrap_or_default()).join("unpin")
    }
}

pub fn config_path() -> PathBuf {
    #[cfg(unix)]
    {
        if let Ok(x) = env::var("XDG_CONFIG_HOME")
            && !x.is_empty()
        {
            return PathBuf::from(x).join("unpin").join("config");
        }
        PathBuf::from(env::var("HOME").unwrap_or_default()).join(".config/unpin/config")
    }
    #[cfg(windows)]
    {
        PathBuf::from(env::var("APPDATA").unwrap_or_default())
            .join("unpin")
            .join("config")
    }
}

/// Substrings that, when present in an asset name (case-insensitive), positively
/// identify it as built for the current OS. An asset that contains none of these
/// is treated as "no OS marker" — see `classify_for_current_os`.
pub fn current_os_keys() -> &'static [&'static str] {
    #[cfg(target_os = "linux")]
    {
        &["linux"]
    }
    #[cfg(target_os = "macos")]
    {
        &["darwin", "macos", "apple"]
    }
    #[cfg(target_os = "windows")]
    {
        // `.exe` alone is a strong OS marker — many Windows releases ship a
        // bare `tool.exe` with no other tag.
        &["windows", "win64", "win32", ".exe"]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        &[]
    }
}

/// Substrings that identify an asset as built for some *other* OS — match
/// → exclude. Disjoint from `current_os_keys`.
pub fn other_os_keys() -> &'static [&'static str] {
    #[cfg(target_os = "linux")]
    {
        &[
            "darwin", "macos", "apple", "windows", "win32", "win64", "freebsd", "openbsd", "netbsd",
        ]
    }
    #[cfg(target_os = "macos")]
    {
        &[
            "linux", "windows", "win32", "win64", "freebsd", "openbsd", "netbsd",
        ]
    }
    #[cfg(target_os = "windows")]
    {
        &["linux", "darwin", "macos", "apple", "freebsd", "openbsd", "netbsd"]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        &[]
    }
}

pub fn current_arch_keys() -> &'static [&'static str] {
    #[cfg(target_arch = "x86_64")]
    {
        &["x86_64", "amd64", "x64"]
    }
    #[cfg(target_arch = "aarch64")]
    {
        &["aarch64", "arm64"]
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        &[]
    }
}

pub fn other_arch_keys() -> &'static [&'static str] {
    #[cfg(target_arch = "x86_64")]
    {
        &["i386", "i686", "armv7", "aarch64", "arm64"]
    }
    #[cfg(target_arch = "aarch64")]
    {
        &["i386", "i686", "armv7", "x86_64", "amd64", "x64"]
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        &[]
    }
}

/// Auxiliary asset markers (checksums, source archives, packaging formats we
/// can't drive). The `.exe` suffix is excluded on Unix but accepted on Windows
/// (it's the primary native format there).
pub fn auxiliary_keys() -> &'static [&'static str] {
    #[cfg(unix)]
    {
        &[
            ".deb", ".rpm", ".appimage", ".7z", ".tar.bz2", ".sig", ".sha256", ".sha512", ".asc",
            ".pem", ".gpg", ".sbom", ".msi", ".exe",
        ]
    }
    #[cfg(windows)]
    {
        // .msi stays — it's a Windows installer we can't headlessly extract.
        &[
            ".deb", ".rpm", ".appimage", ".7z", ".tar.bz2", ".sig", ".sha256", ".sha512", ".asc",
            ".pem", ".gpg", ".sbom", ".msi",
        ]
    }
}

/// Whether `p` is invocable as a native executable on this OS.
/// Unix: any `+x` permission bit. Windows: `.exe` extension (unpin only ships
/// native binaries, so the rest of PATHEXT doesn't apply).
pub fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        p.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("exe"))
            .unwrap_or(false)
    }
}

/// Make `p` invocable. On Unix this means chmod +x; on Windows it's a no-op
/// (the `.exe` extension is what matters and is already baked into the name).
pub fn ensure_executable(p: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if is_executable(p) {
            return Ok(());
        }
        let mut perms = fs::metadata(p)
            .map_err(|e| format!("stat {}: {e}", p.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(p, perms).map_err(|e| format!("chmod {}: {e}", p.display()))
    }
    #[cfg(windows)]
    {
        if !p.exists() {
            return Err(format!("stat {}: not found", p.display()));
        }
        Ok(())
    }
}

/// Apply Unix file mode bits. No-op on Windows. Used by `archive` when an
/// archive entry carries explicit mode bits.
pub fn set_unix_mode(_p: &Path, _mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_p, fs::Permissions::from_mode(_mode))
    }
    #[cfg(windows)]
    {
        Ok(())
    }
}

/// File name to use on disk for an unpin-managed link with the logical short
/// name `name`. On Windows appends `.cmd` so the file is invocable via PATHEXT.
pub fn link_filename(name: &str) -> String {
    #[cfg(unix)]
    {
        name.to_owned()
    }
    #[cfg(windows)]
    {
        format!("{name}.cmd")
    }
}

/// Magic first line in Windows `.cmd` wrappers so `read_link` can distinguish
/// our wrappers from any other `.cmd` the user might place in the same folder.
/// Without it, a stray `tool.cmd` whose body happens to match the
/// `@"…" %*` shape — and that points anywhere under `data_dir()` — would be
/// treated as managed and silently overwritten.
#[cfg(any(windows, test))]
const WINDOWS_WRAPPER_MARKER: &str = "@rem unpin-managed";

/// Pure parser for the `.cmd` wrapper body. Cross-platform so we can test it
/// from Unix. Returns the target path inside the second-line `@"…"` only when
/// the first line matches `WINDOWS_WRAPPER_MARKER`.
#[cfg(any(windows, test))]
fn parse_cmd_wrapper(body: &str) -> Option<&str> {
    let mut lines = body.lines();
    if lines.next()?.trim_end() != WINDOWS_WRAPPER_MARKER {
        return None;
    }
    let target_line = lines.next()?;
    let after_quote = target_line.trim_start_matches('@').strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(&after_quote[..end])
}

/// Create an unpin-managed link at `link_path` pointing at `target`.
/// On Unix this is a regular symlink. On Windows it writes a `.cmd` wrapper
/// that forwards `%*` — no Developer Mode or admin needed. The first line is
/// a `@rem` marker so we can recognize our own wrappers later.
pub fn create_link(target: &Path, link_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link_path)
    }
    #[cfg(windows)]
    {
        let body = format!(
            "{WINDOWS_WRAPPER_MARKER}\r\n@\"{}\" %*\r\n",
            target.display()
        );
        fs::write(link_path, body)
    }
}

/// Read the target path from an unpin-managed link, or `None` if `p` isn't one.
/// On Unix this is `fs::read_link`. On Windows the wrapper must start with the
/// `WINDOWS_WRAPPER_MARKER` line — any other `.cmd` (user-written batch script,
/// or a `.cmd` from another tool) yields `None` rather than a wrong target.
pub fn read_link(p: &Path) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        fs::read_link(p).ok()
    }
    #[cfg(windows)]
    {
        let ext_is_cmd = p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("cmd"))
            .unwrap_or(false);
        if !ext_is_cmd {
            return None;
        }
        let body = fs::read_to_string(p).ok()?;
        parse_cmd_wrapper(&body).map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_cmd_wrapper ----
    // Cross-platform: testing the parser doesn't require Windows.

    #[test]
    fn cmd_wrapper_round_trip() {
        let body = format!(
            "{WINDOWS_WRAPPER_MARKER}\r\n@\"C:\\Users\\me\\AppData\\Local\\unpin\\packages\\foo\\rg.exe\" %*\r\n"
        );
        assert_eq!(
            parse_cmd_wrapper(&body),
            Some("C:\\Users\\me\\AppData\\Local\\unpin\\packages\\foo\\rg.exe")
        );
    }

    #[test]
    fn cmd_wrapper_accepts_lf_only() {
        // Files edited or written with Unix tools may not have \r.
        let body = format!("{WINDOWS_WRAPPER_MARKER}\n@\"C:\\x.exe\" %*\n");
        assert_eq!(parse_cmd_wrapper(&body), Some("C:\\x.exe"));
    }

    #[test]
    fn cmd_wrapper_rejects_missing_marker() {
        // The pre-marker format (or any user-written .cmd) must NOT be
        // recognized as managed — this is the regression fix from review #5.
        let body = "@\"C:\\x.exe\" %*\r\n";
        assert_eq!(parse_cmd_wrapper(body), None);
    }

    #[test]
    fn cmd_wrapper_rejects_wrong_marker() {
        let body = "@rem other-tool\r\n@\"C:\\x.exe\" %*\r\n";
        assert_eq!(parse_cmd_wrapper(body), None);
    }

    #[test]
    fn cmd_wrapper_rejects_empty() {
        assert_eq!(parse_cmd_wrapper(""), None);
    }

    #[test]
    fn cmd_wrapper_rejects_marker_only() {
        // Marker present but no target line.
        let body = format!("{WINDOWS_WRAPPER_MARKER}\r\n");
        assert_eq!(parse_cmd_wrapper(&body), None);
    }

    #[test]
    fn cmd_wrapper_rejects_target_without_quotes() {
        let body = format!("{WINDOWS_WRAPPER_MARKER}\r\n@C:\\x.exe %*\r\n");
        assert_eq!(parse_cmd_wrapper(&body), None);
    }

    #[test]
    fn cmd_wrapper_rejects_unterminated_quote() {
        let body = format!("{WINDOWS_WRAPPER_MARKER}\r\n@\"C:\\x.exe %*\r\n");
        assert_eq!(parse_cmd_wrapper(&body), None);
    }

    #[test]
    fn cmd_wrapper_ignores_extra_lines() {
        // Trailing content shouldn't trip the parser (we only consume two lines).
        let body = format!(
            "{WINDOWS_WRAPPER_MARKER}\r\n@\"C:\\x.exe\" %*\r\nrem extra\r\n"
        );
        assert_eq!(parse_cmd_wrapper(&body), Some("C:\\x.exe"));
    }

    // ---- OS / arch key tables ----

    #[test]
    fn current_and_other_os_keys_are_disjoint() {
        // No key should appear in both "current" and "other" — that would make
        // an asset both selectable and rejected.
        let cur = current_os_keys();
        let other = other_os_keys();
        for k in cur {
            assert!(
                !other.contains(k),
                "key {k:?} is in both current_os_keys and other_os_keys"
            );
        }
    }

    #[test]
    fn current_and_other_arch_keys_are_disjoint() {
        let cur = current_arch_keys();
        let other = other_arch_keys();
        for k in cur {
            assert!(
                !other.contains(k),
                "arch key {k:?} is in both current and other"
            );
        }
    }

    #[test]
    fn auxiliary_keys_cover_common_signatures() {
        // Defensive sanity check on the table — these are the most common
        // companion files seen on GitHub release pages.
        let aux = auxiliary_keys();
        assert!(aux.contains(&".sha256"));
        assert!(aux.contains(&".sig"));
        assert!(aux.contains(&".deb"));
    }

    #[test]
    fn link_filename_extension_matches_platform() {
        let f = link_filename("rg");
        #[cfg(unix)]
        assert_eq!(f, "rg");
        #[cfg(windows)]
        assert_eq!(f, "rg.cmd");
    }
}
