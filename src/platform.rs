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
use std::time::Duration;

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
        &[
            "linux", "darwin", "macos", "apple", "freebsd", "openbsd", "netbsd",
        ]
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
    // Rust `target_arch = "x86"` covers i386/i486/i586/i686. unpins builds for
    // i686-unknown-linux-musl; "x86" is intentionally NOT a current-arch key —
    // it's a substring of "x86_64" and would risk picking the wrong asset for
    // a third-party release that drops the `_64` suffix. Stay precise.
    #[cfg(target_arch = "x86")]
    {
        &["i686", "i386"]
    }
    // Rust `target_arch = "arm"` covers armv5/v6/v7. unpins builds via muslpi
    // (armv6l-baseline, hardfloat) but labels assets "armv7l" since that's
    // what `uname -m` returns on the dominant target hardware (Pi 2+, etc.).
    // Bare "arm" is NOT a key — it would substring-match nothing meaningful
    // (aarch64 doesn't contain "arm") but we keep the table free of overly
    // generic tokens for consistency with the x86/x86_64 reasoning above.
    #[cfg(target_arch = "arm")]
    {
        &["armv6l", "armv7l", "armhf", "armv6", "armv7"]
    }
    // PowerPC 64-bit. `target_arch = "powerpc64"` covers both BE and LE; we
    // only ship LE (musl-power → powerpc64le-musl). Debian's label is
    // "ppc64el" but uname + Rust ecosystem use "ppc64le".
    #[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
    {
        &["ppc64le", "powerpc64le"]
    }
    #[cfg(target_arch = "riscv64")]
    {
        &["riscv64"]
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "x86",
        target_arch = "arm",
        all(target_arch = "powerpc64", target_endian = "little"),
        target_arch = "riscv64"
    )))]
    {
        &[]
    }
}

pub fn other_arch_keys() -> &'static [&'static str] {
    #[cfg(target_arch = "x86_64")]
    {
        &[
            "i386",
            "i686",
            "armv6",
            "armv7",
            "armhf",
            "aarch64",
            "arm64",
            "ppc64le",
            "powerpc64le",
            "riscv64",
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        &[
            "i386",
            "i686",
            "armv6",
            "armv7",
            "armhf",
            "x86_64",
            "amd64",
            "x64",
            "ppc64le",
            "powerpc64le",
            "riscv64",
        ]
    }
    #[cfg(target_arch = "x86")]
    {
        &[
            "x86_64",
            "amd64",
            "x64",
            "aarch64",
            "arm64",
            "armv6",
            "armv7",
            "armhf",
            "ppc64le",
            "powerpc64le",
            "riscv64",
        ]
    }
    #[cfg(target_arch = "arm")]
    {
        &[
            "i386",
            "i686",
            "x86_64",
            "amd64",
            "x64",
            "aarch64",
            "arm64",
            "ppc64le",
            "powerpc64le",
            "riscv64",
        ]
    }
    #[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
    {
        &[
            "i386", "i686", "x86_64", "amd64", "x64", "aarch64", "arm64", "armv6", "armv7",
            "armhf", "riscv64",
        ]
    }
    #[cfg(target_arch = "riscv64")]
    {
        &[
            "i386",
            "i686",
            "x86_64",
            "amd64",
            "x64",
            "aarch64",
            "arm64",
            "armv6",
            "armv7",
            "armhf",
            "ppc64le",
            "powerpc64le",
        ]
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "x86",
        target_arch = "arm",
        all(target_arch = "powerpc64", target_endian = "little"),
        target_arch = "riscv64"
    )))]
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
            ".deb",
            ".rpm",
            ".appimage",
            ".7z",
            ".tar.bz2",
            ".sig",
            ".sha256",
            ".sha512",
            ".asc",
            ".pem",
            ".gpg",
            ".sbom",
            ".msi",
            ".exe",
        ]
    }
    #[cfg(windows)]
    {
        // .msi stays — it's a Windows installer we can't headlessly extract.
        &[
            ".deb",
            ".rpm",
            ".appimage",
            ".7z",
            ".tar.bz2",
            ".sig",
            ".sha256",
            ".sha512",
            ".asc",
            ".pem",
            ".gpg",
            ".sbom",
            ".msi",
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

/// File name for a multi-call **alias** link. On Windows aliases use NTFS
/// hardlinks (so argv[0] preserves the alias name, which `.cmd` wrappers
/// can't do — they pass the resolved target path instead), and a hardlinked
/// executable needs an `.exe` extension to be invocable via PATHEXT.
pub fn alias_link_filename(name: &str) -> String {
    #[cfg(unix)]
    {
        name.to_owned()
    }
    #[cfg(windows)]
    {
        format!("{name}.exe")
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

/// Create a multi-call **alias** link. Aliases need argv[0] to carry the
/// alias name (so the binary's argv[0] dispatch picks the right code path);
/// `.cmd` wrappers can't do that — they invoke the target with its own
/// path. So:
///   - Unix: symlink (kernel preserves the symlink name in argv[0]).
///   - Windows: NTFS hardlink (same inode, different name; needs no admin
///     and no Developer Mode, only that `target` and `link_path` live on
///     the same NTFS volume — they always do for unpin's layout).
pub fn create_alias_link(target: &Path, link_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link_path)
    }
    #[cfg(windows)]
    {
        fs::hard_link(target, link_path)
    }
}

/// RAII guard around a sentinel lock file. The file is removed on drop — the
/// normal happy path releases the lock automatically. Ctrl-C is the caller's
/// problem (register the path with `sigint::push_cleanup` to cover it).
#[derive(Debug)]
pub struct InstallLock {
    path: PathBuf,
}

impl InstallLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Acquire an advisory lock at `<repo_dir>/.unpin.lock`. Two `unpin` processes
/// touching the same package serialize on this lock; different packages run
/// fully in parallel. Lock files older than `stale_after` are taken over —
/// this covers SIGKILL / power-loss scenarios where the previous holder
/// couldn't run its `Drop`. Ctrl-C is handled separately via the sigint
/// cleanup hook.
///
/// Implementation is a portable `O_CREAT | O_EXCL` (`create_new` in std). No
/// `flock`/`LockFileEx` dependency.
pub fn acquire_install_lock(repo_dir: &Path, stale_after: Duration) -> Result<InstallLock, String> {
    fs::create_dir_all(repo_dir).map_err(|e| format!("create {}: {e}", repo_dir.display()))?;
    let lock_path = repo_dir.join(".unpin.lock");
    loop {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(mut f) => {
                // PID + creation time inside the file are diagnostic only —
                // a user looking at a stuck lock can grep `ps` for the PID.
                use std::io::Write;
                let _ = writeln!(f, "pid={}", std::process::id());
                return Ok(InstallLock { path: lock_path });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let stale = fs::metadata(&lock_path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|mt| mt.elapsed().ok())
                    .map(|age| age > stale_after)
                    .unwrap_or(false);
                if stale {
                    let _ = fs::remove_file(&lock_path);
                    continue;
                }
                return Err(format!(
                    "another `unpin install`/`update` is in progress for this package\n  \
                     lock: {}\n  \
                     remove the file manually if you're sure no other unpin is running",
                    lock_path.display()
                ));
            }
            Err(e) => return Err(format!("create lock {}: {e}", lock_path.display())),
        }
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
        let body = format!("{WINDOWS_WRAPPER_MARKER}\r\n@\"C:\\x.exe\" %*\r\nrem extra\r\n");
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

    // ---- InstallLock ----

    #[test]
    fn install_lock_acquire_creates_file_and_drop_removes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("owner/name");
        let lock = acquire_install_lock(&repo, Duration::from_secs(3600)).unwrap();
        let lock_path = repo.join(".unpin.lock");
        assert!(lock_path.exists());
        drop(lock);
        assert!(!lock_path.exists());
    }

    #[test]
    fn install_lock_second_acquire_fails_while_first_held() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("owner/name");
        let _lock = acquire_install_lock(&repo, Duration::from_secs(3600)).unwrap();
        let err = acquire_install_lock(&repo, Duration::from_secs(3600)).unwrap_err();
        assert!(err.contains("in progress"), "got: {err}");
    }

    #[test]
    fn install_lock_stale_lock_is_taken_over() {
        // Simulate a lock from a process that died without running Drop:
        // create the file, then ask for it with a stale_after of 0 so it's
        // immediately considered abandoned.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("owner/name");
        fs::create_dir_all(&repo).unwrap();
        let lock_path = repo.join(".unpin.lock");
        fs::write(&lock_path, "pid=99999").unwrap();
        let lock = acquire_install_lock(&repo, Duration::from_secs(0)).unwrap();
        assert_eq!(lock.path(), lock_path);
    }

    #[test]
    fn alias_link_filename_uses_exe_on_windows() {
        // Aliases need the `.exe` extension on Windows because they're
        // NTFS hardlinks to the actual binary, not `.cmd` wrappers.
        let f = alias_link_filename("xzcat");
        #[cfg(unix)]
        assert_eq!(f, "xzcat");
        #[cfg(windows)]
        assert_eq!(f, "xzcat.exe");
    }
}
