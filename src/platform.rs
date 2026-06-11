//! OS-abstraction layer. Everything POSIX-specific (paths, symlinks, +x bit,
//! asset filtering) routes through here so the rest of the crate stays portable.
//!
//! - Linux/macOS: XDG-ish paths, symlinks for binaries, +x bit for executable.
//! - Windows: `%LOCALAPPDATA%\unpin\` holds the `<name>.exe` NTFS hardlinks the
//!   user adds to PATH; extracted package binaries go under
//!   `%LOCALAPPDATA%\unpin\packages\`. unpin manages itself the same way —
//!   `unpin.exe` lives under `packages\` with a hardlink alongside the rest.
//!   Hardlinks (no admin, no Developer Mode) replace symlinks; the `.exe`
//!   extension marks executables and is what PATHEXT — and every Unixy shell
//!   on Windows (git-bash/MSYS, WSL interop) — resolves.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The three on-disk locations unpin works out of, resolved once at startup
/// from the environment. Bundling them behind a single fallible
/// [`Paths::resolve`] keeps the env-var lookups in one place and — critically
/// — turns an unset/empty `HOME` (or `LOCALAPPDATA`/`APPDATA`) into a loud
/// error instead of a relative path silently rooted at the cwd. Cheap to
/// `clone` (three `PathBuf`s); the network layer stashes a copy in `Ctx` while
/// local commands borrow it directly.
#[derive(Clone, Debug)]
pub struct Paths {
    /// Per-package extracted trees (`<data>/<owner>/<repo>/<tag>/...`).
    pub data: PathBuf,
    /// The PATH entry: symlinks/hardlinks to each package's executables.
    pub bin: PathBuf,
    /// Flat `key = value` config file.
    pub config: PathBuf,
}

impl Paths {
    /// Resolve all three paths from the environment. The **only** fallible
    /// step in the path layer: an unset or empty base variable is a hard
    /// error rather than a relative path joined onto nothing (which used to
    /// install into the current working directory — common breakage in CI
    /// and containers where `HOME` is unset).
    pub fn resolve() -> io::Result<Paths> {
        #[cfg(unix)]
        {
            let data = match nonempty_env("XDG_DATA_HOME") {
                Some(x) => PathBuf::from(x).join("unpin"),
                None => home()?.join(".local/share/unpin"),
            };
            let bin = home()?.join(".local/bin");
            let config = match nonempty_env("XDG_CONFIG_HOME") {
                Some(x) => PathBuf::from(x).join("unpin").join("config"),
                None => home()?.join(".config/unpin/config"),
            };
            Ok(Paths { data, bin, config })
        }
        #[cfg(windows)]
        {
            // `bin` is the same folder that holds `unpin.exe` itself — the one
            // the user adds to PATH. Package hardlinks live next to it; per-
            // package data goes under the `packages\` subdirectory.
            let local = nonempty_env("LOCALAPPDATA").ok_or_else(|| missing("LOCALAPPDATA"))?;
            let appdata = nonempty_env("APPDATA").ok_or_else(|| missing("APPDATA"))?;
            Ok(Paths {
                data: PathBuf::from(&local).join("unpin").join("packages"),
                bin: PathBuf::from(local).join("unpin"),
                config: PathBuf::from(appdata).join("unpin").join("config"),
            })
        }
    }

    pub fn repo_dir(&self, owner: &str, name: &str) -> PathBuf {
        self.data.join(owner).join(name)
    }

    pub fn version_dir(&self, owner: &str, name: &str, tag: &str) -> PathBuf {
        self.repo_dir(owner, name).join(tag)
    }
}

/// An environment variable's value, but only if set and non-empty. An empty
/// value is treated as absent — joining onto `""` yields a relative path,
/// which is exactly the silent failure `Paths::resolve` exists to prevent.
fn nonempty_env(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

#[cfg(windows)]
fn missing(var: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "%{var}% is not set; cannot determine where to install (set %{var}% to a directory)"
        ),
    )
}

#[cfg(unix)]
fn home() -> io::Result<PathBuf> {
    nonempty_env("HOME").map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "$HOME is not set; set HOME (or XDG_DATA_HOME and XDG_CONFIG_HOME) so unpin can locate ~/.local",
        )
    })
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

/// Arch tokens that mark an asset as built for some *other* architecture —
/// match (on a token boundary, via `contains_arch_token`) → exclude. Each
/// target lists every arch family except its own.
///
/// The 32-bit ARM family carries both the `uname -m` labels the catalog uses
/// (`armv6l`/`armv7l` — note the trailing `l`) and the bare Rust/Debian forms
/// (`armv6`/`armv7`/`armhf`) third parties use. Both must be present: boundary
/// matching is exact, so `armv7` no longer catches `armv7l` the way the old
/// substring match did. `s390x` is exclusion-only — unpin isn't built for it,
/// so it's never a *current* arch, but it appears in third-party releases
/// (e.g. ripgrep) and must be excluded on every target.
pub fn other_arch_keys() -> &'static [&'static str] {
    #[cfg(target_arch = "x86_64")]
    {
        &[
            "i386",
            "i686",
            "armv6",
            "armv6l",
            "armv7",
            "armv7l",
            "armhf",
            "aarch64",
            "arm64",
            "ppc64le",
            "powerpc64le",
            "riscv64",
            "s390x",
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        &[
            "i386",
            "i686",
            "armv6",
            "armv6l",
            "armv7",
            "armv7l",
            "armhf",
            "x86_64",
            "amd64",
            "x64",
            "ppc64le",
            "powerpc64le",
            "riscv64",
            "s390x",
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
            "armv6l",
            "armv7",
            "armv7l",
            "armhf",
            "ppc64le",
            "powerpc64le",
            "riscv64",
            "s390x",
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
            "s390x",
        ]
    }
    #[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
    {
        &[
            "i386", "i686", "x86_64", "amd64", "x64", "aarch64", "arm64", "armv6", "armv6l",
            "armv7", "armv7l", "armhf", "riscv64", "s390x",
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
            "armv6l",
            "armv7",
            "armv7l",
            "armhf",
            "ppc64le",
            "powerpc64le",
            "s390x",
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

/// Toolchain/libc variants to prefer when a release ships more than one build
/// for this exact OS **and** arch. unpin favors the most portable option: on
/// Linux that's `musl` (statically linked, no glibc-version coupling) over a
/// `gnu`/glibc build; on Windows it's `msvc` (the native toolchain, no mingw
/// runtime) over a `gnu`/mingw build. Empty on macOS and elsewhere — there's
/// no comparable split. Applied only as a tiebreak (see
/// `asset::apply_toolchain_preference`): it never excludes a sole candidate,
/// so a repo shipping only the non-preferred variant still installs.
pub fn preferred_toolchain_keys() -> &'static [&'static str] {
    #[cfg(target_os = "linux")]
    {
        &["musl"]
    }
    #[cfg(target_os = "macos")]
    {
        &[]
    }
    #[cfg(target_os = "windows")]
    {
        &["msvc"]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        &[]
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

/// File name to use on disk for an unpin-managed link with the logical short
/// name `name`. On Windows appends `.exe`: the link is an NTFS hardlink to the
/// real binary, and `.exe` is what PATHEXT — and git-bash/MSYS/WSL-interop
/// lookup, which only resolve `.exe` — find on PATH.
pub fn link_filename(name: &str) -> String {
    #[cfg(unix)]
    {
        name.to_owned()
    }
    #[cfg(windows)]
    {
        format!("{name}.exe")
    }
}

/// File name for a multi-call **alias** link — same shape as a primary link
/// on both platforms (Windows aliases additionally rely on the hardlink
/// preserving the alias name in argv[0] for the binary's applet dispatch).
pub fn alias_link_filename(name: &str) -> String {
    link_filename(name)
}

/// Marker carried in the file name of a busy link that was renamed aside (a
/// running image can't be deleted on Windows, but it can be renamed). Entries
/// carrying it are tombstones: invisible to `read_link` and reclaimed by
/// [`sweep_sidelined`] once the old process exits.
#[cfg(windows)]
const SIDELINED_MARKER: &str = ".unpin-old-";

/// Whether a file name is a [`sideline_busy_link`] tombstone: anything,
/// then the marker, then the sidelining process's PID. Requiring the digit
/// tail (rather than a bare substring test) keeps a hypothetical package or
/// alias whose *own* name contains the marker from being swept or hidden.
#[cfg(windows)]
fn is_sidelined_name(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    match name.rsplit_once(SIDELINED_MARKER) {
        Some((head, pid)) => {
            !head.is_empty() && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// Rename a bin entry we cannot delete — it is the executing image of a live
/// process — out of the link slot. Returns the tombstone path so callers (the
/// self-uninstall janitor) can finish the delete after this process exits.
#[cfg(windows)]
pub fn sideline_busy_link(link: &Path) -> io::Result<PathBuf> {
    let mut name = link.file_name().unwrap_or_default().to_os_string();
    name.push(format!("{SIDELINED_MARKER}{}", std::process::id()));
    let dest = link.with_file_name(name);
    let _ = fs::remove_file(&dest);
    fs::rename(link, &dest)?;
    Ok(dest)
}

/// Best-effort removal of tombstones left by [`sideline_busy_link`]. A file
/// still held by a running old process just stays for the next sweep.
#[cfg(windows)]
pub fn sweep_sidelined(bin: &Path) {
    if let Ok(entries) = fs::read_dir(bin) {
        for entry in entries.flatten() {
            if is_sidelined_name(&entry.file_name()) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// Create an unpin-managed link at `link_path` pointing at `target`.
/// On Unix this is a regular symlink. On Windows it's an NTFS hardlink — no
/// Developer Mode or admin needed, only that `target` and the link share a
/// volume, which unpin's layout guarantees (`bin` and `packages\` both live
/// under `%LOCALAPPDATA%\unpin`). If the slot is occupied by a file we can't
/// delete (the running image of a live process — e.g. unpin itself during a
/// self-update), the occupant is renamed aside instead: Windows permits
/// renaming a running image, just not deleting it.
pub fn create_link(target: &Path, link_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link_path)
    }
    #[cfg(windows)]
    {
        match fs::hard_link(target, link_path) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if fs::remove_file(link_path).is_err() {
                    sideline_busy_link(link_path)?;
                }
                fs::hard_link(target, link_path)
            }
            r => r,
        }
    }
}

/// Create a multi-call **alias** link named `name` inside the trusted
/// directory `dir`, pointing at `target`. Aliases need argv[0] to carry the
/// alias name (so the binary's argv[0] dispatch picks the right code path).
/// So:
///   - Unix: symlink (kernel preserves the symlink name in argv[0]). The
///     symlink is created through a cap-std `Dir` opened on `dir`, so `name`
///     is confined to `dir` at the syscall layer — `openat2(RESOLVE_BENEATH)`
///     on Linux (emulated elsewhere) refuses a name carrying `..` or a
///     separator even if `validate_alias` upstream were somehow bypassed. This
///     mirrors the archive-extraction path (see `archive.rs`); the alias name
///     is the attacker-influenced half (it comes baked into the release
///     binary), so it gets the same kernel-level treatment as tar entry names.
///   - Windows: NTFS hardlink (same inode, different name; needs no admin and
///     no Developer Mode, only that `target` and the link live on the same
///     NTFS volume — they always do for unpin's layout). `target` lives
///     outside `dir` (under the data dir), so it can't share a single cap-std
///     capability with `dir`; the link name is confined by `validate_alias`
///     (which rejects path separators) instead.
///
/// Any existing entry at the slot is cleared first — neither `symlink` nor
/// `hard_link` replaces in place — so callers that decided to (re)write the
/// slot don't need a separate unlink step.
pub fn create_alias_link(dir: &Path, name: &str, target: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let capdir = cap_std::fs::Dir::open_ambient_dir(dir, cap_std::ambient_authority())?;
        // symlink_contents (not symlink): the alias points at the package
        // binary, which lives *outside* `dir` under the data tree, so `target`
        // must be stored verbatim — cap-std's `symlink` rejects an absolute
        // (escaping) target. `symlink_contents` leaves the target unresolved
        // while still confining the link *name* to `dir` (RESOLVE_BENEATH).
        // It won't overwrite, so clear our slot first; a missing entry (or a
        // non-file we can't unlink) is fine — the create then surfaces it.
        let _ = capdir.remove_file(name);
        capdir.symlink_contents(target, name)
    }
    #[cfg(windows)]
    {
        // Same mechanism as a primary link (hardlink + busy-slot sideline).
        create_link(target, &dir.join(alias_link_filename(name)))
    }
}

/// RAII guard around a kernel-level advisory file lock. The open `File`
/// inside is what holds the lock — dropping it releases the flock at the
/// OS level whether `Drop` runs cleanly (normal exit) or not (SIGKILL,
/// OOM, power loss, `panic = "abort"`). That replaces the old mtime-based
/// "stale lock" heuristic, which had a TOCTOU race during takeover and
/// would spuriously steal locks from slow real installs.
///
/// The sentinel file at `path` stays on disk after Drop just to make the
/// failure mode visible to a user investigating "why is unpin stuck"; the
/// file's presence is *not* what gates the lock, so a leftover is harmless.
/// We still remove it cosmetically when releasing cleanly.
#[derive(Debug)]
pub struct InstallLock {
    file: fs::File,
    path: PathBuf,
}

impl InstallLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        // unlock() can fail (e.g. fd already invalidated); ignore — the
        // upcoming File::drop closes the fd, which releases the kernel
        // lock regardless. The remove_file is cosmetic; it can fail when
        // rdir was wiped underneath us (e.g. by `uninstall_one`).
        let _ = self.file.unlock();
        let _ = fs::remove_file(&self.path);
    }
}

/// Acquire an exclusive advisory lock on `<repo_dir>/.unpin.lock`. Two `unpin`
/// processes touching the same package serialize here; different packages run
/// fully in parallel.
///
/// Uses `File::try_lock` (stable since Rust 1.89) which maps to `flock` on
/// Unix and `LockFileEx` on Windows. The kernel releases the lock when the
/// file descriptor closes for *any* reason, so crashes don't leave stale
/// locks — no timeout heuristic needed.
pub fn acquire_install_lock(repo_dir: &Path) -> Result<InstallLock, String> {
    fs::create_dir_all(repo_dir).map_err(|e| format!("create {}: {e}", repo_dir.display()))?;
    let lock_path = repo_dir.join(".unpin.lock");
    // `truncate(false)` — we don't blow away the diagnostic PID line another
    // unpin may have written. `write(true) + create(true)` is enough for our
    // needs; the file body is informational only.
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("open lock {}: {e}", lock_path.display()))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            return Err(format!(
                "another `unpin install`/`update` is in progress for this package\n  \
                 lock: {}",
                lock_path.display()
            ));
        }
        Err(fs::TryLockError::Error(e)) => {
            return Err(format!("lock {}: {e}", lock_path.display()));
        }
    }
    // Best-effort diagnostic — a user who finds a stuck `unpin` can grep the
    // pid to see which process is sitting on the lock. truncate-then-write
    // because the open didn't truncate.
    use std::io::{Seek, SeekFrom, Write};
    let _ = file.set_len(0);
    let mut f = &file;
    let _ = f.seek(SeekFrom::Start(0));
    let _ = writeln!(f, "pid={}", std::process::id());
    Ok(InstallLock {
        file,
        path: lock_path,
    })
}

/// Process-wide exclusive lock guarding mutations of the shared `bin_dir`
/// (link create + orphan cleanup). The per-package [`InstallLock`]
/// only covers a repo's own `repo_dir`; `bin_dir` is shared across every
/// package, so without this two `unpin` processes installing *different*
/// packages could interleave their link writes (lost links, an orphan sweep
/// deleting the other's fresh link).
///
/// Unlike [`InstallLock`], the lock file is **never removed** on drop: this
/// lock is acquired *blocking*, so a waiter holds an open fd to the file. If
/// the holder unlinked it on release, a third process could create a fresh
/// file at the same path and lock a *different* inode — two processes would
/// then both "hold" the lock. Leaving the file in place keeps every process
/// contending on one inode. The kernel still releases the advisory lock when
/// the fd closes (clean drop, panic, SIGKILL, power loss), so a leftover file
/// is harmless and never goes stale.
#[derive(Debug)]
pub struct LinksLock {
    // The open fd is the lock; `Drop` closing it releases the flock. No
    // explicit unlock or file removal (see type docs).
    _file: fs::File,
}

/// Acquire the shared `bin_dir` links lock, blocking until it's free. Pass the
/// path of any unpin-owned directory that all processes agree on (the data
/// dir); the lock file lives there rather than in `bin_dir` so it doesn't
/// clutter the user's PATH folder.
///
/// `on_wait` fires once iff the lock is currently held by another process —
/// the caller uses it to print a "waiting…" notice through whatever rendering
/// context it owns (a `MultiProgress`, plain stderr, …) before this blocks.
/// There is deliberately no timeout: the kernel guarantees a non-stale lock,
/// so a `WouldBlock` always means a live holder that will release when its
/// (short) link phase — or its interactive prompt — completes.
pub fn acquire_links_lock(data_dir: &Path, on_wait: impl FnOnce()) -> Result<LinksLock, String> {
    fs::create_dir_all(data_dir).map_err(|e| format!("create {}: {e}", data_dir.display()))?;
    let lock_path = data_dir.join(".unpin-links.lock");
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("open lock {}: {e}", lock_path.display()))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            on_wait();
            file.lock()
                .map_err(|e| format!("lock {}: {e}", lock_path.display()))?;
        }
        Err(fs::TryLockError::Error(e)) => {
            return Err(format!("lock {}: {e}", lock_path.display()));
        }
    }
    Ok(LinksLock { _file: file })
}

/// Read the target path from an unpin-managed link, or `None` if `p` isn't one.
/// On Unix this is `fs::read_link`. On Windows links are NTFS hardlinks; a
/// hardlink has no stored target, but `FindFirstFileNameW` enumerates *every*
/// name of the underlying file, and in unpin's layout exactly one of them is
/// the real binary under `packages\` — every other name (the link itself, any
/// sibling aliases) lives in the bin dir. So: return the first co-name outside
/// `p`'s own directory. A file with a single name (a regular `.exe`, e.g. a
/// user's own binary parked in the bin dir) yields `None`, as do tombstones
/// from [`sideline_busy_link`] — they still alias an *old* version's binary
/// and must not count as that package's live link.
pub fn read_link(p: &Path) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        fs::read_link(p).ok()
    }
    #[cfg(windows)]
    {
        if is_sidelined_name(p.file_name()?) {
            return None;
        }
        let names = hardlink_names(p)?;
        if names.len() < 2 {
            return None;
        }
        // FindFirstFileNameW returns volume-relative paths ("\Users\…"); a
        // hardlink never crosses volumes, so `p`'s drive prefix completes them.
        let prefix = match p.components().next()? {
            std::path::Component::Prefix(pre) => pre.as_os_str().to_owned(),
            _ => return None,
        };
        // Decide "is this co-name a sibling of `p`?" by on-disk directory
        // identity, not by spelling. The enumerated co-name carries the volume's
        // on-disk casing and backslashes, while `p` carries however the env
        // spelled our paths — a drive letter in either case, a non-ASCII
        // username whose case NTFS folds but `eq_ignore_ascii_case` wouldn't, an
        // 8.3 component, a trailing separator. Canonicalizing both parents
        // collapses all of that to one form so the test can't misfire (a
        // misfire would either hide a managed link from uninstall/clean or
        // return a sibling alias as the target). The returned path stays the
        // reconstructed, non-verbatim `full` so callers can keep comparing it
        // with `starts_with` against their plain `paths`-derived dirs.
        let parent_canon = fs::canonicalize(p.parent()?).ok()?;
        for n in names {
            let mut s = prefix.clone();
            s.push(&n);
            let full = PathBuf::from(s);
            let sibling = full
                .parent()
                .and_then(|fp| fs::canonicalize(fp).ok())
                .is_some_and(|c| c == parent_canon);
            if !sibling {
                return Some(full);
            }
        }
        None
    }
}

/// Every name (volume-relative) of the file at `p`, via the
/// `FindFirstFileNameW`/`FindNextFileNameW` hardlink enumeration API.
/// `None` on any failure (non-NTFS volume, vanished file, …).
#[cfg(windows)]
fn hardlink_names(p: &Path) -> Option<Vec<std::ffi::OsString>> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindFirstFileNameW, FindNextFileNameW,
    };

    let wide: Vec<u16> = p
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buf: Vec<u16> = vec![0; 512];
    let mut len = buf.len() as u32;
    let handle = unsafe { FindFirstFileNameW(wide.as_ptr(), 0, &mut len, buf.as_mut_ptr()) };
    let handle = if handle == INVALID_HANDLE_VALUE {
        if unsafe { GetLastError() } != ERROR_MORE_DATA {
            return None;
        }
        buf.resize(len as usize, 0);
        let h = unsafe { FindFirstFileNameW(wide.as_ptr(), 0, &mut len, buf.as_mut_ptr()) };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        h
    } else {
        handle
    };

    // `len` counts UTF-16 units including the terminator; trim to the string.
    let take = |buf: &[u16], len: u32| {
        let n = buf
            .iter()
            .take(len as usize)
            .position(|&c| c == 0)
            .unwrap_or(len as usize);
        std::ffi::OsString::from_wide(&buf[..n])
    };

    let mut names = vec![take(&buf, len)];
    loop {
        len = buf.len() as u32;
        if unsafe { FindNextFileNameW(handle, &mut len, buf.as_mut_ptr()) } == 0 {
            match unsafe { GetLastError() } {
                ERROR_MORE_DATA => {
                    buf.resize(len as usize, 0);
                    continue;
                }
                _ => break, // ERROR_HANDLE_EOF is the clean end; anything else, stop too.
            }
        }
        names.push(take(&buf, len));
    }
    unsafe { FindClose(handle) };
    Some(names)
}

/// Whether `a` and `b` are the same file — including via different hardlink
/// names, which `fs::canonicalize` equality can't see. Self-install needs
/// this: the running `unpin.exe` is usually the bin-dir hardlink, while the
/// registered binary is the `packages\` name of the very same file.
#[cfg(windows)]
pub fn is_same_file(a: &Path, b: &Path) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    fn file_id(p: &Path) -> Option<(u32, u32, u32)> {
        let f = fs::File::open(p).ok()?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, &mut info) } == 0 {
            return None;
        }
        Some((
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ))
    }

    matches!((file_id(a), file_id(b)), (Some(x), Some(y)) if x == y)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- create_alias_link ----

    #[cfg(unix)]
    #[test]
    fn create_alias_link_makes_symlink_with_punctuation_name() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let target = tmp.path().join("coreutils");
        fs::write(&target, b"x").unwrap();

        // `[` is a real coreutils applet name — must link cleanly now.
        create_alias_link(&bin, "[", &target).unwrap();
        let link = bin.join("[");
        assert_eq!(fs::read_link(&link).unwrap(), target);
    }

    #[cfg(unix)]
    #[test]
    fn create_alias_link_replaces_existing_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let old = tmp.path().join("old");
        let new = tmp.path().join("new");
        fs::write(&old, b"o").unwrap();
        fs::write(&new, b"n").unwrap();

        create_alias_link(&bin, "ll", &old).unwrap();
        // A second write to the same name must clobber, not error: symlink()
        // alone won't replace, so the helper's pre-clear is what makes this work.
        create_alias_link(&bin, "ll", &new).unwrap();
        assert_eq!(fs::read_link(bin.join("ll")).unwrap(), new);
    }

    #[cfg(unix)]
    #[test]
    fn create_alias_link_refuses_traversal_name() {
        // Kernel-level backstop: even if a `..`-bearing name reached here
        // (it can't — validate_alias rejects separators first), cap-std's
        // RESOLVE_BENEATH refuses it and nothing lands outside `bin`.
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let target = tmp.path().join("target");
        fs::write(&target, b"x").unwrap();

        assert!(create_alias_link(&bin, "../escapee", &target).is_err());
        // The escape path one level up must NOT exist.
        assert!(!tmp.path().join("escapee").exists());
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
        assert_eq!(f, "rg.exe");
    }

    // ---- InstallLock ----

    #[test]
    fn install_lock_acquire_creates_file_and_drop_removes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("owner/name");
        let lock = acquire_install_lock(&repo).unwrap();
        let lock_path = repo.join(".unpin.lock");
        assert!(lock_path.exists());
        drop(lock);
        assert!(!lock_path.exists());
    }

    #[test]
    fn install_lock_second_acquire_fails_while_first_held() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("owner/name");
        let _lock = acquire_install_lock(&repo).unwrap();
        let err = acquire_install_lock(&repo).unwrap_err();
        assert!(err.contains("in progress"), "got: {err}");
    }

    #[test]
    fn install_lock_released_when_first_holder_drops() {
        // Crash recovery is implicit in flock semantics: when a process dies
        // (SIGKILL, panic-abort, power-loss) the kernel drops the lock as
        // soon as the fd closes. We can't kill ourselves mid-test, but
        // dropping the lock exercises the same code path — fd close → lock
        // released → second acquire succeeds.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("owner/name");
        let first = acquire_install_lock(&repo).unwrap();
        drop(first);
        let second = acquire_install_lock(&repo).unwrap();
        assert_eq!(second.path(), repo.join(".unpin.lock"));
    }

    #[test]
    fn install_lock_takes_over_orphan_file_from_dead_holder() {
        // Sentinel file from a previous run that died without unlocking:
        // the file is on disk but no process holds the kernel flock. A
        // fresh acquire must succeed (no mtime-based staleness check
        // needed — the kernel knows nobody owns it).
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("owner/name");
        fs::create_dir_all(&repo).unwrap();
        let lock_path = repo.join(".unpin.lock");
        fs::write(&lock_path, "pid=99999\n").unwrap();
        let lock = acquire_install_lock(&repo).unwrap();
        assert_eq!(lock.path(), lock_path);
    }

    #[test]
    fn links_lock_excludes_while_held_and_keeps_file_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path();
        let mut waited = false;
        let lock = acquire_links_lock(data, || waited = true).unwrap();
        assert!(!waited, "on_wait must not fire when the lock is free");
        let lock_path = data.join(".unpin-links.lock");
        assert!(lock_path.exists());

        // A second, independent fd must see the lock as held — proving mutual
        // exclusion — without us blocking on it.
        let other = fs::OpenOptions::new().write(true).open(&lock_path).unwrap();
        assert!(matches!(
            other.try_lock(),
            Err(fs::TryLockError::WouldBlock)
        ));
        drop(other);

        // Unlike InstallLock, the file is NOT removed on drop: a blocking
        // waiter holds an open fd, and unlinking would let a third process
        // create a fresh inode and lock it in parallel.
        drop(lock);
        assert!(
            lock_path.exists(),
            "links lock file must persist across drop"
        );

        // Released cleanly, so it can be re-acquired with no wait.
        let mut waited2 = false;
        let _lock2 = acquire_links_lock(data, || waited2 = true).unwrap();
        assert!(!waited2);
    }

    #[test]
    fn alias_link_filename_uses_exe_on_windows() {
        // Aliases are NTFS hardlinks to the actual binary on Windows and
        // need the `.exe` extension to resolve via PATHEXT.
        let f = alias_link_filename("xzcat");
        #[cfg(unix)]
        assert_eq!(f, "xzcat");
        #[cfg(windows)]
        assert_eq!(f, "xzcat.exe");
    }
}
