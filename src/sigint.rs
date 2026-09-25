use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// What the interrupt handler removes on the way out.
enum Cleanup {
    /// A `.part` extraction dir.
    Dir(PathBuf),
    /// A lock file this process holds, and the repo dir of a package lock.
    Lock(PathBuf, Option<PathBuf>),
}

impl Cleanup {
    fn path(&self) -> &Path {
        match self {
            Cleanup::Dir(p) | Cleanup::Lock(p, _) => p,
        }
    }
}

// Vec, not Option: parallel installs each register their own vdir and lock.
static CLEANUP: Mutex<Vec<Cleanup>> = Mutex::new(Vec::new());

/// Lock `CLEANUP`, recovering the guard if the mutex was poisoned.
///
/// A poisoned mutex means some thread panicked while holding this lock. The
/// guarded value is a `Vec` of *transient* paths (`.part` dirs and
/// lock files) with no cross-field invariant a half-finished
/// `push`/`drain`/`retain` could corrupt, so the contents are always
/// well-formed regardless of where a panic landed. Refusing the lock on poison
/// (the old `if let Ok(g)`) would have silently disabled cleanup — the
/// interrupt handler would skip it and leak `.part`/`.lock` litter. Recovering
/// keeps the cleanup path working, which is the one path where it matters most.
fn lock_cleanup() -> MutexGuard<'static, Vec<Cleanup>> {
    CLEANUP.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn install() {
    // NB: this closure is NOT an async-signal handler. `ctrlc` installs a
    // minimal OS handler that only nudges a self-pipe and runs *this* closure
    // on a dedicated background thread. So the async-signal-safety rules
    // (no locks, no malloc, no stdio) do NOT apply here — `Mutex::lock`,
    // `std::fs`, `eprintln!` and `process::exit` are all fine on a normal
    // thread. Do not "harden" this into a signal-safe form; that would break
    // the cleanup it exists to do.
    let _ = ctrlc::set_handler(|| {
        // The guard is held until `exit`, so a lock's own release (which
        // unregisters it first) blocks here instead of racing this loop.
        let mut cleanup = lock_cleanup();
        // Dirs first, locks last: removing a lock file releases it to the next
        // process, which must not find our half-written `.part` or have it
        // removed from under it.
        for c in cleanup.iter() {
            if let Cleanup::Dir(p) = c {
                let _ = std::fs::remove_dir_all(p);
            }
        }
        // If a live progress block is on screen, its render thread paints the
        // final frame (finished rows kept, in-progress cleared) and leaves the
        // cursor on a fresh line; we then print the message. With no live UI we
        // add a leading newline to break from whatever was on the line. Either
        // way "interrupted" is printed exactly once, here.
        if crate::progress::interrupt_freeze() {
            eprintln!("unpin: interrupted");
        } else {
            eprintln!("\nunpin: interrupted");
        }
        for c in cleanup.drain(..) {
            if let Cleanup::Lock(lock, repo_dir) = c {
                crate::platform::release_on_interrupt(&lock, repo_dir.as_deref());
            }
        }
        std::process::exit(130);
    });
}

/// Register a `.part` dir to remove if interrupted.
pub fn push_cleanup(path: &Path) {
    lock_cleanup().push(Cleanup::Dir(path.to_path_buf()));
}

/// Register a held lock file to release, after every dir, if interrupted.
pub fn push_lock_cleanup(path: &Path, repo_dir: Option<&Path>) {
    lock_cleanup().push(Cleanup::Lock(
        path.to_path_buf(),
        repo_dir.map(Path::to_owned),
    ));
}

pub fn pop_cleanup(path: &Path) {
    lock_cleanup().retain(|c| c.path() != path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_survives_a_poisoned_mutex() {
        // Poison CLEANUP: panic while holding the guard (its Drop marks the
        // mutex poisoned during unwinding). The thread's panic message on
        // stderr is expected test noise.
        let _ = std::thread::spawn(|| {
            let _g = lock_cleanup();
            panic!("intentionally poison the cleanup mutex");
        })
        .join();

        // With the old `if let Ok(g) = CLEANUP.lock()`, every call below would
        // silently no-op and the interrupt handler would skip cleanup. With
        // poison recovery, registration still works end to end.
        let p = PathBuf::from("unpin-poison-test.part");
        push_cleanup(&p);
        assert!(lock_cleanup().iter().any(|x| x.path() == p));
        pop_cleanup(&p);
        assert!(!lock_cleanup().iter().any(|x| x.path() == p));
    }
}
