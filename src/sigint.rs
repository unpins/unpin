use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

// Vec, not Option<PathBuf>: parallel installs each register their own vdir.
static CLEANUP: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Lock `CLEANUP`, recovering the guard if the mutex was poisoned.
///
/// A poisoned mutex means some thread panicked while holding this lock. The
/// guarded value is a `Vec<PathBuf>` of *transient* paths (`.part` dirs and
/// `.unpin.lock` files) with no cross-field invariant a half-finished
/// `push`/`drain`/`retain` could corrupt, so the contents are always
/// well-formed regardless of where a panic landed. Refusing the lock on poison
/// (the old `if let Ok(g)`) would have silently disabled cleanup — the
/// interrupt handler would skip it and leak `.part`/`.lock` litter. Recovering
/// keeps the cleanup path working, which is the one path where it matters most.
fn lock_cleanup() -> MutexGuard<'static, Vec<PathBuf>> {
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
        for p in lock_cleanup().drain(..) {
            // Cleanup list mixes vdirs (directories) and lock files
            // (regular files). Try both — one errors silently, the
            // other succeeds, depending on which kind `p` is. Cheaper
            // than tracking the kind alongside each entry.
            let _ = std::fs::remove_file(&p);
            let _ = std::fs::remove_dir_all(&p);
        }
        eprintln!("\nunpin: interrupted");
        std::process::exit(130);
    });
}

pub fn push_cleanup(path: &Path) {
    lock_cleanup().push(path.to_path_buf());
}

pub fn pop_cleanup(path: &Path) {
    lock_cleanup().retain(|p| p != path);
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
        assert!(lock_cleanup().iter().any(|x| x == &p));
        pop_cleanup(&p);
        assert!(!lock_cleanup().iter().any(|x| x == &p));
    }
}
