use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

/// What the interrupt handler cleans up on the way out.
enum Cleanup {
    /// A `.part` extraction dir, removed.
    Dir(PathBuf),
    /// A lock this process holds, released by dropping it.
    Lock { id: u64, _lock: Box<dyn Send> },
}

// Vec, not Option: parallel installs each register their own vdir and lock.
static CLEANUP: Mutex<Vec<Cleanup>> = Mutex::new(Vec::new());

/// Lock `CLEANUP`, recovering the guard if the mutex was poisoned.
///
/// A poisoned mutex means some thread panicked while holding this lock. The
/// guarded value is a `Vec` of *transient* entries (`.part` dirs and
/// held locks) with no cross-field invariant a half-finished
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
        // Dropping each lock releases it.
        cleanup.clear();
        std::process::exit(130);
    });
}

/// Register a `.part` dir to remove if interrupted.
pub fn push_cleanup(path: &Path) {
    lock_cleanup().push(Cleanup::Dir(path.to_path_buf()));
}

pub fn pop_cleanup(path: &Path) {
    lock_cleanup().retain(|c| !matches!(c, Cleanup::Dir(p) if p == path));
}

/// A lock kept here, so that an interrupt can release it after every dir;
/// dropping this releases it.
#[derive(Debug)]
pub struct Held(u64);

pub fn hold(lock: impl Send + 'static) -> Held {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    lock_cleanup().push(Cleanup::Lock {
        id,
        _lock: Box::new(lock),
    });
    Held(id)
}

impl Drop for Held {
    fn drop(&mut self) {
        let lock = {
            let mut cleanup = lock_cleanup();
            let i = cleanup
                .iter()
                .position(|c| matches!(c, Cleanup::Lock { id, .. } if *id == self.0));
            i.map(|i| cleanup.swap_remove(i))
        };
        // Released outside the guard, which an interrupt holds until exit.
        drop(lock);
    }
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
        let registered = |c: &Cleanup| matches!(c, Cleanup::Dir(d) if *d == p);
        push_cleanup(&p);
        assert!(lock_cleanup().iter().any(registered));
        pop_cleanup(&p);
        assert!(!lock_cleanup().iter().any(registered));
    }

    #[test]
    fn a_held_lock_is_dropped_when_its_guard_is() {
        struct Flag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let held = hold(Flag(dropped.clone()));
        assert!(!dropped.load(Ordering::SeqCst));
        drop(held);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
