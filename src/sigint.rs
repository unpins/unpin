use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::{self, SeqCst};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

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
        // The guard is held until `exit`, so every lock taken or released,
        // and every `.part` registered, blocks here instead of racing us.
        let mut cleanup = lock_cleanup();
        if EXIT.compare_exchange(0, BY_SIGNAL, SeqCst, SeqCst).is_err() {
            // Main is exiting with its own code, or waits for a child that
            // got this ctrl-c too and decides for itself.
            return;
        }
        // If a live progress block is on screen, its render thread paints the
        // final frame (finished rows kept, in-progress cleared) and leaves the
        // cursor on a fresh line; we then print the message. With no live UI we
        // add a leading newline to break from whatever was on the line. Either
        // way "interrupted" is printed exactly once, here. Frozen before
        // cancelling, so the cancelled legs' errors never reach the screen.
        if crate::progress::interrupt_freeze() {
            eprintln!("unpin: interrupted");
        } else {
            eprintln!("\nunpin: interrupted");
        }
        // A leg's open directory handles keep its `.part` from being removed
        // on Windows: let each one stop and remove its own first.
        CANCELLED.store(true, SeqCst);
        let deadline = Instant::now() + Duration::from_secs(2);
        let stopped = loop {
            if IN_FLIGHT.load(SeqCst) == 0 {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // Dirs before locks: releasing a lock hands the repo to the next
        // process, which must not find our `.part` or have it removed.
        for c in cleanup.iter() {
            if let Cleanup::Dir(p) = c
                && !remove_dir_patiently(p)
            {
                eprintln!(
                    "unpin: left {}; the next install or 'unpin clean' removes it",
                    p.display()
                );
            }
        }
        // Dropping each lock releases it. If a leg may still be writing under
        // one, leave them to the OS, which releases them once it is gone.
        if stopped {
            cleanup.clear();
        }
        std::process::exit(130);
    });
}

const BY_MAIN: u8 = 1;
const BY_SIGNAL: u8 = 2;
const CHILD: u8 = 3;
/// Who exits the process: main with its code, or the handler with 130.
/// While a child runs, neither: an interrupt is the child's to handle.
static EXIT: AtomicU8 = AtomicU8::new(0);

/// Run `f`, which waits for a child sharing our terminal, as main's last
/// step: the child gets the same ctrl-c, and its exit code becomes ours.
pub fn with_child<T>(f: impl FnOnce() -> T) -> T {
    if EXIT.compare_exchange(0, CHILD, SeqCst, SeqCst).is_err() {
        loop {
            std::thread::park();
        }
    }
    let r = f();
    EXIT.store(BY_MAIN, SeqCst);
    r
}

/// Called by main just before it exits: if an interrupt got there first,
/// wait for the handler's exit instead.
pub fn claim_exit() {
    if let Err(BY_SIGNAL) = EXIT.compare_exchange(0, BY_MAIN, SeqCst, SeqCst) {
        loop {
            std::thread::park();
        }
    }
}

/// Retries for a while: Defender or the indexer can hold a new file briefly.
fn remove_dir_patiently(p: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match std::fs::remove_dir_all(p) {
            Ok(()) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => return false,
        }
    }
}

static CANCELLED: AtomicBool = AtomicBool::new(false);
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// Set once an interrupt asked the extractions to stop.
pub fn cancelled() -> bool {
    CANCELLED.load(SeqCst)
}

/// `Err` once cancelled, for the extraction's checkpoints.
pub fn check() -> Result<(), String> {
    if cancelled() {
        Err("interrupted".into())
    } else {
        Ok(())
    }
}

/// The same, for readers and writers. Not `ErrorKind::Interrupted`, which
/// `io::copy` and friends retry.
pub fn check_io() -> std::io::Result<()> {
    if cancelled() {
        Err(std::io::Error::other("interrupted"))
    } else {
        Ok(())
    }
}

/// Work on a `.part` or vdir the handler waits for before removing dirs.
/// Check `cancelled` after taking it: the handler sets the flag, then reads
/// the count.
pub struct InFlight(());
impl InFlight {
    pub fn new() -> Self {
        IN_FLIGHT.fetch_add(1, SeqCst);
        Self(())
    }
}
impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, SeqCst);
    }
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
    fn a_child_hands_the_exit_to_main() {
        assert_eq!(with_child(|| EXIT.load(SeqCst)), CHILD);
        assert_eq!(EXIT.load(SeqCst), BY_MAIN);
        claim_exit(); // returns: main's exit is already claimed
        EXIT.store(0, SeqCst);
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
