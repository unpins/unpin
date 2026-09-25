use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::{self, SeqCst};
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// What the interrupt handler cleans up on the way out.
enum Cleanup {
    /// A `.part` extraction dir, removed.
    Dir(PathBuf),
    /// A lock this process holds, released by dropping it.
    Lock { id: u64, _lock: Box<dyn Send> },
}

struct State {
    // Vec, not Option: parallel installs each register their own vdir and lock.
    entries: Vec<Cleanup>,
    /// Ctrl-c belongs to the program `foreground` started.
    child: bool,
}

static CLEANUP: Mutex<State> = Mutex::new(State {
    entries: Vec::new(),
    child: false,
});

/// Lock `CLEANUP`, recovering it if poisoned: the entries have no invariant a
/// panic can break, and refusing the lock would skip the cleanup on ctrl-c.
fn lock_cleanup() -> MutexGuard<'static, State> {
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
        let mut state = lock_cleanup();
        if state.child {
            return; // the program decides for itself
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
        STOP.fetch_or(CANCELLED, SeqCst);
        let deadline = Instant::now() + Duration::from_secs(2);
        let stopped = loop {
            if STOP.load(SeqCst) == CANCELLED {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // Dirs before locks: releasing a lock hands the repo to the next
        // process, which must not find our `.part` or have it removed.
        for c in &state.entries {
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
            state.entries.clear();
        }
        std::process::exit(130);
    });
}

/// Run `f`, which starts a program in the foreground as main's last step
/// (`exec`, or a child it waits for): from here on ctrl-c is the program's.
/// Blocks for good if an interrupt got here first.
pub fn foreground<T>(f: impl FnOnce() -> T) -> T {
    lock_cleanup().child = true;
    f()
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

/// The count of `InFlight` work, plus a bit set once an interrupt cancels it.
static STOP: AtomicUsize = AtomicUsize::new(0);
const CANCELLED: usize = 1 << (usize::BITS - 1);

/// Set once an interrupt asked the extractions to stop.
pub fn cancelled() -> bool {
    STOP.load(SeqCst) & CANCELLED != 0
}

/// `Err` once cancelled, for the extraction's checkpoints.
pub fn check() -> Result<(), String> {
    check_io().map_err(|e| e.to_string())
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

/// Work on a `.part` or vdir the handler waits for before removing dirs;
/// refused once cancelled.
pub struct InFlight(());
impl InFlight {
    pub fn enter() -> Result<Self, String> {
        STOP.fetch_add(1, SeqCst);
        let this = Self(());
        check().map(|()| this)
    }
}
impl Drop for InFlight {
    fn drop(&mut self) {
        STOP.fetch_sub(1, SeqCst);
    }
}

/// Register a `.part` dir to remove if interrupted.
pub fn push_cleanup(path: &Path) {
    lock_cleanup()
        .entries
        .push(Cleanup::Dir(path.to_path_buf()));
}

pub fn pop_cleanup(path: &Path) {
    lock_cleanup()
        .entries
        .retain(|c| !matches!(c, Cleanup::Dir(p) if p == path));
}

/// A lock kept here, so that an interrupt can release it after every dir;
/// dropping this releases it.
#[derive(Debug)]
pub struct Held(u64);

pub fn hold(lock: impl Send + 'static) -> Held {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    lock_cleanup().entries.push(Cleanup::Lock {
        id,
        _lock: Box::new(lock),
    });
    Held(id)
}

impl Drop for Held {
    fn drop(&mut self) {
        let lock = {
            let entries = &mut lock_cleanup().entries;
            let i = entries
                .iter()
                .position(|c| matches!(c, Cleanup::Lock { id, .. } if *id == self.0));
            i.map(|i| entries.swap_remove(i))
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
        // Poison CLEANUP: panic while holding the guard. The panic message on
        // stderr is expected test noise.
        let _ = std::thread::spawn(|| {
            let _g = lock_cleanup();
            panic!("intentionally poison the cleanup mutex");
        })
        .join();

        let p = PathBuf::from("unpin-poison-test.part");
        let registered = |c: &Cleanup| matches!(c, Cleanup::Dir(d) if *d == p);
        push_cleanup(&p);
        assert!(lock_cleanup().entries.iter().any(registered));
        pop_cleanup(&p);
        assert!(!lock_cleanup().entries.iter().any(registered));
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
