use std::path::{Path, PathBuf};
use std::sync::Mutex;

// Vec, not Option<PathBuf>: parallel installs each register their own vdir.
static CLEANUP: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

pub fn install() {
    let _ = ctrlc::set_handler(|| {
        if let Ok(mut g) = CLEANUP.lock() {
            for p in g.drain(..) {
                // Cleanup list mixes vdirs (directories) and lock files
                // (regular files). Try both — one errors silently, the
                // other succeeds, depending on which kind `p` is. Cheaper
                // than tracking the kind alongside each entry.
                let _ = std::fs::remove_file(&p);
                let _ = std::fs::remove_dir_all(&p);
            }
        }
        eprintln!("\nunpin: interrupted");
        std::process::exit(130);
    });
}

pub fn push_cleanup(path: &Path) {
    if let Ok(mut g) = CLEANUP.lock() {
        g.push(path.to_path_buf());
    }
}

pub fn pop_cleanup(path: &Path) {
    if let Ok(mut g) = CLEANUP.lock() {
        g.retain(|p| p != path);
    }
}
