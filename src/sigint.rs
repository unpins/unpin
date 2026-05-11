use std::path::{Path, PathBuf};
use std::sync::Mutex;

static CLEANUP: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn install() {
    let _ = ctrlc::set_handler(|| {
        if let Ok(mut g) = CLEANUP.lock() {
            if let Some(p) = g.take() {
                let _ = std::fs::remove_dir_all(&p);
            }
        }
        eprintln!("\nunpin: interrupted");
        std::process::exit(130);
    });
}

pub fn register_cleanup(path: &Path) {
    if let Ok(mut g) = CLEANUP.lock() {
        *g = Some(path.to_path_buf());
    }
}

pub fn clear_cleanup() {
    if let Ok(mut g) = CLEANUP.lock() {
        *g = None;
    }
}
