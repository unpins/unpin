use std::io::Write;
use std::panic::PanicHookInfo;

pub fn install() {
    std::panic::set_hook(Box::new(|info| {
        let _ = print_bug(info);
    }));
}

/// Restore SIGPIPE's default handler on Unix. Rust's libstd installs
/// `SIG_IGN` for SIGPIPE in the runtime startup, which turns a broken
/// pipe (e.g. `unpin list | head`) into an EPIPE returned from
/// `println!`. Combined with `panic = "abort"` that crashes the
/// process with a "fatal bug" message instead of dying quietly — the
/// behavior every other CLI shows under the same shell idiom.
///
/// Restoring SIG_DFL makes the kernel reap us silently when the
/// reader closes its end of the pipe, before stdout has a chance to
/// return EPIPE.
///
/// SAFETY: `signal(SIGPIPE, SIG_DFL)` is an async-signal-safe FFI
/// call that changes a single global signal disposition. We call it
/// exactly once from `main()` before any output. SIGPIPE = 13 and
/// SIG_DFL = 0 are stable across glibc, musl, macOS, and BSDs.
#[cfg(unix)]
pub fn restore_sigpipe_default() {
    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    const SIGPIPE: i32 = 13;
    const SIG_DFL: usize = 0;
    unsafe {
        signal(SIGPIPE, SIG_DFL);
    }
}

#[cfg(not(unix))]
pub fn restore_sigpipe_default() {}

fn print_bug(info: &PanicHookInfo<'_>) -> std::io::Result<()> {
    let message = match (
        info.payload().downcast_ref::<&str>(),
        info.payload().downcast_ref::<String>(),
    ) {
        (Some(s), _) => (*s).to_string(),
        (_, Some(s)) => s.clone(),
        _ => "unknown error".into(),
    };
    let location = match info.location() {
        None => String::new(),
        Some(loc) => format!("{}:{}\n\t", loc.file(), loc.line()),
    };

    let mut err = std::io::stderr().lock();
    writeln!(err, "error: Fatal bug in unpin!\n")?;
    writeln!(
        err,
        "This is a bug in unpin, sorry!

Please report this crash to https://github.com/unpins/unpin/issues/new
and include this error message with your report.

Panic: {location}{message}
unpin version: {version}
Operating system: {os}",
        version = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
    )?;
    Ok(())
}
