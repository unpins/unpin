use std::io::Write;
use std::panic::PanicHookInfo;

pub fn install() {
    std::panic::set_hook(Box::new(|info| {
        let _ = print_bug(info);
    }));
}

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
    writeln!(err, "error: Fatal bug in ghp!\n")?;
    writeln!(
        err,
        "This is a bug in ghp, sorry!

Please report this crash to https://github.com/malbarbo/ghp/issues/new
and include this error message with your report.

Panic: {location}{message}
ghp version: {version}
Operating system: {os}",
        version = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
    )?;
    Ok(())
}
