use std::io::{self, Read};

use indicatif::{ProgressBar, ProgressStyle};
use nanoserde::DeJson;

use crate::ctx::Ctx;

const USER_AGENT: &str = concat!("unpin/", env!("CARGO_PKG_VERSION"));

#[derive(DeJson, Debug, Clone)]
pub struct Release {
    pub tag_name: String,
    #[nserde(default)]
    pub published_at: String,
    #[nserde(default)]
    pub assets: Vec<Asset>,
}

#[derive(DeJson, Debug, Clone)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

pub fn fetch_latest(repo: &str, ctx: &Ctx) -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    fetch_release_url(&url, ctx)
}

pub fn fetch_tag(repo: &str, tag: &str, ctx: &Ctx) -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
    fetch_release_url(&url, ctx)
}

fn fetch_release_url(url: &str, ctx: &Ctx) -> Result<Release, String> {
    let body = api_get(url, ctx)?;
    DeJson::deserialize_json(&body).map_err(|e| format!("parse release JSON: {e}"))
}

fn api_get(url: &str, ctx: &Ctx) -> Result<String, String> {
    let mut headers: Vec<(&str, &str)> = vec![
        ("User-Agent", USER_AGENT),
        ("Accept", "application/vnd.github+json"),
    ];
    if let Some(ref h) = ctx.auth {
        headers.push(("Authorization", h));
    }
    if ctx.verbose {
        eprintln!("  GET {url}");
    }
    let resp = ctx.http.get(url, &headers)?;
    if ctx.verbose {
        eprintln!("  -> HTTP {}", resp.status);
    }
    if resp.status < 200 || resp.status >= 300 {
        if resp.status == 404 {
            return Err("not found (check package name or version)".into());
        }
        let msg = github_error_message(&resp.body)
            .unwrap_or_else(|| "request failed".to_string());
        return Err(format!("HTTP {}: {msg}", resp.status));
    }
    String::from_utf8(resp.body).map_err(|e| format!("decode body for {url}: {e}"))
}

#[derive(DeJson)]
struct ErrorBody {
    message: String,
}

fn github_error_message(body: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    DeJson::deserialize_json(s).ok().map(|e: ErrorBody| e.message)
}

/// Convenience download into memory. Used for small payloads (checksum files).
/// Renders no progress. Called only from the serial preflight phase, so a raw
/// `eprintln!` for the verbose URL log is safe (no `MultiProgress` rendering
/// to race against).
pub fn download(url: &str, ctx: &Ctx) -> Result<Vec<u8>, String> {
    if ctx.verbose {
        eprintln!("  GET {url}");
    }
    let bar = ProgressBar::hidden();
    let mut buf = Vec::new();
    let mut reader = download_stream_into(url, &bar, ctx)?;
    std::io::copy(&mut reader, &mut buf).map_err(|e| format!("read {url}: {e}"))?;
    Ok(buf)
}

/// Streaming download against a caller-provided `ProgressBar`. The bar must
/// already be registered with a `MultiProgress` (or hidden) before this is
/// called — otherwise indicatif draws standalone stderr lines that stay in
/// scrollback when the bar is later attached, producing ghost rows.
///
/// Once the HTTP response is in, this only sets the length (or, in the rare
/// `Content-Length`-missing case, swaps to a spinner style). The style itself
/// is whatever the caller pre-configured.
pub fn download_stream_into(
    url: &str,
    bar: &ProgressBar,
    ctx: &Ctx,
) -> Result<ProgressStream, String> {
    let headers: Vec<(&str, &str)> = vec![("User-Agent", USER_AGENT)];
    // Verbose URL printing happens at the call site — it has the right
    // serialization context (`MultiProgress::println` in the parallel-worker
    // path, plain `eprintln!` in serial helpers like `download()`). Logging
    // here with `eprintln!` would race with bar rendering on a TTY.
    let stream = ctx.http.get_streaming(url, &headers)?;
    if stream.status() < 200 || stream.status() >= 300 {
        return Err(format!("HTTP {} downloading {url}", stream.status()));
    }
    match stream.content_length() {
        Some(total) => bar.set_length(total),
        None => {
            bar.set_style(download_progress_style_unknown());
            bar.enable_steady_tick(std::time::Duration::from_millis(120));
        }
    }
    Ok(ProgressStream {
        inner: stream,
        bar: bar.clone(),
    })
}

pub struct ProgressStream {
    inner: Box<dyn crate::http::HttpStream + Send>,
    bar: ProgressBar,
}

impl Read for ProgressStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.bar.inc(n as u64);
        }
        Ok(n)
    }
}

// No Drop impl: the caller decides the bar's final state (clear on success,
// or swap to error style + abandon on failure). Hidden bars (used by
// `download()`) don't need explicit clearing.

/// Standard progress style for downloads: thin parallelogram bar.
/// Callers should pad `prefix` themselves so name/tag align across bars.
pub fn download_progress_style() -> ProgressStyle {
    // `progress_chars("▰▰▱")`: fill, transition (same glyph → no sub-cell), empty.
    ProgressStyle::with_template(
        "  {prefix:.cyan}  {bar:14.green/blue} {percent:>3}%  {bytes:>9}/{total_bytes:<9}  {bytes_per_sec:>10}",
    )
    .unwrap()
    .progress_chars("▰▰▱")
}

/// Style used when `Content-Length` was not provided. Spinner + bytes + rate, no bar.
pub fn download_progress_style_unknown() -> ProgressStyle {
    ProgressStyle::with_template(
        "  {prefix:.cyan}  {spinner} {bytes:>9}  {bytes_per_sec:>10}",
    )
    .unwrap()
}

/// Style for a failed download: prefix + red bar (frozen at the failure point)
/// + the error reason in red. Caller sets the reason via `bar.set_message(...)`.
pub fn download_error_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "  {prefix:.red}  {bar:14.red/red} {percent:>3}%  {wide_msg:.red}",
    )
    .unwrap()
    .progress_chars("▰▰▱")
}
